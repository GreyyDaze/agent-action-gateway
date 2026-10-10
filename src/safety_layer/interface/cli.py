"""The ``safety`` command."""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .gateway import GatewayPolicy

import argparse
import json
import os
import sys
from pathlib import Path

from ..evidence.failure_wall import build_failure_wall
from ..providers.mock import MockProvider
from ..providers.refund_demo_agent import make_refund_agent
from ..runtime.orchestrator import run
from ..storage.traces import TraceStore
from .gate_cli import EXIT_FAIL, EXIT_PASS, EXIT_USAGE
from .wiring import Status, run_check


def announce(scope: str) -> None:
    """State what a command is about, before its output.

    Without this, a green result reads as a verdict on the reader's agent when
    it is only ever a statement about a database, a config or a demo.
    """
    print(f"SCOPE: {scope}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="safety",
        description="Prevention-first safety and evaluation tools for AI agents.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser(
        "check",
        help="verify that your agent's tools are actually wrapped (about your code)",
    )
    check.add_argument(
        "--app",
        help="your agent entry point as module:callable, or a path to scan",
    )
    check.add_argument(
        "--db",
        help="a trace database to audit for actions that bypassed the layer",
    )
    check.add_argument("--format", choices=("text", "json"), default="text")

    run_parser = sub.add_parser("run", help="run the bundled demo agent through the safety layer")
    run_parser.add_argument("task", nargs="?", default="Process the refund for Ava")
    run_parser.add_argument("--db", default="data/runtime.db")

    # add_help=False so `--help` and every other flag reach the gate parser
    # untouched; argparse would otherwise intercept them here. `main` also
    # dispatches this branch before parsing, so nothing is validated twice.
    gate = sub.add_parser(
        "gate",
        help="run regression-gate commands; try `safety gate --help`",
        add_help=False,
    )
    gate.add_argument("args", nargs=argparse.REMAINDER)

    wall = sub.add_parser(
        "wall",
        help="group the failures recorded in your run database",
    )
    wall.add_argument("--db", default="data/runtime.db")

    gateway = sub.add_parser(
        "gateway",
        help="serve the HTTP gateway for your routes (it holds the upstream keys)",
    )
    gateway.add_argument("--config", required=True, help="YAML or JSON route table")
    gateway.add_argument("--db", default="data/runtime.db")
    gateway.add_argument("--host", default="127.0.0.1")
    gateway.add_argument("--port", type=int, default=8080)
    gateway.add_argument("--unix-socket", help="Unix socket path (Linux only) for local agent calls with UID verification")

    # Gateway key management subcommands
    gateway_sub = gateway.add_subparsers(dest="gateway_cmd", help="gateway key management")

    issue_key = gateway_sub.add_parser("issue-key", help="issue a virtual key for an agent")
    issue_key.add_argument("--name", required=True, help="agent name/identifier")
    issue_key.add_argument("--ttl", type=int, default=3600, help="time to live in seconds")
    issue_key.add_argument("--routes", required=True, help="comma-separated list of allowed routes (e.g., /charge,/refund)")

    _ = gateway_sub.add_parser("list-keys", help="list all virtual keys")

    revoke_key = gateway_sub.add_parser("revoke-key", help="revoke a virtual key")
    revoke_key.add_argument("key", help="virtual key to revoke")

    _ = gateway_sub.add_parser("rotate-master", help="rotate the master key")

    return parser


def load_route_policy(path: str) -> GatewayPolicy:
    """Build a gateway policy from a route table.

    Kept here rather than in the gateway so the file format is a CLI concern
    and the gateway stays a plain object.
    """
    import json

    from ..interface.gateway import GatewayPolicy, Route

    text = Path(path).read_text(encoding="utf-8")
    try:
        import yaml

        document = yaml.safe_load(text)
    except ImportError:
        document = json.loads(text)
    if not isinstance(document, dict):
        raise ValueError("gateway config must be a mapping with a 'routes' list")
    policy = GatewayPolicy(
        session_environment=str(document.get("session_environment", "dev")),
        master_key_env=str(document.get("master_key_env", "")),
    )
    for entry in document.get("routes", []):
        policy.register(
            Route(
                path=str(entry["path"]),
                upstream=str(entry["upstream"]),
                action=str(entry["action"]),
                risk=str(entry.get("risk", "destructive")),
                method=str(entry.get("method", "POST")).upper(),
                secret_env=str(entry.get("secret_env", "")),
                environment=str(entry.get("environment", "prod")),
            )
        )
    return policy


def run_gateway(args: argparse.Namespace) -> int:

    from ..interface.gateway import build_gateway_server
    from ..storage.traces import TraceStore

    # Mark this process as a legitimate gateway launch (for embedded-launch check)
    os.environ["SAFETY_GATEWAY"] = "1"

    # Drop privileges if running as root
    if os.geteuid() == 0:
        try:
            import pwd
            pw = pwd.getpwnam("safety-gateway")
            os.setgroups([])
            os.setgid(pw.pw_gid)
            os.setuid(pw.pw_uid)
            os.environ["HOME"] = pw.pw_dir
        except KeyError:
            print(
                "Gateway cannot run as root: user 'safety-gateway' does not exist. "
                "Create the user or run without sudo.",
                file=sys.stderr,
            )
            return EXIT_FAIL

    policy = load_route_policy(args.config)
    server, handler = build_gateway_server(
        TraceStore(args.db), policy, args.host, args.port, unix_socket=args.unix_socket
    )
    if args.unix_socket:
        print(f"Safety gateway on unix://{args.unix_socket}")
    else:
        print(f"Safety gateway on http://{args.host}:{server.server_address[1]}/")
    print(f"access token: {getattr(handler, 'access_token', '')}")
    print(f"registered routes: {len(policy.routes)} (anything else is refused)")
    server.serve_forever()
    return EXIT_PASS


def gateway_issue_key(args: argparse.Namespace) -> int:
    """Issue a virtual key for an agent."""
    import secrets
    import time

    policy = load_route_policy(args.config)
    master_key = os.environ.get(policy.master_key_env) if policy.master_key_env else None
    if not master_key:
        print("Error: master_key_env not configured or not set in environment", file=sys.stderr)
        return EXIT_FAIL

    # Verify the request is authenticated with master key
    provided = os.environ.get("SAFETY_GATEWAY_TOKEN")
    if not provided or not secrets.compare_digest(provided, master_key):
        print("Error: master key required (set SAFETY_GATEWAY_TOKEN)", file=sys.stderr)
        return EXIT_FAIL

    routes = [r.strip() for r in args.routes.split(",") if r.strip()]
    for route in routes:
        if route not in policy.routes:
            print(f"Error: route '{route}' not registered in gateway config", file=sys.stderr)
            return EXIT_FAIL

    key = secrets.token_urlsafe(32)
    expires_at = time.time() + args.ttl if args.ttl > 0 else None

    # Persist to trace store
    store = TraceStore(args.db)
    store.save_virtual_key(key, args.name, routes, expires_at)

    print(f"Virtual key issued: {key}")
    print(f"  name: {args.name}")
    print(f"  routes: {', '.join(routes)}")
    print(f"  expires: {time.ctime(expires_at) if expires_at else 'never'}")
    return EXIT_PASS


def gateway_list_keys(args: argparse.Namespace) -> int:
    """List all virtual keys."""
    import time

    store = TraceStore(args.db)
    keys = store.load_virtual_keys()
    if not keys:
        print("No virtual keys issued.")
        return EXIT_PASS

    for vk in keys:
        status = "REVOKED" if vk["revoked"] else "active"
        expires = time.ctime(vk["expires_at"]) if vk["expires_at"] else "never"
        print(f"{vk['key']} | {vk['name']} | {status} | expires: {expires} | routes: {', '.join(vk['routes'])}")
    return EXIT_PASS


def gateway_revoke_key(args: argparse.Namespace) -> int:
    """Revoke a virtual key."""
    import secrets

    policy = load_route_policy(args.config)
    master_key = os.environ.get(policy.master_key_env) if policy.master_key_env else None
    if not master_key:
        print("Error: master_key_env not configured or not set in environment", file=sys.stderr)
        return EXIT_FAIL

    provided = os.environ.get("SAFETY_GATEWAY_TOKEN")
    if not provided or not secrets.compare_digest(provided, master_key):
        print("Error: master key required (set SAFETY_GATEWAY_TOKEN)", file=sys.stderr)
        return EXIT_FAIL

    store = TraceStore(args.db)
    if not store.revoke_virtual_key(args.key):
        print(f"Error: key not found: {args.key}", file=sys.stderr)
        return EXIT_FAIL

    print(f"Revoked virtual key: {args.key}")
    return EXIT_PASS


def gateway_rotate_master(args: argparse.Namespace) -> int:
    """Rotate the master key."""
    import secrets

    policy = load_route_policy(args.config)
    master_key = os.environ.get(policy.master_key_env) if policy.master_key_env else None
    if not master_key:
        print("Error: master_key_env not configured or not set in environment", file=sys.stderr)
        return EXIT_FAIL

    provided = os.environ.get("SAFETY_GATEWAY_TOKEN")
    if not provided or not secrets.compare_digest(provided, master_key):
        print("Error: master key required (set SAFETY_GATEWAY_TOKEN)", file=sys.stderr)
        return EXIT_FAIL

    new_key = secrets.token_urlsafe(32)
    print(f"New master key: {new_key}")
    print(f"Set {policy.master_key_env}={new_key} in your environment and restart the gateway.")
    print("Existing virtual keys remain valid until they expire or are revoked.")
    return EXIT_PASS


def run_demo(args: argparse.Namespace) -> int:
    result = run(make_refund_agent(MockProvider()), args.task, TraceStore(args.db))
    print(f"run={result['run_id']}")
    print(f"status={result['status']}")
    run_status = result.get("run_status")
    if run_status is not None:
        # A single run is not evaluated for quality. Quality verdicts come from
        # `safety gate check`, which compares against a recorded baseline.
        print(f"run_status={run_status}")
    # A run that failed or was blocked must not exit 0, or a script driving the
    # CLI would treat a stopped run as a success.
    return EXIT_FAIL if result["status"] in {"failed", "blocked"} else EXIT_PASS


def run_wall(args: argparse.Namespace) -> int:
    """Print deterministic failure groups. Reporting only; always succeeds."""
    traces = TraceStore(args.db).snapshot()["traces"]
    groups = build_failure_wall(traces)
    print(f"groups={len(groups)}")
    for group in groups:
        print(
            f"{group.group_id} | {group.signature.error_type} | "
            f"{group.signature.failing_step} | traces={len(group.records)} | "
            f"state={group.state}"
        )
    return EXIT_PASS


def _delegate(prog: str, args: list[str], module: str, attr: str = "main") -> int:
    """Run a subcommand's implementation with `sys.argv` set for its parser.

    `module` is a full dotted path. Importing here rather than at module scope
    keeps the parser importable even where the implementation is absent, so
    `--help` still works in a stripped environment.
    """
    import importlib
    import sys

    try:
        entry = getattr(importlib.import_module(module), attr)
    except ImportError:
        print(
            f"{prog} could not load {module}; the installed package appears "
            "incomplete.",
            file=sys.stderr,
        )
        return EXIT_FAIL
    old = sys.argv
    try:
        sys.argv = [prog, *args]
        entry()
    finally:
        sys.argv = old
    return EXIT_PASS


def _run_check(args: argparse.Namespace) -> int:
    """Report on the caller's own integration, never on the library."""
    report = run_check(app=args.app, db=args.db)
    if args.format == "json":
        print(json.dumps(report.as_dict(), indent=2))
    else:
        print(report.render())
    if report.status is Status.PASS:
        return EXIT_PASS
    return EXIT_FAIL


def main(argv: list[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    # The gate branch is a pass-through, so it must skip this parser entirely:
    # anything after `gate` belongs to the gate parser, not to this one.
    if raw and raw[0] == "gate":
        return _delegate(
            "safety gate", raw[1:], "safety_layer.interface.gate_cli", "main"
        )

    parser = build_parser()
    args = parser.parse_args(raw)

    if args.command == "check":
        return _run_check(args)
    if args.command == "run":
        announce("bundled demo — no agent or data of yours is tested here.")
        return run_demo(args)
    if args.command == "wall":
        announce("your run history — the failures recorded in your database.")
        return run_wall(args)
    if args.command == "gateway":
        announce("your route config — the gateway holds the upstream credentials.")
        if args.gateway_cmd == "issue-key":
            return gateway_issue_key(args)
        if args.gateway_cmd == "list-keys":
            return gateway_list_keys(args)
        if args.gateway_cmd == "revoke-key":
            return gateway_revoke_key(args)
        if args.gateway_cmd == "rotate-master":
            return gateway_rotate_master(args)
        return run_gateway(args)

    parser.error("unknown command")
    return EXIT_USAGE


if __name__ == "__main__":
    raise SystemExit(main())
