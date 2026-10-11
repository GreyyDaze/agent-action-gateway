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

    path = sub.add_parser(
        "path",
        help="score how each run got there, not just whether it finished",
    )
    path.add_argument("--db", default="data/runtime.db")
    path.add_argument("--run", help="score only this run")
    path.add_argument("--format", choices=("text", "json"), default="text")
    path.add_argument(
        "--expect",
        help="comma-separated actions a run was supposed to attempt",
    )

    prune = sub.add_parser(
        "prune",
        help="discard recorded prompts and completions, keeping the evidence",
    )
    prune.add_argument("--db", default="data/runtime.db")
    prune.add_argument(
        "--older-than",
        type=float,
        metavar="DAYS",
        help="only prune records written more than DAYS ago",
    )
    prune.add_argument(
        "--keep-latest",
        type=int,
        metavar="N",
        help="always keep the newest N recorded exchanges per run",
    )
    prune.add_argument(
        "--dry-run",
        action="store_true",
        help="report what would go without changing anything",
    )

    gateway = sub.add_parser(
        "gateway",
        help="serve the HTTP gateway for your routes (it holds the upstream keys)",
    )
    # Not required at this level: `gateway doctor` and `gateway issue-key`
    # each take their own --config after the subcommand. run_gateway and the
    # key commands check for it themselves.
    gateway.add_argument("--config", help="YAML or JSON route table")
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

    doctor = gateway_sub.add_parser(
        "doctor",
        help="check this host's gateway configuration",
    )
    doctor.add_argument("--config", required=True, help="YAML or JSON route table")
    doctor.add_argument("--db", default="data/runtime.db")

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
        method = str(entry.get("method", "POST")).upper()
        # The HTTP shell exposes POST only. A route declaring another method
        # would never be matched, and the gateway would refuse it forever as
        # "not registered" -- a dead route that looks configured.
        if method != "POST":
            raise ValueError(
                f"route {entry.get('path')!r} declares method {method}, but the "
                "gateway serves POST only. Use a provider endpoint that accepts "
                "a POST body."
            )
        policy.register(
            Route(
                path=str(entry["path"]),
                upstream=str(entry["upstream"]),
                action=str(entry["action"]),
                risk=str(entry.get("risk", "destructive")),
                method=method,
                secret_env=str(entry.get("secret_env", "")),
                environment=str(entry.get("environment", "prod")),
            )
        )
    return policy


def run_gateway(args: argparse.Namespace) -> int:

    from ..interface.gateway import build_gateway_server
    from ..storage.traces import TraceStore

    if not args.config:
        print("gateway requires --config pointing at your route table", file=sys.stderr)
        return EXIT_USAGE

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
    # Flushed explicitly: under a service manager or a container, stdout is a
    # pipe and therefore block-buffered, so an unflushed banner stays in the
    # buffer. The operator would see no output at all and no access token.
    print(f"access token: {getattr(handler, 'access_token', '')}", flush=True)
    print(f"registered routes: {len(policy.routes)} (anything else is refused)", flush=True)
    server.serve_forever()
    return EXIT_PASS


def _policy_or_fail(args: argparse.Namespace) -> GatewayPolicy | None:
    """Load the route policy, or explain what is missing.

    The gateway parser no longer requires --config itself, because each
    subcommand takes its own after the subcommand name. Every command that
    genuinely needs a route table goes through here so the failure message is
    the same everywhere.
    """
    if not args.config:
        print("this command requires --config pointing at your route table", file=sys.stderr)
        return None
    try:
        return load_route_policy(args.config)
    except (OSError, ValueError) as exc:
        print(f"could not read {args.config}: {exc}", file=sys.stderr)
        return None


def _master_key_or_fail(policy: GatewayPolicy) -> str | None:
    """The master key from the environment, or an explanation.

    Key management is gated by OS access, not by a token. Anyone who can run
    this command as this user can already read the same environment variable
    the gateway reads, so asking them to prove possession of it would be theatre.
    The real control is who may run the command at all -- which is exactly the
    boundary the deployment is responsible for.
    """
    name = policy.master_key_env
    if not name:
        print(
            "This route table declares no master_key_env, so there is nothing to "
            "authenticate against. Add one, or use the startup token instead.",
            file=sys.stderr,
        )
        return None
    value = os.environ.get(name)
    if not value:
        print(f"Error: {name} is set in the config but not in the environment", file=sys.stderr)
        return None
    return value


def gateway_issue_key(args: argparse.Namespace) -> int:
    """Issue a virtual key for an agent."""
    import secrets
    import time

    policy = _policy_or_fail(args)
    if policy is None:
        return EXIT_USAGE
    if _master_key_or_fail(policy) is None:
        return EXIT_USAGE

    # Verify the request is authenticated with master key
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

    policy = _policy_or_fail(args)
    if policy is None:
        return EXIT_USAGE
    if _master_key_or_fail(policy) is None:
        return EXIT_USAGE

    store = TraceStore(args.db)
    if not store.revoke_virtual_key(args.key):
        print(f"Error: key not found: {args.key}", file=sys.stderr)
        return EXIT_FAIL

    print(f"Revoked virtual key: {args.key}")
    return EXIT_PASS


def gateway_rotate_master(args: argparse.Namespace) -> int:
    """Rotate the master key."""
    import secrets

    policy = _policy_or_fail(args)
    if policy is None:
        return EXIT_USAGE
    if _master_key_or_fail(policy) is None:
        return EXIT_USAGE

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


def gateway_doctor(args: argparse.Namespace) -> int:
    """Report on this host's gateway configuration.

    Every check here runs on the gateway side, so every check is something the
    gateway can genuinely observe: the uid it is running as, the owner and mode
    of each secret file, whether a master key is configured, what it binds to.

    What it deliberately does NOT check is whether the agent can reach a
    provider. That is a different machine, namespace or container, and reporting
    on it from here would be inventing evidence. Run `make verify-boundary` for
    that half -- it attaches to the agent's network and tries to escape.
    """
    import grp
    import stat

    print("SCOPE: this host's gateway configuration only.")
    print("Does NOT report whether your agent can reach a provider -- that needs")
    print("`make verify-boundary`, which runs from the agent's position.\n")

    findings: list[tuple[str, str, str]] = []  # (status, label, detail)

    def check(status: str, label: str, detail: str) -> None:
        findings.append((status, label, detail))

    try:
        policy = load_route_policy(args.config)
    except (OSError, ValueError) as exc:
        print(f"could not read {args.config}: {exc}", file=sys.stderr)
        return EXIT_FAIL

    # 1. Privilege. A root gateway puts its secret in reach of every user.
    euid = os.geteuid()
    if euid == 0:
        check("WARN", "running as root", "every local user can reach this process's secret")
    else:
        try:
            name = grp.getgrgid(euid).gr_name
        except KeyError:
            name = f"uid {euid}"
        check("OK", f"running as {name}", "not root")

    # 2. Secret files. Mode and owner are the whole boundary for a file secret.
    for route in policy.routes.values():
        reference = route.secret_env
        if not reference:
            continue
        if reference.startswith("file:"):
            path = reference[5:]
            try:
                info = os.stat(path)
            except OSError as exc:
                check("FAIL", f"{route.path} secret", f"cannot read {path}: {exc.strerror}")
                continue
            mode = stat.S_IMODE(info.st_mode)
            if mode & 0o077:
                check(
                    "FAIL",
                    f"{route.path} secret",
                    f"{path} is mode {mode:04o}; the gateway will refuse to read it "
                    "until it is 0600",
                )
            elif info.st_uid != euid:
                check(
                    "FAIL",
                    f"{route.path} secret",
                    f"{path} is owned by uid {info.st_uid}, not the gateway's {euid}",
                )
            else:
                check("OK", f"{route.path} secret", f"{path} mode {mode:04o}, owned by this user")
        else:
            check(
                "WARN",
                f"{route.path} secret",
                f"{reference} is an environment variable, so any process sharing this "
                "user can read it; prefer secret_env: \"file:/path\"",
            )

    # 3. Master key. Virtual keys are meaningless without one.
    if not policy.master_key_env:
        check("WARN", "no master key configured", "callers can only use the startup token")
    elif not os.environ.get(policy.master_key_env):
        check("FAIL", "master key", f"{policy.master_key_env} is set in the config but not in the environment")
    else:
        check("OK", "master key", f"{policy.master_key_env} is set")

    # 4. Bind address. Loopback is the only safe default for a local gateway.
    check(
        "OK",
        "bind address",
        f"{args.host}:{args.port}"
        + (
            ""
            if args.host in {"127.0.0.1", "localhost", "::1"}
            else "  <- off-host: reachable beyond this machine"
        ),
    )

    for status, label, detail in findings:
        print(f"[{status}] {label}: {detail}")

    failed = [f for f in findings if f[0] == "FAIL"]
    warned = [f for f in findings if f[0] == "WARN"]
    print()
    if failed:
        print(f"{len(failed)} problem(s) would stop the gateway from starting correctly.")
        return EXIT_FAIL
    if warned:
        print(f"{len(warned)} warning(s). The gateway will run, but see docs/gateway-deployment.md.")
    else:
        print("This host's configuration is consistent. This does not verify the topology.")
    return EXIT_PASS


def run_path_report(args: argparse.Namespace) -> int:
    """Score the path each recorded run took.

    Additive only: nothing here changes a verdict. A run that finished cleanly
    can still have reached for something it should not have, and that is the
    thing worth seeing. Reporting is always safe; gating is a separate decision.
    """
    from ..evaluation.trajectory import score

    traces = TraceStore(args.db).snapshot()["traces"]
    by_run: dict[str, list] = {}
    for trace in traces:
        by_run.setdefault(str(trace.get("run_id")), []).append(trace)

    expected = [a.strip() for a in (args.expect or "").split(",") if a.strip()]
    selected = {args.run} if args.run else set(by_run)

    report = []
    for run_id, steps in sorted(by_run.items()):
        if run_id not in selected:
            continue
        report.append({"run_id": run_id, **score(steps, expected_actions=expected).as_dict()})

    if args.format == "json":
        print(json.dumps({"runs": report}, indent=2))
    else:
        for entry in report:
            if entry["clean"]:
                print(f"{entry['run_id']}  clean path  penalty=0")
                continue
            print(f"{entry['run_id']}  penalty={entry['penalty']}  {', '.join(entry['kinds'])}")
            for signal in entry["signals"]:
                print(f"    step {signal['step']}: {signal['detail']}")
        if report and all(entry["clean"] for entry in report):
            print("\nNo safety problems found in the recorded paths.")
        elif not report:
            print("No runs recorded.")

    # A finding is not a failure of the tool. Exit 0 unless nothing was scored,
    # so this composes in a pipeline without being mistaken for a gate.
    return EXIT_PASS if report else EXIT_FAIL


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


def run_prune(args: argparse.Namespace) -> int:
    """Discard exchange payloads, keeping the rows that record they existed.

    Dry run by default when nothing is specified -- pruning without a bound
    would delete every exchange recorded so far, which is a decision a person
    should make rather than a flag someone forgot to pass.
    """
    if args.older_than is None and args.keep_latest is None:
        print(
            "prune needs --older-than DAYS or --keep-latest N; "
            "without one it would discard every recorded exchange",
            file=sys.stderr,
        )
        return EXIT_USAGE

    report = TraceStore(args.db).prune_exchanges(
        older_than_days=args.older_than,
        keep_latest_per_run=args.keep_latest,
        dry_run=args.dry_run,
    )
    verb = "would prune" if args.dry_run else "pruned"
    print(f"{verb} {report['selected']} of {report['candidates']} recorded exchanges")
    if args.dry_run:
        print("dry run: nothing changed")
    else:
        print(
            "the rows remain, with exchange_state=pruned; receipts were not touched"
        )
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
    if args.command == "path":
        announce("how your recorded runs got there — not a quality judgement.")
        return run_path_report(args)
    if args.command == "prune":
        announce("your recorded prompts and completions — the rows stay.")
        return run_prune(args)
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
        if args.gateway_cmd == "doctor":
            return gateway_doctor(args)
        return run_gateway(args)

    parser.error("unknown command")
    return EXIT_USAGE


if __name__ == "__main__":
    raise SystemExit(main())
