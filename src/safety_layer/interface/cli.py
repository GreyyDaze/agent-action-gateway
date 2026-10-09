"""The ``safety`` command."""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .gateway import GatewayPolicy

import argparse
import json
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
        session_environment=str(document.get("session_environment", "dev"))
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

    policy = load_route_policy(args.config)
    server, handler = build_gateway_server(TraceStore(args.db), policy, args.host, args.port)
    print(f"Safety gateway on http://{args.host}:{server.server_address[1]}/")
    print(f"access token: {getattr(handler, 'access_token', '')}")
    print(f"registered routes: {len(policy.routes)} (anything else is refused)")
    server.serve_forever()
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
        return run_gateway(args)

    parser.error("unknown command")
    return EXIT_USAGE


if __name__ == "__main__":
    raise SystemExit(main())
