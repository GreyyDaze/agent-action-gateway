"""The ``safety`` command."""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .gateway import GatewayPolicy

import argparse
from pathlib import Path

from ..evidence.failure_wall import build_failure_wall
from ..providers.mock import MockProvider
from ..providers.refund_demo_agent import make_refund_agent
from ..runtime.orchestrator import run
from ..storage.traces import TraceStore
from .gate_cli import EXIT_FAIL, EXIT_PASS, EXIT_USAGE


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="safety",
        description="Prevention-first safety and evaluation tools for AI agents.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    run_parser = sub.add_parser("run", help="run the bundled refund agent through the safety layer")
    run_parser.add_argument("task", nargs="?", default="Process the refund for Ava")
    run_parser.add_argument("--db", default="data/runtime.db")

    chaos = sub.add_parser("chaos", help="run the crash-injection proof (receipt book)")
    chaos.add_argument("--jobs", type=int, default=1000)

    proof = sub.add_parser("proof", help="reproduce the Phase 1-6 verification suites")
    proof.add_argument("--jobs", type=int, default=1000)

    gate = sub.add_parser("gate", help="run regression-gate commands")
    gate.add_argument("args", nargs=argparse.REMAINDER)

    wall = sub.add_parser("wall", help="group persisted failures from a trace database")
    wall.add_argument("--db", default="data/runtime.db")

    gateway = sub.add_parser(
        "gateway",
        help="serve the HTTP gateway: deny-by-default routes holding upstream keys",
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
    from ..storage.traces import TraceStore as Store

    policy = load_route_policy(args.config)
    server, handler = build_gateway_server(Store(args.db), policy, args.host, args.port)
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

    The proof scripts are excluded from the published wheel, so they are
    imported here rather than at module scope: an installed package still gets
    a working CLI, and only these developer commands report the absence.
    """
    import importlib
    import sys

    try:
        entry = getattr(importlib.import_module(f"safety_layer.proofs.{module}"), attr)
    except ImportError:
        print(
            f"{prog} is a developer verification command and is not part of the "
            "installed package; run it from a source checkout.",
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


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "run":
        return run_demo(args)
    if args.command == "chaos":
        return _delegate("safety chaos", ["--jobs", str(args.jobs)], "chaos")
    if args.command == "proof":
        return _delegate("safety proof", ["--jobs", str(args.jobs)], "proof")
    if args.command == "gate":
        return _delegate("safety gate", list(args.args), "gate_cli", "gate")
    if args.command == "wall":
        return run_wall(args)
    if args.command == "gateway":
        return run_gateway(args)

    parser.error("unknown command")
    return EXIT_USAGE


if __name__ == "__main__":
    raise SystemExit(main())
