from __future__ import annotations

import argparse
import json
from pathlib import Path

from .gate_cli import main as gate_main
from .mock_provider import MockProvider
from .phase1_proof import main as chaos_main
from .proof import main as proof_main
from .refund_agent import make_refund_agent
from .runtime import run
from .store import TraceStore
from .phase6_trace import build_failure_wall


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="safety",
        description="Prevention-first safety and evaluation tools for AI agents.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    run_parser = sub.add_parser("run", help="run the bundled refund agent through the safety layer")
    run_parser.add_argument("task", nargs="?", default="Process the refund for Ava")
    run_parser.add_argument("--db", default="data/runtime.db")

    chaos = sub.add_parser("chaos", help="run the Phase 1 crash-injection proof")
    chaos.add_argument("--jobs", type=int, default=1000)

    proof = sub.add_parser("proof", help="reproduce the Phase 1-6 proof suites")
    proof.add_argument("--jobs", type=int, default=1000)

    gate = sub.add_parser("gate", help="run regression-gate commands")
    gate.add_argument("args", nargs=argparse.REMAINDER)

    wall = sub.add_parser("wall", help="group persisted failures from a trace database")
    wall.add_argument("--db", default="data/runtime.db")

    return parser


def run_demo(args: argparse.Namespace) -> int:
    result = run(make_refund_agent(MockProvider()), args.task, TraceStore(args.db))
    gate = result.get("gate")
    print(f"run={result['run_id']}")
    print(f"status={result['status']}")
    if gate is not None:
        print(f"gate={gate.verdict} score={gate.score:.1f} threshold={gate.threshold:.1f}")
    return 0


def run_wall(args: argparse.Namespace) -> int:
    traces = TraceStore(args.db).snapshot()["traces"]
    groups = build_failure_wall(traces)
    print(f"groups={len(groups)}")
    for group in groups:
        print(
            f"{group.group_id} | {group.signature.error_type} | "
            f"{group.signature.failing_step} | traces={len(group.records)} | "
            f"state={group.state}"
        )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "run":
        return run_demo(args)
    if args.command == "chaos":
        # Reuse the existing proof harness. The CLI owns no safety logic.
        import sys
        old = sys.argv
        try:
            sys.argv = ["safety chaos", "--jobs", str(args.jobs)]
            chaos_main()
        finally:
            sys.argv = old
        return 0
    if args.command == "proof":
        old = sys.argv
        try:
            sys.argv = ["safety proof", "--jobs", str(args.jobs)]
            proof_main()
        finally:
            sys.argv = old
        return 0
    if args.command == "gate":
        import sys
        old = sys.argv
        try:
            sys.argv = ["safety gate", *args.args]
            gate_main()
        finally:
            sys.argv = old
        return 0
    if args.command == "wall":
        return run_wall(args)

    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
