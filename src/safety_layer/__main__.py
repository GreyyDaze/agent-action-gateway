import argparse

from .mock_provider import MockProvider
from .refund_agent import make_refund_agent
from .runtime import run
from .store import TraceStore


def main() -> None:
    parser = argparse.ArgumentParser(description="Phase 0 agent safety layer demo")
    parser.add_argument("task", nargs="?", default="Process the refund for Ava")
    parser.add_argument("--db", default="data/runtime.db")
    args = parser.parse_args()

    result = run(make_refund_agent(MockProvider()), args.task, TraceStore(args.db))
    gate = result["gate"]
    print(f"run={result['run_id']}")
    print(f"status={result['status']}")
    print(f"gate={gate.verdict} score={gate.score:.1f} threshold={gate.threshold:.1f}")
    print("P0: 1 trace+ 1 receipt+ 1 gate verdict")


if __name__ == "__main__":
    main()
