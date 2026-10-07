from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

PROOFS = (
    ("P2", ["tests/test_phase2.py"], "0 destructive executions without valid fresh approval"),
    ("P3", ["tests/test_phase3.py", "tests/test_phase3_gate.py"], "injected regression caught; unchanged-run false-alarm checks"),
    ("P4", ["tests/test_phase4_stop_rules.py"], "defined traps caught; legitimate suite has zero false stops"),
    ("P5", ["tests/test_phase5_fuses.py"], "zero budget overruns; loop detection trips; pagination passes"),
    ("P6", ["tests/test_phase6_final_proof.py", "tests/test_phase6_planted_failures.py", "tests/test_phase6_promotion_drill.py", "tests/test_phase6_trace.py"], "planted silent-wrong cases flagged; failure signatures group correctly"),
)


def _run(command: list[str]) -> None:
    print("$ " + " ".join(command))
    result = subprocess.run(command, cwd=ROOT, text=True)
    if result.returncode:
        raise SystemExit(result.returncode)


def run_proofs(jobs: int) -> None:
    _run([sys.executable, "-m", "safety_layer.phase1_proof", "--jobs", str(jobs)])
    print(f"P1 PROOF: 0 dupes / {jobs} crash jobs")
    for phase, paths, statement in PROOFS:
        _run([sys.executable, "-m", "pytest", "-q", *paths])
        print(f"{phase} PROOF: PASS | {statement}")
    print("PHASE PROOFS: PASS")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="safety proof", description="Reproduce the deterministic Phase 1-6 proof suites.")
    parser.add_argument("--jobs", type=int, default=1000)
    args = parser.parse_args(argv)
    if args.jobs < 1:
        parser.error("--jobs must be >= 1")
    run_proofs(args.jobs)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
