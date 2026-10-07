from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


def find_repo_root(start: Path | None = None) -> Path:
    """Locate the source checkout that owns the phase proof suites.

    The proof suites are repository tests, not packaged runtime data, so they
    are not shipped inside the wheel. Resolve the checkout from the working
    directory instead of guessing from __file__, which points at site-packages
    for a non-editable install.
    """
    candidates = []
    if start is not None:
        candidates.append(Path(start).resolve())
    candidates.append(Path.cwd().resolve())
    for directory in (Path(__file__).resolve().parent,):
        candidates.extend(directory.parents)

    for candidate in candidates:
        for node in (candidate, *candidate.parents):
            if (node / "tests" / "test_phase2.py").is_file():
                return node

    raise SystemExit(
        "phase proofs require a source checkout containing tests/test_phase2.py; "
        "run this command from the repository root. The packaged wheel does not "
        "include the proof suite."
    )

PROOFS = (
    ("P2", ["tests/test_phase2.py"], "0 destructive executions without valid fresh approval"),
    ("P3", ["tests/test_phase3.py", "tests/test_phase3_gate.py"], "injected regression caught; unchanged-run false-alarm checks"),
    ("P4", ["tests/test_phase4_stop_rules.py"], "defined traps caught; legitimate suite has zero false stops"),
    ("P5", ["tests/test_phase5_fuses.py"], "zero budget overruns; loop detection trips; pagination passes"),
    ("P6", ["tests/test_phase6_final_proof.py", "tests/test_phase6_planted_failures.py", "tests/test_phase6_promotion_drill.py", "tests/test_phase6_trace.py"], "planted silent-wrong cases flagged; failure signatures group correctly"),
)


def _run(command: list[str], cwd: Path) -> None:
    print("$ " + " ".join(command))
    result = subprocess.run(command, cwd=cwd, text=True)
    if result.returncode:
        raise SystemExit(result.returncode)


def run_proofs(jobs: int, *, root: Path | None = None) -> None:
    repo_root = Path(root).resolve() if root is not None else find_repo_root()
    _run(
        [sys.executable, "-m", "safety_layer.phase1_proof", "--jobs", str(jobs)],
        repo_root,
    )
    print(f"P1 PROOF: 0 dupes / {jobs} crash jobs")
    for phase, paths, statement in PROOFS:
        _run([sys.executable, "-m", "pytest", "-q", *paths], repo_root)
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
