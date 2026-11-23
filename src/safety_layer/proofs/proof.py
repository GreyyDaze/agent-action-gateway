"""Runs each guarantee suite and reports whether it holds."""
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
            if (node / "tests" / "test_approvals.py").is_file():
                return node

    raise SystemExit(
        "verification proofs require a source checkout containing tests/test_approvals.py; "
        "run this command from the repository root. The packaged wheel does not "
        "include the proof suite."
    )

# Labelled by the guarantee each suite proves rather than by build-phase
# number, so the output is meaningful to someone who has never seen the plan.
PROOFS = (
    (
        "ADOPTION CONTRACT",
        ["tests/test_adoption_contract.py"],
        "guarded tools are the only path; unapproved actions never execute",
    ),
    (
        "APPROVAL SAFETY",
        ["tests/test_approvals.py"],
        "0 destructive executions without valid fresh approval",
    ),
    (
        "REGRESSION GATE",
        ["tests/test_evaluation.py", "tests/test_gate.py"],
        "injected regression caught; unchanged-run false-alarm checks",
    ),
    (
        "STOP RULES",
        ["tests/test_stop_rules.py"],
        "defined traps caught; legitimate suite has zero false stops",
    ),
    (
        "BUDGETS AND LOOPS",
        ["tests/test_fuses.py"],
        "zero budget overruns; loop detection trips; pagination passes",
    ),
    (
        "FAILURE WALL",
        [
            "tests/test_failure_wall.py",
            "tests/test_silent_failures.py",
            "tests/test_failure_promotion_drill.py",
            "tests/test_trace.py",
        ],
        "planted silent-wrong cases flagged; failure signatures group correctly",
    ),
)


def _run(command: list[str], cwd: Path) -> None:
    print("$ " + " ".join(command))
    result = subprocess.run(command, cwd=cwd, text=True)
    if result.returncode:
        raise SystemExit(result.returncode)


def run_proofs(jobs: int, *, root: Path | None = None) -> None:
    repo_root = Path(root).resolve() if root is not None else find_repo_root()
    _run(
        [sys.executable, "-m", "safety_layer.proofs.chaos", "--jobs", str(jobs)],
        repo_root,
    )
    print("SCOPE: this library itself — no adopter's agent or data is tested.\n")
    print(f"CRASH SAFETY: PASS | 0 dupes / {jobs} crash jobs")
    print(f"DUPLICATE SUPPRESSION: PASS | 1 side effect / {jobs} crashed retries")
    for guarantee, paths, statement in PROOFS:
        _run([sys.executable, "-m", "pytest", "-q", *paths], repo_root)
        print(f"{guarantee}: PASS | {statement}")
    print("ALL GUARANTEES HOLD")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="make proof",
        description="Run this library's own verification suites (repo tests, not an adopter's integration).",
    )
    parser.add_argument("--jobs", type=int, default=1000)
    args = parser.parse_args(argv)
    if args.jobs < 1:
        parser.error("--jobs must be >= 1")
    run_proofs(args.jobs)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
