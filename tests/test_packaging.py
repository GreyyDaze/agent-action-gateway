from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_module_cli_exposes_packaging_commands() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "safety_layer", "--help"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    assert "run" in result.stdout
    assert "chaos" in result.stdout
    assert "gate" in result.stdout
    assert "wall" in result.stdout


def test_module_cli_wall_is_safe_on_empty_database(tmp_path: Path) -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "safety_layer",
            "wall",
            "--db",
            str(tmp_path / "runtime.db"),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout.strip() == "groups=0"


def test_evaluation_artifacts_load_from_package_resources() -> None:
    """The canonical JSON artifacts must resolve via importlib.resources.

    An earlier build shipped them as data-files, which install relative to
    sys.prefix (the venv root) instead of next to the package. The loaders
    resolved a guessed filesystem path and raised on a non-editable install.
    """
    from safety_layer.calibration import load_calibration_set
    from safety_layer.golden import load_golden_set

    assert len(load_golden_set()) == 30
    assert len(load_calibration_set()) == 6


def test_packaged_artifacts_are_not_loaded_from_repo_checkout() -> None:
    """Resolution must not depend on the source tree being present."""
    from safety_layer.calibration import default_calibration_set_path
    from safety_layer.golden import default_golden_set_path

    package_root = Path(__import__("safety_layer").__file__).resolve().parent
    for resolved in (default_golden_set_path(), default_calibration_set_path()):
        assert package_root in resolved.parents


def test_proof_command_runs_and_prints_phase_proofs() -> None:
    """The proof command must execute, not just appear in --help.

    The command previously crashed with UnboundLocalError because the branch
    used `sys` without importing it, while --help tests still passed.
    """
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "safety_layer",
            "proof",
            "--jobs",
            "1",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "P1 PROOF" in result.stdout
    assert "PHASE PROOFS: PASS" in result.stdout


def test_dashboard_snapshot_exposes_runs_and_budget_counters(tmp_path: Path) -> None:
    from types import SimpleNamespace

    from safety_layer.store import TraceStore

    store = TraceStore(tmp_path / "runtime.db")
    store.append_trace(
        __import__("safety_layer.models", fromlist=["TraceEvent"]).TraceEvent(
            "run-1", 1, "agent", "task", {"ok": True}, "completed"
        )
    )
    store.record_fuse_snapshot(
        "run-1",
        SimpleNamespace(
            steps_used=2,
            dollars_used=0.25,
            elapsed_seconds=1.5,
            tripped=False,
            degraded=False,
            reason=None,
        ),
    )
    snapshot = store.dashboard_snapshot()
    assert snapshot["runs"][0]["run_id"] == "run-1"
    assert snapshot["budgets"][0]["steps_used"] == 2
    assert snapshot["budgets"][0]["dollars_used"] == 0.25
