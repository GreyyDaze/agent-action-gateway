from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_module_cli_exposes_phase7_commands() -> None:
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
