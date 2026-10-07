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
