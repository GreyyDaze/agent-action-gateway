"""Tests for the `safety` command line interface.

`cli.py` had no coverage, which is where the exit-code contract lives. A user
scripting `safety run` must be able to trust the process status.
"""

from __future__ import annotations

import contextlib
import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from safety_layer import cli
from safety_layer.gate_cli import EXIT_FAIL, EXIT_PASS, EXIT_USAGE

ROOT = Path(__file__).resolve().parents[1]


class ParserTest(unittest.TestCase):
    def test_every_documented_command_is_registered(self) -> None:
        parser = cli.build_parser()
        for command in ("run", "chaos", "proof", "gate", "wall"):
            with self.subTest(command=command):
                self.assertIn(command, parser.format_help())

    def test_run_defaults_to_the_demo_task(self) -> None:
        args = cli.build_parser().parse_args(["run"])
        self.assertEqual(args.task, "Process the refund for Ava")
        self.assertEqual(args.db, "data/runtime.db")

    def test_chaos_and_proof_default_to_1000_jobs(self) -> None:
        parser = cli.build_parser()
        self.assertEqual(parser.parse_args(["chaos"]).jobs, 1000)
        self.assertEqual(parser.parse_args(["proof"]).jobs, 1000)

    def test_gate_forwards_remaining_arguments(self) -> None:
        args = cli.build_parser().parse_args(["gate", "check", "--lane", "full"])
        self.assertEqual(args.command, "gate")
        self.assertIn("check", args.args)

    def test_missing_command_is_a_usage_error(self) -> None:
        with self.assertRaises(SystemExit) as raised:
            cli.build_parser().parse_args([])
        self.assertEqual(raised.exception.code, EXIT_USAGE)


class RunCommandTest(unittest.TestCase):
    def test_completed_run_exits_zero(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                code = cli.main(["run", "Process the refund for Ava", "--db", str(Path(directory) / "r.db")])
            self.assertEqual(code, EXIT_PASS)
            self.assertIn("status=completed", buffer.getvalue())

    def test_run_reports_not_evaluated_rather_than_a_pass(self) -> None:
        """A single run is not an evaluation and must not claim PASS."""
        with tempfile.TemporaryDirectory() as directory:
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                cli.main(["run", "Process the refund for Ava", "--db", str(Path(directory) / "r.db")])
            output = buffer.getvalue()
            self.assertIn("run_status=NOT_EVALUATED", output)
            self.assertNotIn("PASS", output)

    def test_blocked_run_exits_non_zero(self) -> None:
        """A stopped run must not look like a success to a calling script."""
        with tempfile.TemporaryDirectory() as directory:
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                code = cli.main(
                    [
                        "run",
                        "Refund the account for nobody at all",
                        "--db",
                        str(Path(directory) / "r.db"),
                    ]
                )
            self.assertIn(code, {EXIT_PASS, EXIT_FAIL})
            if "status=blocked" in buffer.getvalue():
                self.assertEqual(code, EXIT_FAIL)


class WallCommandTest(unittest.TestCase):
    def test_empty_database_reports_zero_groups(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                code = cli.main(["wall", "--db", str(Path(directory) / "empty.db")])
            self.assertEqual(code, EXIT_PASS)
            self.assertEqual(buffer.getvalue().strip(), "groups=0")

    def test_failed_trace_is_grouped(self) -> None:
        from safety_layer.models import TraceEvent
        from safety_layer.store import TraceStore

        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / "w.db"
            store = TraceStore(db)
            store.append_trace(
                TraceEvent("run-x", 1, "tool.call", "task", {"error": {"type": "TimeoutError"}}, "failed")
            )
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                cli.main(["wall", "--db", str(db)])
            output = buffer.getvalue()
            self.assertIn("groups=1", output)
            self.assertIn("TimeoutError", output)


class SubprocessTest(unittest.TestCase):
    """The console-script path, which argparse-level tests do not cover."""

    def _run(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "safety_layer", *args],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

    def test_help_exits_zero(self) -> None:
        self.assertEqual(self._run("--help").returncode, 0)

    def test_unknown_flag_is_a_usage_error(self) -> None:
        self.assertEqual(self._run("run", "--nope").returncode, EXIT_USAGE)

    def test_wall_on_empty_database(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = self._run("wall", "--db", str(Path(directory) / "e.db"))
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout.strip(), "groups=0")


if __name__ == "__main__":
    unittest.main()
