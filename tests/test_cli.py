"""Tests for the `agent-gateway` command line interface.

`cli.py` had no coverage, which is where the exit-code contract lives. A user
scripting `agent-gateway` must be able to trust the process status.
"""

from __future__ import annotations

import contextlib
import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from agent_action_gateway import cli
from agent_action_gateway.gate_cli import EXIT_PASS, EXIT_USAGE

ROOT = Path(__file__).resolve().parents[1]


class ParserTest(unittest.TestCase):
    def test_every_documented_command_is_registered(self) -> None:
        parser = cli.build_parser()
        for command in ("check", "gate", "wall", "path", "prune", "gateway", "mcp-serve", "mcp-proxy", "egress-serve", "dashboard"):
            with self.subTest(command=command):
                self.assertIn(command, parser.format_help())

    def test_framework_verification_is_not_a_user_command(self) -> None:
        """Self-verification belongs to `make`, not to an installed CLI.

        A command with no adopter input cannot report on the adopter, so
        shipping it invites a green result to be read as a verdict on their
        integration.
        """
        help_text = cli.build_parser().format_help()
        for command in ("proof", "chaos"):
            with self.subTest(command=command):
                self.assertNotIn(command, help_text)
                with self.assertRaises(SystemExit):
                    cli.build_parser().parse_args([command])

    def test_check_defaults_to_text_output(self) -> None:
        args = cli.build_parser().parse_args(["check"])
        self.assertEqual(args.format, "text")
        self.assertIsNone(args.app)
        self.assertIsNone(args.db)

    def test_gate_forwards_remaining_arguments(self) -> None:
        args = cli.build_parser().parse_args(["gate", "check", "--lane", "full"])
        self.assertEqual(args.command, "gate")
        self.assertIn("check", args.args)

    def test_missing_command_is_a_usage_error(self) -> None:
        with self.assertRaises(SystemExit) as raised:
            cli.build_parser().parse_args([])
        self.assertEqual(raised.exception.code, EXIT_USAGE)


class DashboardCommandTest(unittest.TestCase):
    def test_dashboard_command_serves_the_given_database(self) -> None:
        from unittest import mock

        with mock.patch("agent_action_gateway.observability.dashboard.serve") as serve:
            code = cli.main(["dashboard", "--db", "x.db", "--port", "8123"])
        self.assertEqual(code, 0)
        serve.assert_called_once_with("x.db", "127.0.0.1", 8123)


class DelegationTest(unittest.TestCase):
    """`agent-gateway gate` must actually reach its implementation.

    It once imported from `agent_action_gateway.proofs.gate_cli`, which does not exist,
    so every invocation printed an "is a developer verification command" notice
    and exited 1. The parser tests and `--help` tests passed throughout.
    """

    def test_delegate_resolves_a_full_module_path(self) -> None:
        import importlib

        for module in ("agent_action_gateway.gate_cli",):
            with self.subTest(module=module):
                self.assertTrue(hasattr(importlib.import_module(module), "main"))

    def test_gate_subcommand_is_not_a_dead_end(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "agent_action_gateway", "gate", "--help"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("developer verification command", result.stderr)
        self.assertIn("check", result.stdout)

    def test_no_subcommand_reports_itself_unavailable(self) -> None:
        """The unavailability notice is reserved for genuinely missing code."""
        for args in (["gate", "--help"], ["check"], ["wall", "--db", "/nonexistent.db"]):
            with self.subTest(args=args):
                result = subprocess.run(
                    [sys.executable, "-m", "agent_action_gateway", *args],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                )
                self.assertNotIn(
                    "developer verification command", result.stderr + result.stdout
                )


class WallCommandTest(unittest.TestCase):
    def test_empty_database_reports_zero_groups(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                code = cli.main(["wall", "--db", str(Path(directory) / "empty.db")])
            self.assertEqual(code, EXIT_PASS)
            output = buffer.getvalue()
            self.assertIn("SCOPE: your run history", output)
            self.assertIn("groups=0", output)

    def test_failed_trace_is_grouped(self) -> None:
        from agent_action_gateway.runtime.records import TraceEvent
        from agent_action_gateway.storage.traces import TraceStore

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
            [sys.executable, "-m", "agent_action_gateway", *args],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

    def test_help_exits_zero(self) -> None:
        self.assertEqual(self._run("--help").returncode, 0)

    def test_unknown_flag_is_a_usage_error(self) -> None:
        self.assertEqual(self._run("wall", "--nope").returncode, EXIT_USAGE)

    def test_wall_on_empty_database(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = self._run("wall", "--db", str(Path(directory) / "e.db"))
            self.assertEqual(result.returncode, 0)
            self.assertIn("SCOPE: your run history", result.stdout)
            self.assertIn("groups=0", result.stdout)


if __name__ == "__main__":
    unittest.main()
