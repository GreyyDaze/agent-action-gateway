"""`safety check` — verifying the caller's wiring rather than the library.

The library's own suites prove the enforcement path works. They cannot show
whether a given application routes actions through it, so these tests pin the
behaviour that makes the gap visible at all.

The rule these tests exist to protect: an empty or unreadable input must never
be reported as a pass. An action that bypasses the layer leaves no trace, so
"nothing to check" and "everything is fine" are different answers, and only
one of them is true.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from safety_layer.interface.wiring import (
    Status,
    audit_database,
    run_check,
    scan_code,
)
from safety_layer.storage.traces import TraceStore

ROOT = Path(__file__).resolve().parents[1]

GUARDED = '''
from safety_layer import session

def build():
    with session() as ctx:
        refund = ctx.tool(refund_fn, action="refund", risk="destructive")
        lookup = ctx.tool(lookup_fn, action="lookup", risk="read")
        return ctx.run(agent, task, tools={"refund": refund, "lookup": lookup})
'''

# The documented wrapper pattern: the wrapper is *supposed* to call the
# provider. Flagging this would make the checker useless on correct code.
WRAPPED_PROVIDER_CALL = '''
from safety_layer import session

def build(provider):
    with session() as ctx:
        refund = ctx.tool(
            lambda order_id, intent_key: provider.execute(order_id, intent_key),
            action="refund",
            risk="destructive",
            provider=provider,
        )
'''

BYPASSES_LAYER = '''
import stripe
from safety_layer import session

def build(provider):
    stripe.PaymentIntent.create(amount=400000)
    with session() as ctx:
        refund = ctx.tool(refund_fn, action="refund", risk="destructive")
    provider.refund("ORD-1", "k1")
'''


def write_app(source: str) -> Path:
    directory = Path(tempfile.mkdtemp())
    (directory / "agent.py").write_text(source, encoding="utf-8")
    return directory


class StaticScanTest(unittest.TestCase):
    """`--app` is the only mode that can see a bypass."""

    def test_correctly_wired_code_passes(self) -> None:
        report = scan_code(write_app(GUARDED))
        self.assertIs(report.status, Status.PASS, report.render())

    def test_documented_wrapper_pattern_is_not_a_false_positive(self) -> None:
        """The wrapper calling the provider is the guard working."""
        report = scan_code(write_app(WRAPPED_PROVIDER_CALL))
        self.assertIs(report.status, Status.PASS, report.render())

    def test_direct_provider_import_fails(self) -> None:
        report = scan_code(write_app(BYPASSES_LAYER))
        self.assertIs(report.status, Status.FAIL, report.render())
        names = {f.name for f in report.findings if f.status is Status.FAIL}
        self.assertIn("direct provider imports", names)

    def test_direct_provider_call_fails(self) -> None:
        report = scan_code(write_app(BYPASSES_LAYER))
        call_findings = [f for f in report.findings if f.name.startswith("provider calls")]
        self.assertEqual(call_findings[0].status, Status.FAIL)

    def test_findings_carry_file_and_line(self) -> None:
        report = scan_code(write_app(BYPASSES_LAYER))
        locations = [loc for f in report.findings for loc in f.locations]
        self.assertTrue(any("agent.py:" in loc for loc in locations), locations)

    def test_empty_directory_is_inconclusive_not_a_pass(self) -> None:
        directory = Path(tempfile.mkdtemp())
        report = scan_code(directory)
        self.assertIs(report.status, Status.INCONCLUSIVE, report.render())

    def test_unparsable_source_is_reported_not_swallowed(self) -> None:
        directory = Path(tempfile.mkdtemp())
        (directory / "broken.py").write_text("def (:\n", encoding="utf-8")
        report = scan_code(directory)
        self.assertIsNot(report.status, Status.PASS)
        self.assertTrue(any("SyntaxError" in f.detail or f.status is Status.INCONCLUSIVE
                            for f in report.findings))


class DatabaseAuditTest(unittest.TestCase):
    """`--db` reports on recorded actions, and never invents safety."""

    def test_missing_database_is_inconclusive(self) -> None:
        report = audit_database(Path(tempfile.mkdtemp()) / "absent.db")
        self.assertIs(report.status, Status.INCONCLUSIVE, report.render())

    def test_database_without_traces_is_inconclusive(self) -> None:
        path = Path(tempfile.mkdtemp()) / "empty.db"
        TraceStore(path)
        report = audit_database(path)
        self.assertIs(report.status, Status.INCONCLUSIVE, report.render())

    def test_empty_trace_table_is_inconclusive(self) -> None:
        """The rule that matters: nothing recorded is not evidence of safety."""
        path = Path(tempfile.mkdtemp()) / "blank.db"
        TraceStore(path)
        import sqlite3

        connection = sqlite3.connect(path)
        assert "trace_events" in {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        connection.close()

        report = audit_database(path)
        self.assertIs(report.status, Status.INCONCLUSIVE, report.render())
        self.assertIn("not evidence", report.render())

    def test_populated_database_reports_actions(self) -> None:
        path = Path(tempfile.mkdtemp()) / "real.db"
        from safety_layer.runtime.session import session

        with session(store=TraceStore(path)) as ctx:
            tool = ctx.tool(
                lambda **kwargs: {"status": "refunded"},
                action="refund",
                risk="destructive",
            )
            approval = ctx.request_approval("refund", {"order_id": "ORD-1"})
            ctx.approve(approval.approval_id, "operator")
            tool(order_id="ORD-1", approval_id=approval.approval_id)

        report = audit_database(path)
        self.assertIsNotNone(report.findings)
        self.assertIn("recorded actions", {f.name for f in report.findings})


class InputHandlingTest(unittest.TestCase):
    def test_no_input_is_inconclusive(self) -> None:
        report = run_check(app=None, db=None)
        self.assertIs(report.status, Status.INCONCLUSIVE)

    def test_report_serializes_to_json(self) -> None:
        payload = scan_code(write_app(BYPASSES_LAYER)).as_dict()
        self.assertEqual(payload["status"], "FAIL")
        json.dumps(payload)


class CommandTest(unittest.TestCase):
    """The command's exit code is what a build reads."""

    def _run(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "safety_layer", "check", *args],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

    def test_bypassing_code_exits_non_zero(self) -> None:
        result = self._run("--app", str(write_app(BYPASSES_LAYER)))
        self.assertEqual(result.returncode, 1, result.stdout)

    def test_correctly_wired_code_exits_zero(self) -> None:
        result = self._run("--app", str(write_app(GUARDED)))
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_empty_database_never_exits_zero(self) -> None:
        path = Path(tempfile.mkdtemp()) / "blank.db"
        TraceStore(path)
        result = self._run("--db", str(path))
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertNotIn("PASS", result.stdout.replace("SCOPE", ""))

    def test_output_states_it_does_not_verify_the_library(self) -> None:
        result = self._run("--app", str(write_app(GUARDED)))
        self.assertIn("does not re-verify the library itself", result.stdout)

    def test_json_format_is_machine_readable(self) -> None:
        result = self._run("--app", str(write_app(BYPASSES_LAYER)), "--format", "json")
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], "FAIL")

    def test_no_input_exits_non_zero_with_usage_hint(self) -> None:
        result = self._run()
        self.assertEqual(result.returncode, 1)
        self.assertIn("--app", result.stdout)


if __name__ == "__main__":
    unittest.main()
