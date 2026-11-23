"""A write needs approval like a destructive action. Retries of a `ctx.tool` tool
are capped at the loop limit and do not stop the run."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from agent_action_gateway import session
from agent_action_gateway.storage.traces import TraceStore


class _TempStore(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.db = Path(tmp.name) / "runtime.db"

    def store(self) -> TraceStore:
        return TraceStore(self.db)


class WriteNeedsApprovalTest(_TempStore):
    def setUp(self) -> None:
        super().setUp()
        self.calls: list[str] = []

    def note(self, text: str, intent_key: str = "") -> dict:
        self.calls.append(text)
        return {"ok": True}

    def test_write_without_approval_is_blocked(self) -> None:
        with session(environment="prod", store=self.store()) as ctx:
            write = ctx.tool(self.note, action="note.write", risk="write")
            result = write(text="hi")
        self.assertEqual(result["status"], "blocked")
        self.assertTrue(result["needs_approval"])
        self.assertEqual(self.calls, [])

    def test_write_runs_with_an_exact_approval(self) -> None:
        with session(environment="prod", store=self.store()) as ctx:
            write = ctx.tool(self.note, action="note.write", risk="write")
            approval = ctx.request_approval("note.write", {"text": "hi"})
            ctx.approve(approval.approval_id, "reviewer")
            other = write(text="bye", approval_id=approval.approval_id)
            allowed = write(text="hi", approval_id=approval.approval_id)
        self.assertEqual(other["status"], "blocked")
        self.assertEqual(allowed["status"], "allowed")
        self.assertEqual(allowed["risk"], "write")  # asking for approval keeps the risk
        self.assertEqual(self.calls, ["hi"])

    def test_write_can_opt_out_explicitly(self) -> None:
        with session(environment="prod", store=self.store()) as ctx:
            write = ctx.tool(
                self.note, action="note.write", risk="write", requires_approval=False
            )
            result = write(text="hi")
        self.assertEqual(result["status"], "allowed")
        self.assertEqual(self.calls, ["hi"])


class RetryIsNotALoopTest(_TempStore):
    def test_bounded_retries_of_a_read_do_not_stop_the_run(self) -> None:
        calls: list[int] = []

        def status(name: str) -> dict:
            calls.append(1)
            return {"status_code": 503}

        with session(environment="prod", store=self.store()) as ctx:
            read = ctx.tool(status, action="svc.status", risk="read")
            result = ctx.retrying(read, attempts=4)(name="api")
            after = read(name="other")
        self.assertEqual(result, {"status_code": 503})
        self.assertEqual(len(calls), 4)  # capped at the loop limit (3), then one more call
        self.assertEqual(after["status"], "allowed")

    def test_plain_repeats_are_still_caught(self) -> None:
        def status(name: str) -> dict:
            return {"ok": True}

        with session(environment="prod", store=self.store()) as ctx:
            read = ctx.tool(status, action="svc.status", risk="read")
            results = [read(name="api")["status"] for _ in range(4)]
        self.assertIn("blocked", results)

    def test_a_write_retry_is_refused_not_run_twice(self) -> None:
        calls: list[int] = []

        def restart(name: str, intent_key: str = "") -> dict:
            calls.append(1)
            return {"status_code": 503}

        with session(environment="prod", store=self.store()) as ctx:
            tool = ctx.tool(restart, action="svc.restart", risk="write")
            approval = ctx.request_approval("svc.restart", {"name": "api"})
            ctx.approve(approval.approval_id, "reviewer")
            result = ctx.retrying(tool, attempts=3)(
                name="api", approval_id=approval.approval_id
            )
        self.assertEqual(len(calls), 1)
        self.assertEqual(result["status"], "blocked")


if __name__ == "__main__":
    unittest.main()
