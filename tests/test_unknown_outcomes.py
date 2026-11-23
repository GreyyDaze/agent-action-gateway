"""Which errors release an effect's claim, and which keep it held until settled."""

from __future__ import annotations

import io
import os
import tempfile
import threading
import unittest
import urllib.error
from contextlib import redirect_stdout
from http.client import RemoteDisconnected

from agent_action_gateway import OutcomeUnknown, session
from agent_action_gateway.audit.receipts import outcome_is_unknown
from agent_action_gateway.cli import main
from agent_action_gateway.storage.traces import TraceStore


def _http(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError("https://api.example", code, "x", {}, None)  # type: ignore[arg-type]


class ClassificationTest(unittest.TestCase):
    def test_errors_that_may_have_landed_are_unknown(self) -> None:
        for exc in (
            OutcomeUnknown("no answer"), TimeoutError(), ConnectionResetError(),
            BrokenPipeError(), RemoteDisconnected(), _http(500), _http(503),
            urllib.error.URLError(TimeoutError("timed out")), KeyboardInterrupt(),
        ):
            with self.subTest(exc=repr(exc)):
                self.assertTrue(outcome_is_unknown(exc))

    def test_errors_that_prove_nothing_happened_are_not(self) -> None:
        for exc in (
            ConnectionRefusedError(), _http(400), _http(404), ValueError("bad input"),
            urllib.error.URLError(ConnectionRefusedError()), RuntimeError(),
        ):
            with self.subTest(exc=repr(exc)):
                self.assertFalse(outcome_is_unknown(exc))


class _LibraryCase(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.db = os.path.join(tmp.name, "runtime.db")
        self.calls: list[str] = []

    def attempts(self, errors: list[BaseException], tries: int) -> list[str]:
        """Call the same approved action `tries` times; the first calls raise `errors`."""
        def tool(table: str, intent_key: str = "") -> dict:
            self.calls.append(intent_key)
            if len(self.calls) <= len(errors):
                raise errors[len(self.calls) - 1]
            return {"dropped": table}

        outcomes = []
        with session(store=TraceStore(self.db), environment="prod") as ctx:
            drop = ctx.tool(tool, action="db.drop", risk="destructive")
            for _ in range(tries):
                approval = ctx.request_approval("db.drop", {"table": "t"})
                ctx.approve(approval.approval_id, "alice")
                try:
                    result = drop(table="t", approval_id=approval.approval_id)
                    outcomes.append(f"{result['status']}:{result['decision']}")
                except BaseException as exc:  # noqa: BLE001 - recording what was raised
                    outcomes.append(f"raised:{type(exc).__name__}")
        return outcomes


class LibraryTest(_LibraryCase):
    def test_a_failure_that_did_not_land_can_be_retried_with_the_same_key(self) -> None:
        outcomes = self.attempts([ConnectionRefusedError()], 2)
        self.assertEqual(outcomes, ["raised:ConnectionRefusedError", "allowed:ALLOW"])
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(len(set(self.calls)), 1, "the provider sees one idempotency key")

    def test_an_outcome_that_may_have_landed_is_held(self) -> None:
        for exc in (TimeoutError(), OutcomeUnknown("no answer"), _http(502)):
            with self.subTest(exc=repr(exc)):
                self.calls.clear()
                self.db = self.db + "x"
                outcomes = self.attempts([exc], 2)
                self.assertEqual(outcomes[1], "blocked:DEDUPLICATED")
                self.assertEqual(len(self.calls), 1, "never run twice")

    def test_once_settled_as_done_a_repeat_gets_the_recorded_result(self) -> None:
        self.attempts([TimeoutError()], 1)
        (held,) = TraceStore(self.db).unknown_receipts()
        TraceStore(self.db).mark_done(held.intent_key, "ref-1")
        outcomes = self.attempts([], 1)
        self.assertEqual(outcomes, ["allowed:DEDUPLICATED"])
        self.assertEqual(len(self.calls), 1)

    def test_once_settled_as_failed_a_later_attempt_runs(self) -> None:
        self.attempts([TimeoutError()], 1)
        (held,) = TraceStore(self.db).unknown_receipts()
        TraceStore(self.db).mark_failed(held.intent_key)
        self.assertEqual(self.attempts([], 1), ["allowed:ALLOW"])
        self.assertEqual(len(self.calls), 2)

    def test_a_receipt_resolved_by_reconciliation_counts_as_done(self) -> None:
        self.attempts([TimeoutError()], 1)
        (held,) = TraceStore(self.db).unknown_receipts()
        TraceStore(self.db).mark_resolved(held.intent_key, "ref-2")
        self.assertEqual(self.attempts([], 1), ["allowed:DEDUPLICATED"])


class ReclaimRaceTest(unittest.TestCase):
    def test_only_one_of_many_retries_takes_a_failed_claim(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        store = TraceStore(os.path.join(tmp.name, "r.db"))
        receipt, _ = store.claim_receipt("effect-1", "run", "step", "db.drop", {"t": 1})
        store.mark_failed(receipt.intent_key)
        wins: list[bool] = []
        threads = [
            threading.Thread(target=lambda: wins.append(store.reclaim_failed(receipt.intent_key)))
            for _ in range(8)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(wins.count(True), 1)


class ReceiptsCommandTest(_LibraryCase):
    def run_cli(self, *args: str) -> tuple[int, str]:
        out = io.StringIO()
        with redirect_stdout(out):
            code = main(["receipts", *args, "--db", self.db])
        return code, out.getvalue()

    def test_list_and_settle(self) -> None:
        code, text = self.run_cli("list")
        self.assertEqual(code, 0)
        self.assertIn("No held actions", text)

        self.attempts([TimeoutError()], 1)
        (held,) = TraceStore(self.db).unknown_receipts()
        code, text = self.run_cli("list")
        self.assertIn(held.intent_key, text)

        code, _ = self.run_cli("settle", "--key", held.intent_key)
        self.assertEqual(code, 2, "settle needs --done or --failed")
        code, _ = self.run_cli("settle", "--key", "nope", "--done")
        self.assertEqual(code, 2)
        code, text = self.run_cli("settle", "--key", held.intent_key, "--done", "--ref", "r9")
        self.assertEqual(code, 0)
        self.assertEqual(TraceStore(self.db).unknown_receipts(), [])


if __name__ == "__main__":
    unittest.main()
