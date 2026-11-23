"""Guarded-path durability.

The Phase 1 chaos proof exercises `dispatch_external_action` directly. This
file proves the adopter-facing path - a guarded tool obtained from a session -
survives the same crashes without duplicating a side effect.

If this ever fails, the adoption path has diverged from the proven one, which
is the exact failure this feature exists to prevent.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from agent_action_gateway import session
from agent_action_gateway.audit.receipts import UnresolvableReceiptError, resolve_unknown
from agent_action_gateway.integrations.adapters.mock import MockPaymentProvider
from agent_action_gateway.policy.fuses import FuseLimits
from agent_action_gateway.storage.traces import TraceStore


class GuardedReceiptTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.db = Path(self._tmp.name) / "runtime.db"
        self.store = TraceStore(self.db)
        self.provider = MockPaymentProvider(dedupe=True)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _guarded_refund(self, ctx):
        return ctx.tool(
            lambda order_id, intent_key: self.provider.execute(order_id, intent_key),
            action="refund",
            risk="destructive",
            provider=self.provider,
            target="ORD-100",
        )

    def test_approved_guarded_action_writes_a_real_receipt(self) -> None:
        """Not a string line: a row with a lifecycle state and an intent key."""
        with session(store=self.store) as ctx:
            approval = ctx.request_approval("refund", {"order_id": "ORD-100"})
            ctx.approve(approval.approval_id, "operator")
            refund = self._guarded_refund(ctx)
            outcome = refund(order_id="ORD-100", approval_id=approval.approval_id)

        self.assertEqual(outcome["status"], "allowed")
        receipts = self.store.snapshot()["receipts"]
        self.assertEqual(len(receipts), 1)
        receipt = receipts[0]
        self.assertEqual(receipt["state"], "done")
        self.assertTrue(receipt["intent_key"])
        self.assertNotEqual(receipt["action"], "legacy")

    def test_refused_action_writes_no_receipt(self) -> None:
        """A blocked call must not look like a completed one."""
        with session(store=self.store) as ctx:
            refund = self._guarded_refund(ctx)
            refund(order_id="ORD-100")

        self.assertEqual(self.store.snapshot()["receipts"], [])
        self.assertEqual(len(self.provider.refunds), 0)

    def test_crash_before_write_after_does_not_duplicate(self) -> None:
        """The Phase 1 invariant, proven on the adoption path."""
        with session(store=self.store) as ctx:
            approval = ctx.request_approval("refund", {"order_id": "ORD-100"})
            ctx.approve(approval.approval_id, "operator")
            refund = self._guarded_refund(ctx)
            refund(order_id="ORD-100", approval_id=approval.approval_id)

        # Simulate the crash window: dispatched, but the local record never
        # advanced past `unknown`.
        with self.store.connection() as connection:
            connection.execute(
                "UPDATE receipts SET state='unknown', provider_ref=NULL"
            )

        resolved = resolve_unknown(self.store, self.provider)
        self.assertEqual(resolved, 1)
        self.assertEqual(self.store.unknown_receipts(), [])
        self.assertEqual(len(self.provider.refunds), 1, "side effect duplicated")

    def test_guarded_chaos_harness_reports_no_duplicates(self) -> None:
        """Crash injection against guarded tools, not the internal path.

        `run_proof` returns (provider_actions, unknown_receipts). One provider
        action per job with nothing left unresolved is the exactly-once result;
        a duplicate would show up as actions > jobs.
        """
        from agent_action_gateway.proofs.chaos import run_proof

        actions, unknown = run_proof(jobs=25)
        self.assertEqual(unknown, 0, "receipts left unresolved")
        self.assertEqual(actions, 25, "duplicate side effects detected")

    def test_receipt_without_a_target_is_manual_not_a_blind_retry(self) -> None:
        self.store.create_receipt(
            "run-x", "step-1", "external_action", {"amount": 400}
        )
        with self.assertRaises(UnresolvableReceiptError):
            resolve_unknown(self.store, self.provider)


class ApprovalSingleUseTest(unittest.TestCase):
    """An approval authorizes one execution, not a repeatable one."""

    def test_approval_cannot_be_replayed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = TraceStore(Path(directory) / "r.db")
            provider = MockPaymentProvider(dedupe=True)
            with session(store=store) as ctx:
                approval = ctx.request_approval("refund", {"order_id": "ORD-1"})
                ctx.approve(approval.approval_id, "operator")
                refund = ctx.tool(
                    lambda order_id, intent_key: provider.execute(order_id, intent_key),
                    action="refund",
                    risk="destructive",
                    provider=provider,
                    target="ORD-1",
                )
                first = refund(order_id="ORD-1", approval_id=approval.approval_id)
                second = refund(order_id="ORD-1", approval_id=approval.approval_id)

            self.assertEqual(first["status"], "allowed")
            self.assertEqual(second["status"], "blocked")
            self.assertIn("used", second["error"].lower())


if __name__ == "__main__":
    unittest.main()


class FuseReportingTest(unittest.TestCase):
    """A refused budget must report itself as refused.

    Found by self-critique: the loop detector refused every call but left the
    snapshot reporting `tripped=False`, so a dashboard would show a healthy
    budget for a run that was already dead.
    """

    def test_loop_trip_is_reported_on_the_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = TraceStore(Path(directory) / "r.db")
            with session(store=store, limits=FuseLimits(max_steps=100, loop_repeat_limit=3)) as ctx:
                tool = ctx.tool(lambda **kw: {"ok": True}, action="lookup", risk="read")
                outcomes = [tool(customer="Ava") for _ in range(6)]
                snapshot = ctx.fuse.snapshot()

        # The first calls legitimately succeed; the loop is what stops it.
        self.assertEqual(outcomes[0]["status"], "allowed")
        self.assertTrue(any(o["status"] == "blocked" for o in outcomes))
        self.assertTrue(snapshot.tripped)
        self.assertIsNotNone(snapshot.reason)
        self.assertIn("loop", snapshot.reason.lower())

    def test_session_marks_itself_degraded_after_a_trip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = TraceStore(Path(directory) / "r.db")
            with session(store=store, limits=FuseLimits(max_steps=100, loop_repeat_limit=3)) as ctx:
                tool = ctx.tool(lambda **kw: {"ok": True}, action="lookup", risk="read")
                for _ in range(6):
                    tool(customer="Ava")
                self.assertTrue(ctx.fuse.snapshot().tripped)
