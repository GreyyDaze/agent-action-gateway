import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from safety_layer.core.locks import ApprovalStore, RiskRegistry
from safety_layer.core.safety import SafetyBlockedError, check_action
from safety_layer.providers.mock import MockPaymentProvider
from safety_layer.runtime.orchestrator import dispatch_external_action
from safety_layer.storage.traces import TraceStore


class ApprovalLockTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = TraceStore(Path(self.tmp.name) / "runtime.db")
        self.approvals = ApprovalStore(self.store)
        self.registry = RiskRegistry()
        self.registry.register("refund", "destructive")
        self.registry.register("lookup_order", "read")
        self.registry.register("update_note", "write")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def approval(self, *, days: int = 1, state: object | None = None) -> str:
        record = self.approvals.create(
            "refund",
            {"order_id": "ORD-100", "amount": 400},
            "human-1",
            datetime.now(UTC) + timedelta(days=days),
            state,
        )
        return record.approval_id

    def test_approval_request_starts_pending_with_exact_raw_payload(self) -> None:
        record = self.approvals.request(
            "refund",
            {"order_id": "ORD-100", "amount": 400},
            datetime.now(UTC) + timedelta(days=1),
        )
        self.assertEqual(record.decision, "pending")
        self.assertEqual(record.arguments, {"order_id": "ORD-100", "amount": 400})
        self.assertIsNone(record.approver)

    def test_pending_approval_cannot_execute_before_human_approval(self) -> None:
        record = self.approvals.request(
            "refund",
            {"order_id": "ORD-100", "amount": 400},
            datetime.now(UTC) + timedelta(days=1),
        )
        with self.assertRaises(SafetyBlockedError):
            check_action(
                self.approvals,
                self.registry,
                "refund",
                record.arguments,
                approval_id=record.approval_id,
            )

    def test_human_approval_enables_exact_action(self) -> None:
        record = self.approvals.request(
            "refund",
            {"order_id": "ORD-100", "amount": 400},
            datetime.now(UTC) + timedelta(days=1),
        )
        approved = self.approvals.approve(record.approval_id, "human-1")
        self.assertEqual(approved.decision, "approved")
        self.assertEqual(approved.approver, "human-1")
        self.assertEqual(
            check_action(
                self.approvals,
                self.registry,
                "refund",
                record.arguments,
                approval_id=record.approval_id,
            ),
            "destructive",
        )

    def test_human_denial_blocks_action(self) -> None:
        record = self.approvals.request(
            "refund",
            {"order_id": "ORD-100", "amount": 400},
            datetime.now(UTC) + timedelta(days=1),
        )
        self.approvals.deny(record.approval_id, "human-1")
        with self.assertRaises(SafetyBlockedError):
            check_action(
                self.approvals,
                self.registry,
                "refund",
                record.arguments,
                approval_id=record.approval_id,
            )

    def test_unapproved_destructive_is_blocked(self) -> None:
        provider = MockPaymentProvider(dedupe=True)
        with self.assertRaises(SafetyBlockedError):
            dispatch_external_action(
                self.store, provider, "run-1", "step-1",
                {"order_id": "ORD-100", "amount": 400}, "ORD-100",
                registry=self.registry, approval_store=self.approvals,
            )
        self.assertEqual(len(provider.refunds), 0)

    def test_unknown_action_defaults_to_destructive(self) -> None:
        with self.assertRaises(SafetyBlockedError):
            check_action(self.approvals, self.registry, "delete_customer", {"id": "C-1"})

    def test_tampered_payload_is_blocked(self) -> None:
        approval_id = self.approval()
        with self.assertRaises(SafetyBlockedError):
            check_action(
                self.approvals, self.registry, "refund",
                {"order_id": "ORD-100", "amount": 401},
                approval_id=approval_id,
            )

    def test_expired_approval_is_blocked(self) -> None:
        approval_id = self.approval()
        with self.assertRaises(SafetyBlockedError):
            check_action(
                self.approvals, self.registry, "refund",
                {"order_id": "ORD-100", "amount": 400},
                approval_id=approval_id,
                now=datetime.now(UTC) + timedelta(days=2),
            )

    def test_state_change_invalidates_approval(self) -> None:
        approval_id = self.approval(state={"order_status": "open"})
        with self.assertRaises(SafetyBlockedError):
            check_action(
                self.approvals, self.registry, "refund",
                {"order_id": "ORD-100", "amount": 400},
                approval_id=approval_id,
                current_state={"order_status": "cancelled"},
            )

    def test_valid_fresh_approval_allows_external_action(self) -> None:
        approval_id = self.approval(state={"order_status": "open"})
        provider = MockPaymentProvider(dedupe=True)
        result = dispatch_external_action(
            self.store, provider, "run-1", "step-1",
            {"order_id": "ORD-100", "amount": 400}, "ORD-100",
            registry=self.registry, approval_store=self.approvals,
            approval_id=approval_id, current_state={"order_status": "open"},
        )
        self.assertEqual(len(provider.refunds), 1)
        self.assertTrue(result.startswith("mock-"))

    def test_approval_is_single_use(self) -> None:
        approval_id = self.approval()
        check_action(
            self.approvals, self.registry, "refund",
            {"order_id": "ORD-100", "amount": 400},
            approval_id=approval_id,
        )
        with self.assertRaises(SafetyBlockedError):
            check_action(
                self.approvals, self.registry, "refund",
                {"order_id": "ORD-100", "amount": 400},
                approval_id=approval_id,
            )

    def test_safety_unavailable_fails_closed_for_write_and_destructive(self) -> None:
        self.approvals.available = False
        with self.assertRaises(SafetyBlockedError):
            check_action(self.approvals, self.registry, "update_note", {"id": "N-1"})
        with self.assertRaises(SafetyBlockedError):
            check_action(self.approvals, self.registry, "refund", {"order_id": "ORD-100"})

    def test_read_still_works_when_safety_service_is_unavailable(self) -> None:
        self.approvals.available = False
        self.assertEqual(
            check_action(self.approvals, self.registry, "lookup_order", {"customer": "Ava"}),
            "read",
        )


if __name__ == "__main__":
    unittest.main()
