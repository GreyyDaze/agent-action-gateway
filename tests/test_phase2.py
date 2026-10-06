import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from safety_layer.locks import ApprovalError, ApprovalStore, RiskRegistry
from safety_layer.mock_provider import MockPaymentProvider
from safety_layer.safety import SafetyBlockedError, check_action
from safety_layer.store import TraceStore


class Phase2LocksTest(unittest.TestCase):
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
            datetime.now(timezone.utc) + timedelta(days=days),
            state,
        )
        return record.approval_id

    def test_unapproved_destructive_is_blocked(self) -> None:
        with self.assertRaises(SafetyBlockedError):
            check_action(self.approvals, self.registry, "refund", {"order_id": "ORD-100", "amount": 400})

    def test_unknown_action_defaults_to_destructive(self) -> None:
        with self.assertRaises(SafetyBlockedError):
            check_action(self.approvals, self.registry, "delete_customer", {"id": "C-1"})

    def test_tampered_payload_is_blocked(self) -> None:
        approval_id = self.approval()
        with self.assertRaises(SafetyBlockedError):
            check_action(
                self.approvals,
                self.registry,
                "refund",
                {"order_id": "ORD-100", "amount": 401},
                approval_id=approval_id,
            )

    def test_expired_approval_is_blocked(self) -> None:
        approval = self.approvals.create(
            "refund",
            {"order_id": "ORD-100", "amount": 400},
            "human-1",
            datetime.now(timezone.utc) + timedelta(seconds=1),
        )
        with self.assertRaises(SafetyBlockedError):
            check_action(
                self.approvals,
                self.registry,
                "refund",
                {"order_id": "ORD-100", "amount": 400},
                approval_id=approval.approval_id,
                current_state=None,
            )

    def test_state_change_invalidates_approval(self) -> None:
        approval_id = self.approval(state={"order_status": "open"})
        with self.assertRaises(SafetyBlockedError):
            check_action(
                self.approvals,
                self.registry,
                "refund",
                {"order_id": "ORD-100", "amount": 400},
                approval_id=approval_id,
                current_state={"order_status": "cancelled"},
            )

    def test_valid_fresh_approval_allows(self) -> None:
        approval_id = self.approval(state={"order_status": "open"})
        self.assertEqual(
            check_action(
                self.approvals,
                self.registry,
                "refund",
                {"order_id": "ORD-100", "amount": 400},
                approval_id=approval_id,
                current_state={"order_status": "open"},
            ),
            "destructive",
        )

    def test_safety_unavailable_fails_closed_for_write_and_destructive(self) -> None:
        self.approvals.available = False
        with self.assertRaises(ApprovalError):
            check_action(
                self.approvals,
                self.registry,
                "update_note",
                {"id": "N-1"},
            )
        with self.assertRaises(ApprovalError):
            check_action(
                self.approvals,
                self.registry,
                "refund",
                {"order_id": "ORD-100"},
            )

    def test_read_still_works_when_safety_service_is_unavailable(self) -> None:
        self.approvals.available = False
        self.assertEqual(
            check_action(
                self.approvals,
                self.registry,
                "lookup_order",
                {"customer": "Ava"},
            ),
            "read",
        )


if __name__ == "__main__":
    unittest.main()
