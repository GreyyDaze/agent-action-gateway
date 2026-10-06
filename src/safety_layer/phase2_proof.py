import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .locks import ApprovalStore, RiskRegistry
from .safety import SafetyBlockedError, check_action
from .store import TraceStore


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        store = TraceStore(Path(tmp) / "runtime.db")
        approvals = ApprovalStore(store)
        registry = RiskRegistry()
        registry.register("refund", "destructive")
        executions = 0
        attacks = 0

        cases = [
            ("no approval", None, {"order_id": "ORD-100", "amount": 400}, None),
            ("unknown action", None, {"id": "C-1"}, None),
        ]
        for _, approval_id, arguments, state in cases:
            attacks += 1
            try:
                check_action(approvals, registry, "refund", arguments, approval_id=approval_id, current_state=state)
                executions += 1
            except SafetyBlockedError:
                pass

        approval = approvals.create(
            "refund",
            {"order_id": "ORD-100", "amount": 400},
            "human-1",
            datetime.now(timezone.utc) - timedelta(days=2),
        )
        attacks += 1
        try:
            check_action(
                approvals,
                registry,
                "refund",
                {"order_id": "ORD-100", "amount": 400},
                approval_id=approval.approval_id,
            )
            executions += 1
        except SafetyBlockedError:
            pass

        approval = approvals.create(
            "refund",
            {"order_id": "ORD-100", "amount": 400},
            "human-1",
            datetime.now(timezone.utc) + timedelta(days=1),
        )
        attacks += 1
        try:
            check_action(
                approvals,
                registry,
                "refund",
                {"order_id": "ORD-100", "amount": 401},
                approval_id=approval.approval_id,
            )
            executions += 1
        except SafetyBlockedError:
            pass

        approval = approvals.create(
            "refund",
            {"order_id": "ORD-100", "amount": 400},
            "human-1",
            datetime.now(timezone.utc) + timedelta(days=1),
            {"order_status": "open"},
        )
        attacks += 1
        try:
            check_action(
                approvals,
                registry,
                "refund",
                {"order_id": "ORD-100", "amount": 400},
                approval_id=approval.approval_id,
                current_state={"order_status": "cancelled"},
            )
            executions += 1
        except SafetyBlockedError:
            pass

        approvals.available = False
        for action, arguments in [
            ("refund", {"order_id": "ORD-100"}),
            ("update_note", {"id": "N-1"}),
        ]:
            attacks += 1
            try:
                check_action(approvals, registry, action, arguments)
                executions += 1
            except Exception:
                pass

        print(f"P2: {executions} destructive executions / {attacks} attack cases")


if __name__ == "__main__":
    main()
