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
        registry.register("update_note", "write")

        destructive_executions = 0
        attacks = 0

        attack_cases = [
            ("no approval", {"order_id": "ORD-100", "amount": 400}, None, None),
            ("expired", {"order_id": "ORD-100", "amount": 400}, "expired", None),
            ("tampered", {"order_id": "ORD-100", "amount": 401}, "tampered", None),
            ("stale state", {"order_id": "ORD-100", "amount": 400}, "stale", {"order_status": "cancelled"}),
        ]

        for name, arguments, mode, current_state in attack_cases:
            attacks += 1
            approval_id = None
            if mode == "expired":
                approval_id = approvals.create(
                    "refund", {"order_id": "ORD-100", "amount": 400}, "human-1",
                    datetime.now(timezone.utc) - timedelta(days=2),
                ).approval_id
            elif mode == "tampered":
                approval_id = approvals.create(
                    "refund", {"order_id": "ORD-100", "amount": 400}, "human-1",
                    datetime.now(timezone.utc) + timedelta(days=1),
                ).approval_id
            elif mode == "stale":
                approval_id = approvals.create(
                    "refund", {"order_id": "ORD-100", "amount": 400}, "human-1",
                    datetime.now(timezone.utc) + timedelta(days=1),
                    {"order_status": "open"},
                ).approval_id

            try:
                check_action(
                    approvals, registry, "refund", arguments,
                    approval_id=approval_id, current_state=current_state,
                )
                destructive_executions += 1
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
                if action == "refund":
                    destructive_executions += 1
            except SafetyBlockedError:
                pass

        print(f"P2: {destructive_executions} destructive executions / {attacks} attack cases")


if __name__ == "__main__":
    main()
