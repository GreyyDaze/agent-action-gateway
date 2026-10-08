import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from ..core.locks import ApprovalStore, RiskRegistry
from ..core.safety import SafetyBlockedError
from ..providers.mock import MockPaymentProvider
from ..runtime.orchestrator import dispatch_external_action
from ..storage.traces import TraceStore


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        store = TraceStore(Path(tmp) / "runtime.db")
        approvals = ApprovalStore(store)
        registry = RiskRegistry()
        registry.register("refund", "destructive")
        provider = MockPaymentProvider(dedupe=True)

        destructive_executions = 0
        attacks = 0

        attack_cases = [
            ("no approval", {"order_id": "ORD-100", "amount": 400}, None, None),
            ("expired", {"order_id": "ORD-100", "amount": 400}, "expired", None),
            ("tampered", {"order_id": "ORD-100", "amount": 401}, "tampered", None),
            ("stale state", {"order_id": "ORD-100", "amount": 400}, "stale", {"order_status": "cancelled"}),
        ]

        for _, arguments, mode, current_state in attack_cases:
            attacks += 1
            approval_id = None
            if mode == "expired" or mode == "tampered":
                approval_id = approvals.create(
                    "refund", {"order_id": "ORD-100", "amount": 400}, "human-1",
                    datetime.now(UTC) + timedelta(days=1),
                ).approval_id
            elif mode == "stale":
                approval_id = approvals.create(
                    "refund", {"order_id": "ORD-100", "amount": 400}, "human-1",
                    datetime.now(UTC) + timedelta(days=1),
                    {"order_status": "open"},
                ).approval_id

            try:
                dispatch_external_action(
                    store, provider, "attack-run", f"attack-{attacks}",
                    arguments, "ORD-100",
                    registry=registry, approval_store=approvals,
                    approval_id=approval_id, current_state=current_state,
                    now=datetime.now(UTC) + timedelta(days=2) if mode == "expired" else None,
                )
                destructive_executions += 1
            except SafetyBlockedError:
                pass

        approvals.available = False
        attacks += 1
        try:
            dispatch_external_action(
                store, provider, "attack-run", f"attack-{attacks}",
                {"order_id": "ORD-100"}, "ORD-100",
                registry=registry, approval_store=approvals,
            )
            destructive_executions += 1
        except SafetyBlockedError:
            pass

        print(f"P2: {destructive_executions} destructive executions / {attacks} attack cases")


if __name__ == "__main__":
    main()
