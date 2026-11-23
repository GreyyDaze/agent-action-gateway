"""Verification that approvals cannot be reused or altered."""
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from agent_action_gateway.policy.locks import ApprovalStore, RiskRegistry
from agent_action_gateway.policy.safety import SafetyBlockedError
from agent_action_gateway.proofs.fakes import MockEffectProvider
from agent_action_gateway.runtime.orchestrator import dispatch_external_action
from agent_action_gateway.storage.traces import TraceStore


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        store = TraceStore(Path(tmp) / "runtime.db")
        approvals = ApprovalStore(store)
        registry = RiskRegistry()
        registry.register("rollback", "destructive")
        provider = MockEffectProvider(dedupe=True)

        destructive_executions = 0
        attacks = 0

        attack_cases = [
            ("no approval", {"deployment_id": "DEP-100", "revision": 400}, None, None),
            ("expired", {"deployment_id": "DEP-100", "revision": 400}, "expired", None),
            ("tampered", {"deployment_id": "DEP-100", "revision": 401}, "tampered", None),
            ("stale state", {"deployment_id": "DEP-100", "revision": 400}, "stale", {"deployment_status": "cancelled"}),
        ]

        for _, arguments, mode, current_state in attack_cases:
            attacks += 1
            approval_id = None
            if mode == "expired" or mode == "tampered":
                approval_id = approvals.create(
                    "rollback", {"deployment_id": "DEP-100", "revision": 400}, "human-1",
                    datetime.now(UTC) + timedelta(days=1),
                ).approval_id
            elif mode == "stale":
                approval_id = approvals.create(
                    "rollback", {"deployment_id": "DEP-100", "revision": 400}, "human-1",
                    datetime.now(UTC) + timedelta(days=1),
                    {"deployment_status": "open"},
                ).approval_id

            try:
                dispatch_external_action(
                    store, provider, "attack-run", f"attack-{attacks}",
                    arguments, "DEP-100",
                    action="rollback",
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
                {"deployment_id": "DEP-100"}, "DEP-100",
                action="rollback",
                registry=registry, approval_store=approvals,
            )
            destructive_executions += 1
        except SafetyBlockedError:
            pass

        print(f"APPROVAL SAFETY: {destructive_executions} destructive executions / {attacks} attack cases")


if __name__ == "__main__":
    main()
