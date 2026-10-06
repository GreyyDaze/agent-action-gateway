from typing import Any

from .locks import ApprovalError, ApprovalStore, RiskRegistry, authorize


class SafetyBlockedError(RuntimeError):
    pass


def check_action(
    approval_store: ApprovalStore,
    registry: RiskRegistry,
    action: str,
    arguments: dict[str, Any],
    *,
    approval_id: str | None = None,
    current_state: Any | None = None,
) -> str:
    try:
        return authorize(
            approval_store,
            registry,
            action,
            arguments,
            approval_id=approval_id,
            current_state=current_state,
        )
    except Exception as exc:
        raise SafetyBlockedError(str(exc)) from exc
