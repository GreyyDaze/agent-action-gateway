from collections.abc import Callable
from typing import Any
from uuid import uuid4

from .gate import evaluate
from .locks import ApprovalStore, RiskRegistry
from .models import TraceEvent
from .provider import RefundProvider
from .receipts import execute_side_effect, resolve_unknown
from .safety import check_action
from .store import TraceStore


def run(agent_fn: Callable[[str], Any], task: str, store: TraceStore | None = None) -> dict[str, Any]:
    """Phase 0-compatible agent shell; the external agent remains outside the layer."""
    trace_store = store or TraceStore()
    run_id = str(uuid4())

    trace_store.append_trace(TraceEvent(run_id, 0, "before", task, None, "started"))
    try:
        output = agent_fn(task)
    except Exception as exc:
        trace_store.append_trace(TraceEvent(run_id, 1, "agent", task, str(exc), "failed"))
        trace_store.append_receipt(run_id, f"RECEIPT run={run_id} status=failed")
        gate = evaluate(run_id, trace_store, score=0.0)
        return {"run_id": run_id, "output": None, "gate": gate, "status": "failed"}

    trace_store.append_trace(TraceEvent(run_id, 1, "agent", task, output, "completed"))
    trace_store.append_trace(TraceEvent(run_id, 2, "after", output, None, "completed"))
    trace_store.append_receipt(run_id, f"RECEIPT run={run_id} status=completed")
    gate = evaluate(run_id, trace_store)
    return {"run_id": run_id, "output": output, "gate": gate, "status": "completed"}


def dispatch_external_action(
    store: TraceStore,
    provider: RefundProvider,
    run_id: str,
    step_id: str,
    arguments: dict[str, Any],
    order_id: str,
    *,
    action: str = "refund",
    registry: RiskRegistry | None = None,
    approval_store: ApprovalStore | None = None,
    approval_id: str | None = None,
    current_state: Any | None = None,
) -> str:
    """Authorize a proposed action, then execute it through the durable receipt boundary."""
    if registry is None or approval_store is None:
        raise RuntimeError("Phase 2 safety policy is required for external action dispatch")
    check_action(
        approval_store,
        registry,
        action,
        arguments,
        approval_id=approval_id,
        current_state=current_state,
    )
    return execute_side_effect(store, provider, run_id, step_id, arguments, order_id)


def recover_external_actions(store: TraceStore, provider: RefundProvider) -> int:
    """Resolve unknown side effects before any retry."""
    return resolve_unknown(store, provider)
