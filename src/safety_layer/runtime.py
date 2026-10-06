from collections.abc import Callable
from typing import Any
from uuid import uuid4

from .gate import evaluate
from .models import TraceEvent
from .store import TraceStore


def run(agent_fn: Callable[[str], Any], task: str, store: TraceStore | None = None) -> dict[str, Any]:
    """Run an agent through the Phase 0 safety-layer shell.

    Guards are intentionally thin in Phase 0. The wrapper makes the lifecycle
    visible without pretending that the later safety controls already exist.
    """
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
