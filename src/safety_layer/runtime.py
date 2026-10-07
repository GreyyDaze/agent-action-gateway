from collections.abc import Callable, Mapping
from datetime import datetime
from typing import Any
from uuid import uuid4

from .cross_check import CrossCheckSpec, perform_cross_check
from .fuses import FuseController, FuseTrippedError
from .gate import evaluate
from .locks import ApprovalStore, RiskRegistry
from .models import TraceEvent
from .provider import RefundProvider
from .receipts import execute_side_effect, resolve_unknown
from .safety import check_action
from .stop_rules import (
    AmbiguityBlockedError,
    ClarificationState,
    ResultDecision,
    StopPolicy,
    enforce_environment,
    validate_required_input,
)
from .store import TraceStore


def run(
    agent_fn: Callable[[str], Any],
    task: str,
    store: TraceStore | None = None,
    *,
    run_id: str | None = None,
    clarification_state: ClarificationState | None = None,
    required_inputs: dict[str, Any] | None = None,
    batch: bool = False,
    new_turn: bool = False,
    fuse: FuseController | None = None,
) -> dict[str, Any]:
    """Run the agent with durable Phase 4 clarification state."""
    trace_store = store or TraceStore()
    active_run_id = run_id or str(uuid4())
    stop_policy = StopPolicy()

    if clarification_state is None:
        persisted = trace_store.load_clarification_state(active_run_id)
        if persisted is None:
            clarification_state = ClarificationState()
        else:
            clarification_state = ClarificationState(
                attempts=persisted["attempts"],
                max_attempts=persisted["max_attempts"],
                asked_this_turn=persisted["asked_this_turn"],
            )

    if new_turn:
        clarification_state.next_turn()

    if required_inputs is not None:
        try:
            proposal = validate_required_input(
                stop_policy, clarification_state, required_inputs, batch=batch
            )
        except AmbiguityBlockedError as exc:
            trace_store.save_clarification_state(active_run_id, clarification_state)
            trace_store.append_trace(
                TraceEvent(active_run_id, 0, "phase4", task, str(exc), "blocked")
            )
            return {
                "run_id": active_run_id,
                "output": None,
                "status": "blocked",
                "reason": str(exc),
                "attempt": clarification_state.attempts,
            }

        trace_store.save_clarification_state(active_run_id, clarification_state)

        if proposal.decision == "ASK":
            trace_store.append_trace(
                TraceEvent(active_run_id, 0, "phase4", task, proposal.missing_fields, "ask")
            )
            return {
                "run_id": active_run_id,
                "output": None,
                "status": "needs_clarification",
                "missing_fields": proposal.missing_fields,
                "attempt": clarification_state.attempts,
            }

    trace_store.append_trace(TraceEvent(active_run_id, 0, "before", task, None, "started"))
    if fuse is not None:
        try:
            fuse.budget.check()
        except FuseTrippedError as exc:
            trace_store.append_trace(
                TraceEvent(active_run_id, 0, "phase5.fuse", task, str(exc), "blocked")
            )
            return {
                "run_id": active_run_id,
                "output": None,
                "status": "blocked",
                "reason": str(exc),
                "attempt": clarification_state.attempts,
            }
    try:
        if fuse is None:
            output = agent_fn(task)
        else:
            with fuse.deadline_guard():
                output = agent_fn(task)
    except FuseTrippedError as exc:
        trace_store.append_trace(TraceEvent(active_run_id, 1, "phase5.fuse", task, str(exc), "blocked"))
        return {
            "run_id": active_run_id,
            "output": None,
            "status": "blocked",
            "reason": str(exc),
            "attempt": clarification_state.attempts,
        }
    except Exception as exc:
        trace_store.append_trace(TraceEvent(active_run_id, 1, "agent", task, str(exc), "failed"))
        trace_store.append_receipt(active_run_id, f"RECEIPT run={active_run_id} status=failed")
        gate = evaluate(active_run_id, trace_store, score=0.0)
        return {
            "run_id": active_run_id,
            "output": None,
            "gate": gate,
            "status": "failed",
            "attempt": clarification_state.attempts,
        }

    trace_store.append_trace(TraceEvent(active_run_id, 1, "agent", task, output, "completed"))
    trace_store.append_trace(TraceEvent(active_run_id, 2, "after", output, None, "completed"))
    trace_store.append_receipt(active_run_id, f"RECEIPT run={active_run_id} status=completed")
    gate = evaluate(active_run_id, trace_store)
    return {
        "run_id": active_run_id,
        "output": output,
        "gate": gate,
        "status": "degraded" if fuse is not None and fuse.degraded else "completed",
        "attempt": clarification_state.attempts,
    }

def evaluate_tool_result(
    store: TraceStore,
    run_id: str,
    task: str,
    result: Mapping[str, Any],
    *,
    required_fields: tuple[str, ...] = (),
    high_stakes: bool = False,
    batch: bool = False,
    cross_check: CrossCheckSpec | None = None,
) -> ResultDecision:
    """Apply Phase 4 policy to the result returned by a real tool."""
    policy = StopPolicy()
    checked = None

    if not result:
        if cross_check is None:
            decision = policy.empty_result(
                cross_check_performed=False,
                batch=batch,
            )
        else:
            checked = perform_cross_check(result, cross_check)
            decision = policy.cross_check_result(checked, batch=batch)
    else:
        missing = [
            field for field in required_fields if result.get(field) in (None, "")
        ]
        if missing:
            decision = policy.partial_result(
                result,
                missing,
                missing_critical=high_stakes,
                batch=batch,
            )
        elif high_stakes:
            if cross_check is None:
                decision = policy.high_stakes_read(
                    second_source_confirmed=False,
                    batch=batch,
                )
            else:
                checked = perform_cross_check(result, cross_check)
                decision = policy.high_stakes_read(
                    second_source_confirmed=checked.agrees,
                    batch=batch,
                )
        else:
            decision = ResultDecision("CONTINUE")

    evidence = {
        "decision": decision.decision,
        "flags": decision.flags,
        "missing": decision.missing,
        "cross_check_required": decision.cross_check_required,
        "cross_check": (
            {
                "first_source": checked.first_source,
                "second_source": checked.second_source,
                "invariant": checked.invariant_name,
                "agrees": checked.agrees,
            }
            if checked is not None
            else None
        ),
    }
    store.append_trace(
        TraceEvent(
            run_id,
            3,
            "phase4.tool_result",
            task,
            evidence,
            decision.decision.lower(),
        )
    )
    return decision



def execute_tool(
    store: TraceStore,
    run_id: str,
    task: str,
    tool_fn: Callable[[], Mapping[str, Any]],
    *,
    required_fields: tuple[str, ...] = (),
    high_stakes: bool = False,
    batch: bool = False,
    cross_check: CrossCheckSpec | None = None,
    fuse: FuseController | None = None,
    action: str | None = None,
    arguments: dict[str, Any] | None = None,
    estimated_cost_usd: float = 0.0,
    actual_cost_usd: float | None = None,
    new_information: bool = False,
    state_changed: bool = False,
    write: bool = False,
) -> dict[str, Any]:
    """Execute one external tool call through the Phase 5 boundary, then apply Phase 4."""
    if fuse is not None:
        try:
            fuse.before_dispatch(
                action or task,
                arguments or {},
                estimated_cost_usd=estimated_cost_usd,
                new_information=new_information,
                state_changed=state_changed,
                write=write,
            )
        except FuseTrippedError as exc:
            store.append_trace(
                TraceEvent(
                    run_id,
                    3,
                    "phase5.fuse",
                    task,
                    str(exc),
                    "blocked",
                )
            )
            return {"status": "blocked", "decision": "FUSE", "result": None, "error": str(exc)}
    try:
        result = tool_fn()
    except Exception as exc:
        store.append_trace(
            TraceEvent(
                run_id,
                3,
                "phase4.tool_result",
                task,
                {"decision": "BLOCK", "flags": ("tool-error",), "error": str(exc)},
                "blocked",
            )
        )
        return {"status": "blocked", "decision": "BLOCK", "result": None, "error": str(exc)}

    if fuse is not None and actual_cost_usd is not None:
        try:
            fuse.budget.reconcile_cost(estimated_cost_usd, actual_cost_usd)
        except FuseTrippedError as exc:
            store.append_trace(
                TraceEvent(run_id, 3, "phase5.fuse", task, str(exc), "blocked")
            )
            return {"status": "blocked", "decision": "FUSE", "result": None, "error": str(exc)}

    decision = evaluate_tool_result(
        store,
        run_id,
        task,
        result,
        required_fields=required_fields,
        high_stakes=high_stakes,
        batch=batch,
        cross_check=cross_check,
    )
    return {
        "status": "allowed" if decision.decision == "CONTINUE" else "stopped",
        "decision": decision.decision,
        "result": result if decision.decision == "CONTINUE" else None,
        "flags": decision.flags,
        "missing": decision.missing,
        "cross_check_required": decision.cross_check_required,
    }

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
    now: datetime | None = None,
    session_environment: str = "prod",
    target_environment: str | None = None,
    fuse: FuseController | None = None,
    estimated_cost_usd: float = 0.0,
    actual_cost_usd: float | None = None,
    new_information: bool = False,
    state_changed: bool = False,
) -> str:
    """Authorize a proposed action, then execute it through the durable receipt boundary."""
    if registry is None or approval_store is None:
        raise RuntimeError("Phase 2 safety policy is required for external action dispatch")
    if fuse is not None:
        fuse.before_dispatch(
            action,
            arguments,
            estimated_cost_usd=estimated_cost_usd,
            new_information=new_information,
            state_changed=state_changed,
            write=True,
        )
    enforce_environment(session_environment, target_environment or session_environment)
    check_action(
        approval_store,
        registry,
        action,
        arguments,
        approval_id=approval_id,
        current_state=current_state,
        now=now,
    )
    result = execute_side_effect(store, provider, run_id, step_id, arguments, order_id)
    if fuse is not None and actual_cost_usd is not None:
        fuse.budget.reconcile_cost(estimated_cost_usd, actual_cost_usd)
    return result


def recover_external_actions(store: TraceStore, provider: RefundProvider) -> int:
    """Resolve unknown side effects before any retry."""
    return resolve_unknown(store, provider)
