"""Starts and stops the pieces that make up a run."""
from collections.abc import Callable, Mapping
from datetime import datetime
from typing import Any
from uuid import uuid4

from ..core.cross_check import CrossCheckSpec, perform_cross_check
from ..core.enforcement import EnforcementContext, enforce
from ..core.fuses import FuseController, FuseTrippedError
from ..core.locks import ApprovalStore, RiskRegistry
from ..core.safety import SafetyBlockedError
from ..core.stop_rules import (
    AmbiguityBlockedError,
    ClarificationState,
    ResultDecision,
    StopPolicy,
    validate_required_input,
)
from ..evaluation.gate import record_run_status
from ..evidence.capture import suspicious_flags
from ..evidence.status import honest_status
from ..providers.base import ExternalActionProvider
from ..storage.traces import TraceStore
from .records import TraceEvent


def _persist_fuse(trace_store: TraceStore, run_id: str, fuse: FuseController | None) -> None:
    if fuse is not None:
        trace_store.record_fuse_snapshot(run_id, fuse.budget.snapshot())


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
    """Run the agent with durable validation clarification state."""
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
                TraceEvent(active_run_id, 0, "validation", task, str(exc), "blocked")
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
                TraceEvent(active_run_id, 0, "validation", task, proposal.missing_fields, "ask")
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
                TraceEvent(active_run_id, 0, "fuse", task, str(exc), "blocked")
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
        trace_store.append_trace(TraceEvent(active_run_id, 1, "fuse", task, str(exc), "blocked"))
        _persist_fuse(trace_store, active_run_id, fuse)
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
        run_status = record_run_status(active_run_id, trace_store, failed=True)
        _persist_fuse(trace_store, active_run_id, fuse)
        return {
            "run_id": active_run_id,
            "output": None,
            "run_status": run_status.verdict,
            "status": "failed",
            "enforcement": "observe",
            "attempt": clarification_state.attempts,
        }

    trace_store.append_trace(TraceEvent(active_run_id, 1, "agent", task, output, "completed"))
    trace_store.append_trace(TraceEvent(active_run_id, 2, "after", output, None, "completed"))
    trace_store.append_receipt(active_run_id, f"RECEIPT run={active_run_id} status=completed")
    run_status = record_run_status(active_run_id, trace_store, failed=False)
    _persist_fuse(trace_store, active_run_id, fuse)
    return {
        "run_id": active_run_id,
        "output": output,
        "run_status": run_status.verdict,
        "status": "degraded" if fuse is not None and fuse.degraded else "completed",
        "enforcement": "observe",
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
    """Apply validation policy to the result returned by a real tool."""
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

    evidence_flags = suspicious_flags(
        empty_result=not bool(result),
        invariant_failed=checked is not None and not checked.agrees,
        cross_check_failed=checked is not None and not checked.agrees,
    )
    evidence = {
        "decision": decision.decision,
        "flags": decision.flags,
        "evidence_suspicious_flags": evidence_flags,
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
            "tool.result",
            task,
            evidence,
            decision.decision.lower(),
            flags=evidence_flags,
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
    step_id: str | None = None,
    registry: RiskRegistry | None = None,
    approval_store: ApprovalStore | None = None,
    approval_id: str | None = None,
    session_environment: str = "prod",
    target_environment: str | None = None,
    arguments: dict[str, Any] | None = None,
    estimated_cost_usd: float = 0.0,
    actual_cost_usd: float | None = None,
    new_information: bool = False,
    state_changed: bool = False,
    write: bool = False,
) -> dict[str, Any]:
    """Execute one external tool call through the shared pipeline, then validate.

    Pre-dispatch checks go through `enforce` so this path cannot drift from the
    guarded one. Read-only calls carry no provider, so no receipt is written.
    """
    if fuse is not None:
        decision = enforce(
            EnforcementContext(
                store=store,
                run_id=run_id,
                action=action or task,
                arguments=arguments or {},
                step_id=step_id or (action or task),
                registry=registry,
                approval_store=approval_store,
                approval_id=approval_id,
                session_environment=session_environment,
                target_environment=target_environment,
                fuse=fuse,
                estimated_cost_usd=estimated_cost_usd,
                new_information=new_information,
                state_changed=state_changed,
                write=write,
                records_receipt=False,
                task=task,
            )
        )
        if decision.blocked:
            return {
                "status": "blocked",
                "decision": decision.decision,
                "result": None,
                "error": decision.error,
            }
    try:
        result = tool_fn()
    except Exception as exc:
        store.append_trace(
            TraceEvent(
                run_id,
                3,
                "tool.result",
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
                TraceEvent(run_id, 3, "fuse", task, str(exc), "blocked")
            )
            return {"status": "blocked", "decision": "FUSE", "result": None, "error": str(exc)}

    result_decision = evaluate_tool_result(
        store,
        run_id,
        task,
        result,
        required_fields=required_fields,
        high_stakes=high_stakes,
        batch=batch,
        cross_check=cross_check,
    )
    trace_flags = suspicious_flags(empty_result=not bool(result))
    evidence_status = honest_status(
        blocked=result_decision.decision != "CONTINUE",
        suspicious=bool(trace_flags),
    )
    # Preserve the validation/5 public status contract. observability evidence is
    # exposed separately so observability does not silently change behavior.
    status = "allowed" if result_decision.decision == "CONTINUE" else "stopped"
    return {
        "status": status,
        "evidence_status": evidence_status,
        "decision": result_decision.decision,
        "result": result if result_decision.decision == "CONTINUE" else None,
        "flags": result_decision.flags,
        "evidence_suspicious_flags": trace_flags,
        "missing": result_decision.missing,
        "cross_check_required": result_decision.cross_check_required,
    }


def dispatch_external_action(
    store: TraceStore,
    provider: ExternalActionProvider,
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
    """Authorize a proposed action, then execute it through the shared pipeline.

    A thin adapter: the ordering lives in core.enforcement.enforce so every
    caller, guarded or not, crosses the same checks in the same sequence.
    """
    if registry is None or approval_store is None:
        raise RuntimeError("approval safety policy is required for external action dispatch")
    decision = enforce(
        EnforcementContext(
            store=store,
            run_id=run_id,
            action=action,
            arguments=arguments,
            step_id=step_id,
            target=order_id,
            provider=provider,
            registry=registry,
            approval_store=approval_store,
            approval_id=approval_id,
            current_state=current_state,
            now=now,
            session_environment=session_environment,
            target_environment=target_environment,
            fuse=fuse,
            estimated_cost_usd=estimated_cost_usd,
            actual_cost_usd=actual_cost_usd,
            new_information=new_information,
            state_changed=state_changed,
            task=action,
        )
    )
    if decision.blocked:
        # Re-raise the original refusal so existing callers keep catching the
        # exception type they were written against.
        raise decision.exc or SafetyBlockedError(decision.error or decision.decision)
    return decision.provider_ref or ""

