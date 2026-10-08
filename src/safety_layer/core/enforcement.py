"""The single enforcement pipeline.

Every guarded action, whichever adapter or interface it arrives through, crosses
this function exactly once. That is the whole point: the primitives were correct
but each caller assembled them differently, so enforcement existed without being
on anyone's path.

Ordering is deliberate and load-bearing:

1. risk classification  - fail closed on unknown actions (E3.4)
2. fuse before dispatch - cheap local check, before anything expensive (E2.5)
3. environment          - a staging session must not reach production (R-04)
4. approval             - digest, expiry, single use (E3.5, R-07/08/09)
5. dispatch             - receipt write-before, provider call, write-after
6. result validation    - stop rules applied to what came back (E1.1)
7. evidence             - trace and honest status

Steps 1-4 never call the provider. A failure at any of them means zero side
effects, which is what makes the pipeline safe to fail closed.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from ..evidence.capture import suspicious_flags
from ..evidence.status import honest_status
from ..providers.base import ExternalActionProvider
from ..storage.traces import TraceStore
from .fuses import FuseController, FuseTrippedError
from .locks import ApprovalError, ApprovalStore, RiskRegistry, SafetyBlockedError, authorize
from .receipts import execute_side_effect
from .stop_rules import CrossEnvironmentError, enforce_environment

BLOCKED = "blocked"


@dataclass(frozen=True)
class EnforcementContext:
    """Everything the pipeline needs to authorize and dispatch one action."""

    store: TraceStore
    run_id: str
    action: str
    arguments: dict[str, Any]
    step_id: str

    # dispatch target
    target: str | None = None
    provider: ExternalActionProvider | None = None

    # policy
    registry: ApprovalStore | RiskRegistry | None = None
    approval_store: ApprovalStore | None = None
    approval_id: str | None = None
    current_state: Any | None = None
    now: Any = None

    # environment
    session_environment: str = "prod"
    target_environment: str | None = None

    # budgets
    fuse: FuseController | None = None
    estimated_cost_usd: float = 0.0
    actual_cost_usd: float | None = None
    new_information: bool = False
    state_changed: bool = False
    #: Overrides the risk-derived write classification. The fuse's degraded
    #: mode distinguishes a capped read from a fail-closed write, so a caller
    #: that knows which it is must be able to say so.
    write: bool | None = None

    # result validation
    required_fields: tuple[str, ...] = ()
    high_stakes: bool = False
    batch: bool = False
    cross_check: Any = None

    # observation
    task: str = ""
    step: int = 3
    #: When false, a successful dispatch is returned without a receipt row.
    #: Reserved for read-only probes that have no external side effect.
    records_receipt: bool = True


@dataclass(frozen=True)
class Decision:
    """Outcome of the pipeline. `result` is None whenever status is blocked."""

    status: str
    decision: str
    result: Any = None
    error: str | None = None
    risk: str | None = None
    flags: tuple[str, ...] = field(default_factory=tuple)
    evidence_status: str = "ok"
    provider_ref: str | None = None
    #: Fields the result was missing. An agent can only correct a call if it is
    #: told what was wrong with it.
    missing: tuple[str, ...] = field(default_factory=tuple)
    #: True when the call needs a human decision before it can proceed.
    needs_approval: bool = False
    #: True when the result was empty or contradicted and needs a second source.
    cross_check_required: bool = False
    #: The original refusal, so an adapter that previously raised a specific
    #: exception type keeps raising it. Flattening these would change the
    #: documented contract for every existing caller.
    exc: BaseException | None = None

    @property
    def blocked(self) -> bool:
        return self.status == BLOCKED

    @property
    def intent_key(self) -> str | None:
        """The idempotency key the receipt was written under, when there is one."""
        return self._intent_key

    _intent_key: str | None = None

    def as_dict(self) -> dict[str, Any]:
        """Shape returned to callers, matching the documented guard contract."""
        payload: dict[str, Any] = {
            "status": self.status,
            "decision": self.decision,
            "result": self.result,
            "flags": self.flags,
            "evidence_status": self.evidence_status,
        }
        if self.error is not None:
            payload["error"] = self.error
        if self.risk is not None:
            payload["risk"] = self.risk
        if self.missing:
            payload["missing"] = list(self.missing)
        if self.cross_check_required:
            payload["cross_check_required"] = True
        if self.needs_approval:
            payload["needs_approval"] = True
        return payload


def _trace(ctx: EnforcementContext, event: str, output: Any, status: str) -> None:
    from ..runtime.records import TraceEvent

    ctx.store.append_trace(
        TraceEvent(
            ctx.run_id,
            ctx.step,
            event,
            ctx.task or ctx.action,
            output,
            status,
        )
    )


def enforce(ctx: EnforcementContext) -> Decision:
    """Authorize and dispatch one action. Never raises for a policy refusal."""
    # 1. risk classification - unknown actions default to destructive (E3.4).
    registry = ctx.registry if isinstance(ctx.registry, RiskRegistry) else None
    risk = registry.classify(ctx.action) if registry else "destructive"

    # 2. fuse, before anything expensive is consulted (E2.5).
    if ctx.fuse is not None:
        try:
            ctx.fuse.before_dispatch(
                ctx.action,
                ctx.arguments,
                estimated_cost_usd=ctx.estimated_cost_usd,
                new_information=ctx.new_information,
                state_changed=ctx.state_changed,
                write=(risk != "read") if ctx.write is None else ctx.write,
            )
        except FuseTrippedError as exc:
            _trace(ctx, "enforcement.fuse", str(exc), BLOCKED)
            return Decision(BLOCKED, "FUSE", error=str(exc), risk=risk, exc=exc,
                            evidence_status=honest_status(blocked=True))

    # 3. environment, before authorization or dispatch (R-04).
    try:
        enforce_environment(
            ctx.session_environment,
            ctx.target_environment or ctx.session_environment,
        )
    except CrossEnvironmentError as exc:
        _trace(ctx, "enforcement.environment", str(exc), BLOCKED)
        return Decision(BLOCKED, "ENVIRONMENT", error=str(exc), risk=risk, exc=exc,
                        evidence_status=honest_status(blocked=True))

    # 4. approval, exact payload, single use (E3.5).
    if ctx.approval_store is not None and risk != "read":
        try:
            authorize(
                ctx.approval_store,
                registry or RiskRegistry(),
                ctx.action,
                ctx.arguments,
                approval_id=ctx.approval_id,
                current_state=ctx.current_state,
                now=ctx.now,
            )
        except ApprovalError as refusal:
            # Preserve the exception type callers already catch. The name
            # `refusal` is bound inside the block, which matters because
            # `except ... as x` unbinds x once the block exits.
            blocked = (
                refusal
                if isinstance(refusal, SafetyBlockedError)
                else SafetyBlockedError(str(refusal))
            )
            _trace(ctx, "enforcement.approval", str(blocked), BLOCKED)
            return Decision(
                BLOCKED,
                "APPROVAL",
                error=str(blocked),
                risk=risk,
                # The refusal is actionable: the agent can request an approval.
                needs_approval=ctx.approval_id is None,
                exc=blocked,
                evidence_status=honest_status(blocked=True),
            )

    # 5. dispatch. The provider is unreachable until every check above passes.
    provider_ref: str | None = None
    intent_key: str | None = None
    if ctx.provider is not None and ctx.target is not None and ctx.records_receipt:
        try:
            provider_ref = execute_side_effect(
                ctx.store, ctx.provider, ctx.run_id, ctx.step_id, ctx.arguments, ctx.target
            )
            intent_key = f"{ctx.run_id}:{ctx.step_id}"
        except Exception as exc:
            _trace(ctx, "enforcement.dispatch", str(exc), "failed")
            return Decision(BLOCKED, "DISPATCH", error=str(exc), risk=risk, exc=exc,
                            evidence_status=honest_status(error=True))

    if ctx.fuse is not None and ctx.actual_cost_usd is not None:
        try:
            ctx.fuse.budget.reconcile_cost(ctx.estimated_cost_usd, ctx.actual_cost_usd)
        except FuseTrippedError as exc:
            _trace(ctx, "enforcement.fuse", str(exc), BLOCKED)
            return Decision(BLOCKED, "FUSE", error=str(exc), risk=risk, exc=exc,
                            provider_ref=provider_ref,
                            evidence_status=honest_status(blocked=True))

    # 6/7. evidence. A provider reference is evidence, not a validated result:
    # stop rules apply to data the agent will act on, so a dispatched side
    # effect returns ALLOWED without pretending its result was inspected.
    flags = ("dispatched",) if provider_ref else ()
    _trace(
        ctx,
        "enforcement.decision",
        {"action": ctx.action, "risk": risk, "provider_ref": provider_ref, "flags": list(flags)},
        "completed",
    )
    return Decision(
        "allowed",
        "ALLOW",
        result={"provider_ref": provider_ref} if provider_ref else {},
        risk=risk,
        flags=flags,
        provider_ref=provider_ref,
        _intent_key=intent_key,
        evidence_status=honest_status(suspicious=bool(flags)),
    )


def validate_result(
    store: TraceStore,
    run_id: str,
    task: str,
    result: Mapping[str, Any] | None,
    *,
    required_fields: tuple[str, ...] = (),
    high_stakes: bool = False,
    batch: bool = False,
    cross_check: Any = None,
) -> Decision:
    """Apply stop rules to a tool result (E1.1). No side effect occurs here."""
    from .stop_rules import ResultDecision, StopPolicy

    policy = StopPolicy()
    checked = None
    if not result:
        if cross_check is None:
            outcome: ResultDecision = policy.empty_result(cross_check_performed=False, batch=batch)
        else:
            from .cross_check import perform_cross_check

            checked = perform_cross_check(result or {}, cross_check)
            outcome = policy.cross_check_result(checked, batch=batch)
    else:
        missing = [f for f in required_fields if result.get(f) in (None, "")]
        if missing:
            outcome = policy.partial_result(
                result, missing, missing_critical=high_stakes, batch=batch
            )
        elif high_stakes:
            if cross_check is None:
                outcome = policy.high_stakes_read(second_source_confirmed=False, batch=batch)
            else:
                from .cross_check import perform_cross_check

                checked = perform_cross_check(result, cross_check)
                outcome = policy.high_stakes_read(second_source_confirmed=checked.agrees, batch=batch)
        else:
            outcome = ResultDecision("CONTINUE")

    flags = suspicious_flags(
        empty_result=not bool(result),
        invariant_failed=checked is not None and not checked.agrees,
        cross_check_failed=checked is not None and not checked.agrees,
    )
    from ..runtime.records import TraceEvent

    store.append_trace(
        TraceEvent(
            run_id,
            4,
            "enforcement.result",
            task,
            {"decision": outcome.decision, "flags": list(outcome.flags),
             "evidence_flags": list(flags), "missing": list(outcome.missing)},
            outcome.decision.lower(),
            flags=flags,
        )
    )
    blocked = outcome.decision != "CONTINUE"
    return Decision(
        BLOCKED if blocked else "allowed",
        outcome.decision,
        result=dict(result) if not blocked and result else None,
        flags=tuple(outcome.flags),
        missing=tuple(outcome.missing),
        cross_check_required=outcome.cross_check_required,
        evidence_status=honest_status(blocked=blocked, suspicious=bool(flags)),
    )
