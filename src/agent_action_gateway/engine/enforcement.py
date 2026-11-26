"""The single enforcement pipeline.

Every guarded action, whichever adapter or interface it arrives through, crosses
this function exactly once.

Ordering is deliberate and load-bearing:

1. risk classification  - an action with no declared risk is destructive
2. budgets              - checked before anything expensive happens
3. environment          - a non-production session must not reach production
4. approval             - bound to exact arguments, expiring, single use
5. dispatch             - receipt write-before, provider call, write-after
6. result validation    - check what came back against the stop rules
7. evidence             - trace and run status

Steps 1-4 never call the provider. A failure at any of them means zero side
effects, which is what makes the pipeline safe to fail closed.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from agent_action_gateway.audit.receipts import (
    TARGET_KEY,
    EffectInFlight,
    claim_effect,
    outcome_is_unknown,
)
from agent_action_gateway.guards.capture import suspicious_flags
from agent_action_gateway.guards.status import run_status
from agent_action_gateway.integrations.adapters.base import ExternalActionProvider
from agent_action_gateway.policy.fuses import FuseController, FuseTrippedError
from agent_action_gateway.policy.locks import (
    ApprovalError,
    ApprovalStore,
    RiskRegistry,
    SafetyBlockedError,
    authorize,
)
from agent_action_gateway.policy.stop_rules import CrossEnvironmentError, enforce_environment
from agent_action_gateway.storage.traces import TraceStore

BLOCKED = "blocked"
ALLOWED = "allowed"


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
    #: Separates otherwise-identical effects across tenants or principals. Empty
    #: means every caller shares one namespace, which silently suppresses the
    #: second of two tenants issuing the same action.
    effect_scope: str = ""
    #: Arguments that define the effect, when not all of them do.
    identity_fields: tuple[str, ...] = ()


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
    #: The original refusal, so an adapter can raise the same exception type
    #: it always has.
    exc: BaseException | None = None

    @property
    def blocked(self) -> bool:
        return self.status == BLOCKED

    @property
    def intent_key(self) -> str | None:
        """The idempotency key the receipt was written under, when there is one."""
        return self._intent_key

    _intent_key: str | None = None
    #: True when the effect had already landed in an earlier attempt, so the
    #: recorded outcome was replayed instead of the action being repeated.
    deduplicated: bool = False

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
    from agent_action_gateway.runtime.records import TraceEvent

    ctx.store.append_trace(
        TraceEvent(
            ctx.run_id,
            ctx.step,
            event,
            ctx.task or ctx.action,
            output,
            status,
        ),
            enforcement="enforced",
    )


def enforce(ctx: EnforcementContext) -> Decision:
    """Authorize and dispatch one action. Never raises for a policy refusal."""
    # 1. Risk classification: an undeclared action is treated as destructive.
    registry = ctx.registry if isinstance(ctx.registry, RiskRegistry) else None
    risk = registry.classify(ctx.action) if registry else "destructive"

    # 2. Budgets, before anything expensive is consulted.
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
                            evidence_status=run_status(blocked=True))

    # 3. Environment, before authorization or dispatch.
    try:
        enforce_environment(
            ctx.session_environment,
            ctx.target_environment or ctx.session_environment,
        )
    except CrossEnvironmentError as exc:
        _trace(ctx, "enforcement.environment", str(exc), BLOCKED)
        return Decision(BLOCKED, "ENVIRONMENT", error=str(exc), risk=risk, exc=exc,
                        evidence_status=run_status(blocked=True))

    # 4. Approval, bound to exact arguments, consumed on use.
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
                evidence_status=run_status(blocked=True),
            )

    # 5. dispatch. The provider is unreachable until every check above passes.
    provider_ref: str | None = None
    intent_key: str | None = None
    if ctx.records_receipt and risk != "read":
        # The effect is claimed before it is executed, and the claim is keyed on
        # what the action is rather than on which run attempted it. That is what
        # makes a duplicate detectable across a crash, a restart, and a second
        # worker -- none of which share a run_id. Reads have no side effect to
        # deduplicate, so they do not pay for a claim.
        try:
            # The target is persisted with the receipt, separately from the
            # caller's payload, so recovery never depends on the caller's
            # argument shape -- `resolve_unknown` reads it back to settle an
            # effect whose outcome is unknown.
            durable_arguments = dict(ctx.arguments)
            if ctx.target is not None:
                durable_arguments.setdefault(TARGET_KEY, ctx.target)
            receipt, owned = claim_effect(
                ctx.store,
                ctx.run_id,
                ctx.step_id,
                ctx.action,
                durable_arguments,
                scope=ctx.effect_scope,
                identity_fields=ctx.identity_fields,
            )
            intent_key = receipt.intent_key
            if not owned:
                if receipt.state in ("done", "resolved"):
                    # Already happened. Return the recorded outcome rather than
                    # repeating the action.
                    return Decision(
                        ALLOWED, "DEDUPLICATED",
                        result={"provider_ref": receipt.provider_ref},
                        risk=risk,
                        provider_ref=receipt.provider_ref,
                        _intent_key=receipt.intent_key,
                        deduplicated=True,
                        evidence_status="ok",
                    )
                # A `failed` attempt is known not to have landed, so this
                # caller may take the claim over and try again (only one of
                # several callers retrying at once wins it). A `pending` one
                # may have landed, so it is refused until someone settles it.
                if not (receipt.state == "failed"
                        and ctx.store.reclaim_failed(receipt.intent_key)):
                    raise EffectInFlight(
                        f"effect {receipt.intent_key} is claimed and unfinished; "
                        "settle it before retrying (agent-gateway receipts)"
                    )
        except EffectInFlight as exc:
            _trace(ctx, "enforcement.dispatch", str(exc), "blocked")
            return Decision(
                BLOCKED, "DEDUPLICATED", error=str(exc), risk=risk,
                flags=("effect-already-claimed",),
                evidence_status=run_status(blocked=True),
            )

    if ctx.provider is not None and ctx.target is not None and ctx.records_receipt:
        try:
            provider_ref = ctx.provider.execute(ctx.target, intent_key or "")
        except BaseException as exc:
            # A timeout or a 5xx may have landed: leave the claim unfinished
            # so the same effect is not retried blindly.
            if not outcome_is_unknown(exc):
                ctx.store.mark_failed(intent_key or "")
            raise
        ctx.store.mark_done(intent_key or "", provider_ref)

    if ctx.fuse is not None and ctx.actual_cost_usd is not None:
        try:
            ctx.fuse.budget.reconcile_cost(ctx.estimated_cost_usd, ctx.actual_cost_usd)
        except FuseTrippedError as exc:
            _trace(ctx, "enforcement.fuse", str(exc), BLOCKED)
            return Decision(BLOCKED, "FUSE", error=str(exc), risk=risk, exc=exc,
                            provider_ref=provider_ref,
                            evidence_status=run_status(blocked=True))

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
        evidence_status=run_status(suspicious=bool(flags)),
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
    """Check a tool result against the stop rules. No side effect occurs here."""
    from agent_action_gateway.policy.stop_rules import ResultDecision, StopPolicy

    policy = StopPolicy()
    checked = None
    if not result:
        if cross_check is None:
            outcome: ResultDecision = policy.empty_result(cross_check_performed=False, batch=batch)
        else:
            from agent_action_gateway.policy.cross_check import perform_cross_check

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
                from agent_action_gateway.policy.cross_check import perform_cross_check

                checked = perform_cross_check(result, cross_check)
                outcome = policy.high_stakes_read(second_source_confirmed=checked.agrees, batch=batch)
        else:
            outcome = ResultDecision("CONTINUE")

    flags = suspicious_flags(
        empty_result=not bool(result),
        invariant_failed=checked is not None and not checked.agrees,
        cross_check_failed=checked is not None and not checked.agrees,
    )
    from agent_action_gateway.runtime.records import TraceEvent

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
        ), enforcement="enforced",
    )
    blocked = outcome.decision != "CONTINUE"
    return Decision(
        BLOCKED if blocked else "allowed",
        outcome.decision,
        result=dict(result) if not blocked and result else None,
        flags=tuple(outcome.flags),
        missing=tuple(outcome.missing),
        cross_check_required=outcome.cross_check_required,
        evidence_status=run_status(blocked=blocked, suspicious=bool(flags)),
    )
