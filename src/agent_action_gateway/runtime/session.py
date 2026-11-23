"""The adopter-facing safety session.

A session is how an adopter obtains tools. The agent receives functions from
here and never holds the raw ones, so every action it takes has already passed
risk classification, budgets, environment checks, approval and the receipt
boundary.

The contract is deliberately small:

    with session() as ctx:
        drop = ctx.tool(drop_table, action="db.drop_table", risk="destructive")
        result = ctx.run(agent, task, tools={"drop_table": drop})

Everything is on by default. A caller who passes nothing still gets budgets,
approval on destructive actions, receipts and cross-environment blocking. Opting
out has to be explicit, because a silent default is the failure this project
exists to prevent.
"""

from __future__ import annotations

import functools
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from datetime import UTC
from typing import Any
from uuid import uuid4

from agent_action_gateway.engine import enforcement
from agent_action_gateway.engine.enforcement import Decision, EnforcementContext
from agent_action_gateway.integrations.adapters.base import ExternalActionProvider
from agent_action_gateway.policy.cross_check import CrossCheckSpec
from agent_action_gateway.policy.fuses import (
    FuseBudget,
    FuseController,
    FuseLimits,
    FuseTrippedError,
)
from agent_action_gateway.policy.locks import Approval, ApprovalStore, RiskRegistry
from agent_action_gateway.policy.stop_rules import (
    AmbiguityBlockedError,
    ClarificationState,
    StopPolicy,
    validate_required_input,
)
from agent_action_gateway.runtime.records import TraceEvent
from agent_action_gateway.storage.traces import TraceStore

#: Session defaults. Deliberately finite: an unbounded run is an incident.
DEFAULT_FUSE_LIMITS = FuseLimits(
    max_steps=50,
    max_wall_seconds=600.0,
    max_dollars=2.0,
)
DEFAULT_ENVIRONMENT = "dev"
VALID_ENVIRONMENTS = ("dev", "staging", "prod")


def _payload(result: dict) -> dict:
    """The tool's own return value, unwrapped from the guard's envelope.

    A guarded call comes back as {status, decision, result, ...} where `result`
    is whatever the tool returned. Retry logic has to look at the payload, not
    the envelope -- the envelope's `status` is about the *policy decision*, so
    reading it as the tool's status would treat every allowed call as a failure.
    """
    # Only unwrap when the dict actually looks like the guard's envelope. A
    # plain tool returning its own {"result": ...} must not be mistaken for one.
    if "decision" not in result:
        return result
    nested = result.get("result")
    return nested if isinstance(nested, dict) else {}


def _was_blocked(result: dict) -> bool:
    """Whether policy refused this call.

    Read from the decision the pipeline recorded, not from an exception type or
    a message. Anything that guesses is guessing about the most important branch
    in the library. A fuse trip counts: the run was stopped, and retrying it
    would spend budget to be stopped again.
    """
    if str(result.get("status", "")).lower() == "blocked":
        return True
    if str(result.get("decision", "")).upper() in {"BLOCK", "BLOCKED", "DENY", "DENIED",
                                                   "REFUSE", "FUSE"}:
        return True
    payload = _payload(result)
    if payload.get("blocked") or payload.get("needs_approval"):
        return True
    if str(payload.get("decision", "")).lower() in {"blocked", "denied", "refused"}:
        return True
    # A tool reporting its own outcome as blocked counts too. Only the literal
    # "blocked" is treated as a refusal: a tool returning status "ok" must not
    # be mistaken for one.
    return str(payload.get("status", "")).lower() == "blocked"


def _is_retryable(result: dict) -> bool:
    """Whether the *payload* looks like a transient failure rather than a decision.

    Deliberately conservative: only an explicit transient marker or an upstream
    status in the 5xx range. Anything unrecognised goes back to the caller
    rather than being retried, because retrying an unknown failure is how a
    budget disappears.
    """
    payload = _payload(result)
    if payload.get("transient") is True:
        return True
    status = payload.get("status_code") or payload.get("status")
    return isinstance(status, int) and 500 <= status < 600


def _returns_ok(result: dict) -> bool:
    """Whether a retry produced a usable result."""
    payload = _payload(result)
    status = payload.get("status_code") or payload.get("status")
    return not (isinstance(status, int) and status >= 400)

class SafetySession:
    """Holds policy state for one run and mints guarded tools from it."""

    def __init__(
        self,
        store: TraceStore | None = None,
        *,
        run_id: str | None = None,
        environment: str = DEFAULT_ENVIRONMENT,
        limits: FuseLimits | None = None,
        registry: RiskRegistry | None = None,
        fuse: FuseController | None = None,
        batch: bool = False,
    ) -> None:
        if environment not in VALID_ENVIRONMENTS:
            raise ValueError(
                f"environment must be one of {', '.join(VALID_ENVIRONMENTS)}; "
                f"got {environment!r}"
            )
        self.store = store or TraceStore()
        self.run_id = run_id or str(uuid4())
        self.environment = environment
        self.batch = batch
        self.limits = limits or DEFAULT_FUSE_LIMITS
        self.fuse = fuse or FuseController(FuseBudget(self.limits))
        self.registry = registry or RiskRegistry()
        self.approvals = ApprovalStore(self.store)
        # Clarification state is per run and durable, so an agent that keeps
        # asking the same vague question across turns is still counted.
        self.clarification = _load_clarification(self.store, self.run_id)
        self._step = 0
        self.decisions: list[Decision] = []

    # -- approvals --------------------------------------------------------

    def request_approval(
        self,
        action: str,
        arguments: dict[str, Any],
        *,
        expires_in_seconds: int = 900,
        approver: str = "pending",
    ) -> Approval:
        """Create a pending approval bound to this exact payload."""
        from datetime import datetime, timedelta

        self.registry.register(action, "destructive")
        approval = self.approvals.request(
            action,
            arguments,
            datetime.now(UTC) + timedelta(seconds=expires_in_seconds),
        )
        if approver != "pending":
            return self.approvals.approve(approval.approval_id, approver)
        return approval

    def approve(self, approval_id: str, approver: str) -> Approval:
        return self.approvals.approve(approval_id, approver)

    def deny(self, approval_id: str, approver: str) -> Approval:
        return self.approvals.deny(approval_id, approver)

    def pending_approvals(self) -> list[Approval]:
        return self.approvals.pending()

    # -- model exchange ----------------------------------------------------

    def record_model_exchange(
        self,
        prompt: str | None = None,
        completion: str | None = None,
        *,
        tokens_in: int | None = None,
        tokens_out: int | None = None,
        cost_usd: float | None = None,
        latency_ms: float | None = None,
        event: str = "model.exchange",
        status: str = "completed",
    ) -> int:
        """Record one prompt/completion pair against this run.

        The SDK does not own the adopter's model call, so it cannot see the
        prompt on its own. Without this, a trace shows what the task was and
        what the tool returned, but not what the model was actually given --
        and an audit that cannot reconstruct the exchange cannot explain a bad
        one.

        Redaction is applied on write like every other field, so a caller may
        pass a raw prompt without pre-sanitising it. Omitted values stay NULL,
        which means "not captured" rather than "empty".
        """
        return self.store.append_trace(
            TraceEvent(
                self.run_id,
                0,
                event,
                None,
                None,
                status,
                prompt=prompt,
                completion=completion,
                tokens_in=tokens_in,
                tokens_out=tokens_out,
                cost_usd=cost_usd,
                latency_ms=latency_ms,
            )
        )

    # -- self-correction ----------------------------------------------------

    def retrying(
        self,
        fn: Callable[..., dict[str, Any]],
        *,
        attempts: int = 2,
        on_retry: Callable[[int, dict[str, Any]], None] | None = None,
    ) -> Callable[..., dict[str, Any]]:
        """Retry a guarded tool when it fails for a transient reason.

        Self-correction is the highest-leverage change available to an agent,
        and it is also the easiest way to turn a safety guard into a suggestion:
        a loop that retries will eventually get past a limit by trying often
        enough. So the retry rule is asymmetric on purpose.

            allowed  -> retried up to `attempts` times
            blocked  -> never retried

        A refusal here means policy said no, not that the call was unlucky.
        Retrying it would burn budget, and on a destructive route it would be
        the guard being probed rather than obeyed. So a blocked result is
        returned immediately and counted, however many attempts remain.

        Transient-looking errors -- a timeout, a 5xx upstream -- do get retried,
        because those are the case where retrying is correct. The test is the
        decision recorded on the result, not the shape of the error.
        """
        if attempts < 1:
            raise ValueError("attempts must be at least 1")

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> dict[str, Any]:
            last: dict[str, Any] = {}
            for attempt in range(1, attempts + 1):
                result = fn(*args, **kwargs)
                if not isinstance(result, dict):
                    return result
                last = result
                payload = _payload(result)
                if _was_blocked(result):
                    # Recorded rather than silently swallowed: an operator must
                    # be able to see that an agent tried again after a refusal.
                    self.store.append_trace(
                        TraceEvent(
                            self.run_id,
                            0,
                            "self_correction.refused",
                            {"attempt": attempt, "result": result},
                            "retry refused",
                            "blocked",
                        )
                    )
                    return result
                if not _is_retryable(result) or attempt == attempts:
                    return payload if payload else result
                if on_retry is not None:
                    on_retry(attempt, result)
            return last

        return wrapper

    # -- tools ------------------------------------------------------------

    def tool(
        self,
        fn: Callable[..., Any],
        *,
        action: str,
        risk: str | None = None,
        provider: ExternalActionProvider | None = None,
        target: str | None = None,
        target_environment: str | None = None,
        required_fields: tuple[str, ...] = (),
        high_stakes: bool = False,
        cross_check: CrossCheckSpec | None = None,
        estimated_cost_usd: float = 0.0,
        requires_approval: bool | None = None,
        effect_scope: str = "",
        identity_fields: tuple[str, ...] = (),
    ) -> Callable[..., dict[str, Any]]:
        """Return a guarded callable that routes every call through `enforce`.

        `risk` defaults to destructive: a tool nobody classified is never
        treated as safe.

        `effect_scope` separates otherwise-identical effects across tenants or
        principals. Leaving it empty puts every caller in one namespace, so a
        shared deployment silently suppresses the second of two tenants issuing
        the same action. Any multi-tenant adopter must set it.

        `identity_fields` names the arguments that define the effect. It is the
        escape hatch for the tools where identical arguments do not mean an
        identical effect -- a body that may be edited between retries, a
        timestamp that marks the attempt rather than the intent. Everything not
        named is excluded from the key.
        """
        resolved_risk = risk or "destructive"
        self.registry.register(action, resolved_risk)
        # Destructive is the default; a read tool needs no approval unless the
        # caller asks for one.
        needs_approval = (
            resolved_risk != "read" if requires_approval is None else requires_approval
        )

        def guarded(*args: Any, **kwargs: Any) -> dict[str, Any]:
            self._step += 1
            arguments = _arguments_from(args, kwargs)
            # Pop from the payload unconditionally. An `or` chain here silently
            # left approval_id in the arguments, so every approved call hashed a
            # payload the operator had never seen.
            approval_id = kwargs.pop("approval_id", None)
            if approval_id is None:
                approval_id = arguments.pop("approval_id", None)
            else:
                arguments.pop("approval_id", None)
            actual_cost = kwargs.pop("actual_cost_usd", None)
            approval_id = str(approval_id) if approval_id is not None else None

            decision = enforcement.enforce(
                EnforcementContext(
                    store=self.store,
                    run_id=self.run_id,
                    action=action,
                    arguments=arguments,
                    step_id=f"tool-{self._step}",
                    target=target,
                    provider=provider if needs_approval or resolved_risk != "read" else None,
                    registry=self.registry,
                    approval_store=self.approvals if needs_approval else None,
                    approval_id=approval_id,
                    session_environment=self.environment,
                    target_environment=target_environment,
                    fuse=self.fuse,
                    estimated_cost_usd=estimated_cost_usd,
                    actual_cost_usd=actual_cost,
                    required_fields=required_fields,
                    high_stakes=high_stakes,
                    batch=self.batch,
                    cross_check=cross_check,
                    task=action,
                    effect_scope=effect_scope,
                    identity_fields=identity_fields,
                )
            )
            self.decisions.append(decision)
            if decision.blocked:
                return decision.as_dict()

            # The intent key is the idempotency token the receipt was written
            # under. A tool that accepts it can hand it to its provider, so a
            # crash-recovery replay is recognised as the same action. A tool
            # that does not accept it still cannot run twice: the effect claim
            # blocks the second call either way.
            call_kwargs = dict(kwargs)
            if decision.intent_key is not None and _accepts_keyword(fn, "intent_key"):
                call_kwargs.setdefault("intent_key", decision.intent_key)
            if decision.deduplicated:
                # The effect already landed in an earlier run. The recorded
                # outcome is the answer; calling the function again is the
                # duplicate this whole path exists to prevent.
                return {
                    "status": "allowed",
                    "decision": "DEDUPLICATED",
                    "result": decision.result,
                    "risk": decision.risk,
                    "flags": decision.flags,
                    "evidence_status": decision.evidence_status,
                }
            try:
                payload = _invoke(fn, args, call_kwargs)
            except BaseException:
                # The effect is known not to have landed, so the claim is
                # released and a later attempt is allowed to try again. Left
                # pending it would block every future attempt as in-flight.
                if decision.intent_key is not None:
                    self.store.mark_failed(decision.intent_key)
                raise
            if decision.intent_key is not None:
                # The call returned, so the effect landed. Without this the
                # receipt stays `pending` and every later identical call is
                # refused as in-flight -- which is the opposite of intended.
                self.store.mark_done(decision.intent_key, None)
            if isinstance(payload, Mapping) and (required_fields or high_stakes or cross_check):
                validation = enforcement.validate_result(
                    self.store,
                    self.run_id,
                    action,
                    payload,
                    required_fields=required_fields,
                    high_stakes=high_stakes,
                    batch=self.batch,
                    cross_check=cross_check,
                )
                self.decisions.append(validation)
                if validation.blocked:
                    return validation.as_dict()
                return validation.as_dict()
            return {
                "status": "allowed",
                "decision": "ALLOW",
                "result": payload,
                "risk": decision.risk,
                "flags": decision.flags,
                "evidence_status": decision.evidence_status,
            }

        guarded.__name__ = f"guarded_{action}"
        guarded.__doc__ = (
            f"Guarded {action!r} (risk={resolved_risk}). Every call is authorised, "
            "budgeted and recorded before the underlying function runs."
        )
        guarded.__safety_action__ = action  # type: ignore[attr-defined]
        guarded.__safety_risk__ = resolved_risk  # type: ignore[attr-defined]
        return guarded

    # -- running an agent -------------------------------------------------

    def run(
        self,
        agent_fn: Callable[..., Any],
        task: str,
        *,
        tools: Mapping[str, Callable[..., Any]] | None = None,
        required_inputs: Mapping[str, Any] | None = None,
        new_turn: bool = False,
        batch: bool | None = None,
    ) -> dict[str, Any]:
        """Run an agent with tools it can only reach through this session.

        `required_inputs` names the values the task cannot proceed without, with
        `None` for each one still unknown. If any is missing the agent is not
        called: the run returns `needs_clarification` so a person can answer,
        at most once per turn. Pass `new_turn=True` when the person has replied.
        In batch mode nobody can answer, so a missing input blocks instead.
        """
        tool_map = dict(tools or {})
        if new_turn:
            self.clarification.next_turn()
        if required_inputs is not None:
            stopped = self._check_required_inputs(
                task, dict(required_inputs), self.batch if batch is None else batch
            )
            if stopped is not None:
                return stopped
        self.store.append_trace(
            TraceEvent(self.run_id, 0, "session.start", task, {
                "environment": self.environment,
                "enforcement": "enforced",
                "tools": sorted(tool_map),
            }, "started")
        )
        try:
            # The time limit applies to the agent itself, not only to its tool
            # calls: an agent that thinks forever without calling a tool must
            # still stop. A budget already spent stops the run before it starts.
            self.fuse.budget.check()
            with self.fuse.deadline_guard():
                output = _call_agent(agent_fn, task, tool_map)
            status, error = ("completed", None)
        except FuseTrippedError as exc:
            self.store.append_trace(
                TraceEvent(self.run_id, 9, "fuse", task, str(exc), "blocked")
            )
            self._record_budget()
            return {
                "run_id": self.run_id,
                "status": "blocked",
                "enforcement": "enforced",
                "output": None,
                "error": str(exc),
                "decisions": len(self.decisions),
                "blocked_decisions": len([d for d in self.decisions if d.blocked]),
                "attempt": self.clarification.attempts,
            }
        except Exception as exc:
            self.store.append_trace(
                TraceEvent(self.run_id, 9, "agent", task, str(exc), "failed")
            )
            self._record_budget()
            blocked_so_far = [d for d in self.decisions if d.blocked]
            return {
                "run_id": self.run_id,
                "status": "blocked" if blocked_so_far else "failed",
                "enforcement": "enforced",
                "output": None,
                "error": str(exc),
                "decisions": len(self.decisions),
                "blocked_decisions": len(blocked_so_far),
                "attempt": self.clarification.attempts,
            }

        # Counted after the agent runs: decisions are appended as it acts.
        blocked = [d for d in self.decisions if d.blocked]
        # A blocked action means the run is not clean, whatever the agent says.
        if blocked:
            status = "blocked"
        elif self.fuse.degraded:
            status = "degraded"
        else:
            status = "completed"

        self.store.append_trace(
            TraceEvent(
                self.run_id,
                9,
                "session.end",
                task,
                {"output": output, "status": status, "blocked": len(blocked)},
                status,
            )
        )
        self._record_budget()
        return {
            "run_id": self.run_id,
            "status": status,
            "enforcement": "enforced",
            "output": output,
            "error": error,
            "decisions": len(self.decisions),
            "blocked_decisions": len(blocked),
            "pending_approvals": [a.approval_id for a in self.approvals.pending()],
            "attempt": self.clarification.attempts,
        }

    def _record_budget(self) -> None:
        """Persist how much of the budget the run used, for the dashboard."""
        self.store.record_fuse_snapshot(self.run_id, self.fuse.budget.snapshot())

    def _check_required_inputs(
        self, task: str, required: dict[str, Any], batch: bool
    ) -> dict[str, Any] | None:
        """Stop before the agent runs when a required input is missing."""
        base = {"run_id": self.run_id, "enforcement": "enforced", "output": None}
        try:
            proposal = validate_required_input(
                StopPolicy(), self.clarification, required, batch=batch
            )
        except AmbiguityBlockedError as exc:
            self.store.save_clarification_state(self.run_id, self.clarification)
            self.store.append_trace(
                TraceEvent(self.run_id, 0, "validation", task, str(exc), "blocked")
            )
            return {**base, "status": "blocked", "error": str(exc),
                    "attempt": self.clarification.attempts}
        self.store.save_clarification_state(self.run_id, self.clarification)
        if proposal.decision == "ASK":
            self.store.append_trace(
                TraceEvent(self.run_id, 0, "validation", task, proposal.missing_fields, "ask")
            )
            return {**base, "status": "needs_clarification",
                    "missing_fields": proposal.missing_fields,
                    "attempt": self.clarification.attempts}
        return None

    def close(self) -> None:
        self.store.append_trace(
            TraceEvent(
                self.run_id,
                9,
                "session.close",
                "session",
                {"decisions": len(self.decisions)},
                "completed",
            )
        )

    def __enter__(self) -> SafetySession:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


@contextmanager
def session(**kwargs: Any) -> Iterator[SafetySession]:
    """Convenience factory so callers need not import the class."""
    active = SafetySession(**kwargs)
    try:
        yield active
    finally:
        active.close()


def _load_clarification(store: TraceStore, run_id: str) -> ClarificationState:
    persisted = store.load_clarification_state(run_id)
    if persisted is None:
        return ClarificationState()
    return ClarificationState(
        attempts=persisted["attempts"],
        max_attempts=persisted["max_attempts"],
        asked_this_turn=persisted["asked_this_turn"],
    )


# -- argument shaping ------------------------------------------------------


def _arguments_from(args: tuple[Any, ...], kwargs: dict[str, Any]) -> dict[str, Any]:
    """Flatten a tool call into the payload approval binds to.

    The whole keyword payload is what gets hashed, so an approval cannot be
    reused for a different call that happens to share the first argument.
    """
    payload = dict(kwargs)
    if args:
        payload.setdefault("_args", list(args))
    return payload


def _accepts_keyword(fn: Callable[..., Any], name: str) -> bool:
    """Whether `fn` can be called with `name=` as a keyword argument.

    A callable whose signature cannot be read is assumed to accept it, which
    keeps the earlier behaviour for builtins and C extensions.
    """
    import inspect

    try:
        parameters = inspect.signature(fn).parameters.values()
    except (TypeError, ValueError):
        return True
    return any(
        p.kind is inspect.Parameter.VAR_KEYWORD
        or (p.name == name and p.kind is not inspect.Parameter.POSITIONAL_ONLY)
        for p in parameters
    )


def _invoke(fn: Callable[..., Any], args: tuple[Any, ...], kwargs: dict[str, Any]) -> Any:
    """Call the underlying function without swallowing its signature."""
    import inspect

    try:
        signature = inspect.signature(fn)
        signature.bind(*args, **kwargs)
    except (TypeError, ValueError):
        pass
    return fn(*args, **kwargs)


def _call_agent(
    agent_fn: Callable[..., Any],
    task: str,
    tools: dict[str, Callable[..., Any]],
) -> Any:
    """Support agents that accept only a task, or a task plus tools."""
    import inspect

    try:
        parameters = inspect.signature(agent_fn).parameters
    except (TypeError, ValueError):
        return agent_fn(task)
    if len(parameters) >= 2:
        return agent_fn(task, tools)
    return agent_fn(task)
