"""The adopter-facing safety session.

A session is how an adopter obtains tools. The agent receives functions from
here and never holds the raw ones, so every action it takes has already passed
risk classification, budgets, environment checks, approval and the receipt
boundary.

The contract is deliberately small:

    with safety.session() as ctx:
        refund = ctx.tool(refund_fn, action="refund", risk="destructive")
        result  = ctx.run(agent, task, tools={"refund": refund})

Everything is on by default. A caller who passes nothing still gets budgets,
approval on destructive actions, receipts and cross-environment blocking. Opting
out has to be explicit, because a silent default is the failure this project
exists to prevent.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from datetime import UTC
from typing import Any
from uuid import uuid4

from ..core import enforcement
from ..core.cross_check import CrossCheckSpec
from ..core.enforcement import Decision, EnforcementContext
from ..core.fuses import FuseBudget, FuseController, FuseLimits
from ..core.locks import Approval, ApprovalStore, RiskRegistry
from ..core.stop_rules import ClarificationState
from ..providers.base import ExternalActionProvider
from ..runtime.records import TraceEvent
from ..storage.traces import TraceStore

#: Session defaults. Deliberately finite: an unbounded run is an incident.
DEFAULT_FUSE_LIMITS = FuseLimits(
    max_steps=50,
    max_wall_seconds=600.0,
    max_dollars=2.0,
)
DEFAULT_ENVIRONMENT = "dev"
VALID_ENVIRONMENTS = ("dev", "staging", "prod")


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
        self.clarification = ClarificationState()
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
    ) -> Callable[..., dict[str, Any]]:
        """Return a guarded callable that routes every call through `enforce`.

        `risk` defaults to destructive (E3.4): a tool nobody classified is not
        silently safe.
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
                )
            )
            self.decisions.append(decision)
            if decision.blocked:
                return decision.as_dict()

            # The intent key is the idempotency token the receipt was written
            # under. A wrapped tool must be able to hand it to its provider, or
            # a crash-recovery replay cannot be recognised as the same action.
            call_kwargs = dict(kwargs)
            if decision.intent_key is not None:
                call_kwargs.setdefault("intent_key", decision.intent_key)
            payload = _invoke(fn, args, call_kwargs)
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
    ) -> dict[str, Any]:
        """Run an agent with tools it can only reach through this session."""
        tool_map = dict(tools or {})
        self.store.append_trace(
            TraceEvent(self.run_id, 0, "session.start", task, {
                "environment": self.environment,
                "enforcement": "enforced",
                "tools": sorted(tool_map),
            }, "started")
        )
        try:
            output = _call_agent(agent_fn, task, tool_map)
            status, error = ("completed", None)
        except Exception as exc:
            self.store.append_trace(
                TraceEvent(self.run_id, 9, "agent", task, str(exc), "failed")
            )
            blocked_so_far = [d for d in self.decisions if d.blocked]
            return {
                "run_id": self.run_id,
                "status": "blocked" if blocked_so_far else "failed",
                "enforcement": "enforced",
                "output": None,
                "error": str(exc),
                "decisions": len(self.decisions),
                "blocked_decisions": len(blocked_so_far),
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
        return {
            "run_id": self.run_id,
            "status": status,
            "enforcement": "enforced",
            "output": output,
            "error": error,
            "decisions": len(self.decisions),
            "blocked_decisions": len(blocked),
            "pending_approvals": [a.approval_id for a in self.approvals.pending()],
        }

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
