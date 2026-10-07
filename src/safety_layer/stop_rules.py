"""Deterministic stop-and-ask rules for ambiguous agent actions and results.

LLM confidence is deliberately not used here. Decisions come from explicit
runtime state, tool results, environment labels, and policy inputs.
"""

from dataclasses import dataclass, field
from typing import Any, Mapping


class StopRuleError(RuntimeError):
    """Base error for a fail-closed stop-and-ask decision."""


class AmbiguityBlockedError(StopRuleError):
    """Raised when an ambiguous action cannot safely continue."""


class CrossEnvironmentError(StopRuleError):
    """Raised when an action targets a different environment than the run."""


class HighStakesConfirmationError(StopRuleError):
    """Raised when a high-stakes read lacks independent confirmation."""


@dataclass
class ClarificationState:
    """Per-run clarification budget.

    The state is intentionally small and runtime-owned. Persistence can be added
    later if a paused run needs to survive process restarts.
    """

    attempts: int = 0
    max_attempts: int = 2
    asked_this_turn: bool = False

    def request(self, *, critical: bool = True) -> str:
        if not critical:
            return "CONTINUE"

        if self.asked_this_turn:
            raise AmbiguityBlockedError("at most one clarification question is allowed per turn")

        if self.attempts >= self.max_attempts:
            return "BEST_EFFORT_WITH_CAVEAT"

        self.attempts += 1
        self.asked_this_turn = True
        return "ASK"

    def next_turn(self) -> None:
        self.asked_this_turn = False


@dataclass(frozen=True)
class AmbiguityDecision:
    decision: str
    missing_fields: tuple[str, ...] = ()
    caveat: str | None = None


@dataclass(frozen=True)
class ResultDecision:
    decision: str
    flags: tuple[str, ...] = ()
    missing: tuple[str, ...] = ()
    cross_check_required: bool = False


@dataclass(frozen=True)
class StopPolicy:
    """Phase 4 deterministic policy.

    Batch/headless work is fail-closed on unresolved ambiguity because there is
    no human available to answer a clarification question.
    """

    batch_fail_closed: bool = True
    max_clarification_attempts: int = 2

    def missing_input(
        self,
        state: ClarificationState,
        missing_fields: list[str] | tuple[str, ...],
        *,
        batch: bool = False,
        critical: bool = True,
    ) -> AmbiguityDecision:
        missing = tuple(missing_fields)
        if not missing:
            return AmbiguityDecision("CONTINUE")

        if batch and self.batch_fail_closed:
            raise AmbiguityBlockedError(
                f"required information missing in batch mode: {', '.join(missing)}"
            )

        state.max_attempts = self.max_clarification_attempts
        decision = state.request(critical=critical)
        if decision == "ASK":
            return AmbiguityDecision("ASK", missing_fields=missing)

        return AmbiguityDecision(
            "BEST_EFFORT_WITH_CAVEAT",
            missing_fields=missing,
            caveat=f"missing required information: {', '.join(missing)}",
        )

    def empty_result(
        self,
        *,
        cross_check_performed: bool,
        batch: bool = False,
    ) -> ResultDecision:
        if cross_check_performed:
            return ResultDecision(
                "ASK" if not batch else "BLOCK",
                flags=("empty-result-confirmed",),
                cross_check_required=False,
            )

        return ResultDecision(
            "CROSS_CHECK",
            flags=("empty-result-suspicious",),
            cross_check_required=True,
        )

    def partial_result(
        self,
        found: Mapping[str, Any],
        missing: list[str] | tuple[str, ...],
        *,
        missing_critical: bool,
        batch: bool = False,
    ) -> ResultDecision:
        missing_fields = tuple(missing)
        if not missing_fields:
            return ResultDecision("CONTINUE")

        if missing_critical:
            return ResultDecision(
                "BLOCK" if batch else "ASK",
                flags=("partial-result",),
                missing=missing_fields,
            )

        return ResultDecision(
            "REPORT_PARTIAL",
            flags=("partial-result",),
            missing=missing_fields,
        )

    def high_stakes_read(
        self,
        *,
        second_source_confirmed: bool,
        batch: bool = False,
    ) -> ResultDecision:
        if second_source_confirmed:
            return ResultDecision("CONTINUE")

        return ResultDecision(
            "BLOCK" if batch else "ASK",
            flags=("high-stakes-read-unconfirmed",),
        )


def enforce_environment(
    session_environment: str,
    target_environment: str,
) -> None:
    """Reject cross-environment actions before the external dispatch."""
    if session_environment not in {"staging", "prod"}:
        raise ValueError("session environment must be 'staging' or 'prod'")
    if target_environment not in {"staging", "prod"}:
        raise ValueError("target environment must be 'staging' or 'prod'")
    if session_environment != target_environment:
        raise CrossEnvironmentError(
            f"cross-environment action blocked: session={session_environment}, "
            f"target={target_environment}"
        )
