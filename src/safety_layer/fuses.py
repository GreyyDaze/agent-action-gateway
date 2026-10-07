"""Deterministic Phase 5 execution fuses.

Fuses are deliberately local and deterministic. They sit on the action
boundary and never try to judge the agent's goal.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import dataclass
from typing import Any


class FuseError(RuntimeError):
    """Base error for a fuse decision that blocks execution."""


class FuseTrippedError(FuseError):
    """Raised when a run cannot dispatch another action."""


@dataclass(frozen=True)
class FuseLimits:
    max_steps: int | None = None
    max_wall_seconds: float | None = None
    max_dollars: float | None = None
    loop_repeat_limit: int = 3

    def __post_init__(self) -> None:
        if self.max_steps is not None and self.max_steps < 0:
            raise ValueError("max_steps must be >= 0")
        if self.max_wall_seconds is not None and self.max_wall_seconds < 0:
            raise ValueError("max_wall_seconds must be >= 0")
        if self.max_dollars is not None and self.max_dollars < 0:
            raise ValueError("max_dollars must be >= 0")
        if self.loop_repeat_limit < 2:
            raise ValueError("loop_repeat_limit must be >= 2")


@dataclass(frozen=True)
class FuseSnapshot:
    steps_used: int
    dollars_used: float
    elapsed_seconds: float
    tripped: bool
    reason: str | None


class FuseBudget:
    """In-process atomic budget for one run.

    The lock protects the read-modify-write operation so concurrent callers
    sharing this budget cannot both consume the same remaining capacity.
    """

    def __init__(
        self,
        limits: FuseLimits | None = None,
        *,
        clock: Any = time.monotonic,
    ) -> None:
        self.limits = limits or FuseLimits()
        self._clock = clock
        self._started_at = clock()
        self._steps_used = 0
        self._dollars_used = 0.0
        self._tripped_reason: str | None = None
        self._lock = threading.Lock()

    def check(self) -> None:
        """Check limits without consuming a step or dispatching an action."""
        with self._lock:
            self._check_locked()

    def consume_step(self, estimated_cost_usd: float = 0.0) -> None:
        """Atomically reserve one action and its estimated spend.

        Reservation happens before dispatch. Therefore a rejected action never
        reaches the external tool.
        """
        if estimated_cost_usd < 0:
            raise ValueError("estimated_cost_usd must be >= 0")

        with self._lock:
            self._check_locked()

            next_steps = self._steps_used + 1
            next_dollars = self._dollars_used + estimated_cost_usd

            if (
                self.limits.max_steps is not None
                and next_steps > self.limits.max_steps
            ):
                self._trip_locked("step budget exhausted")
            if (
                self.limits.max_dollars is not None
                and next_dollars > self.limits.max_dollars
            ):
                self._trip_locked("spend budget exhausted")

            self._steps_used = next_steps
            self._dollars_used = next_dollars

    def reconcile_cost(self, estimated_dollars: float, actual_dollars: float) -> None:
        """Replace a pre-dispatch estimate with observed cost."""
        if estimated_dollars < 0 or actual_dollars < 0:
            raise ValueError("costs must be >= 0")
        with self._lock:
            self._dollars_used += actual_dollars - estimated_dollars
            if self._dollars_used < 0:
                self._dollars_used = 0.0
            if (
                self.limits.max_dollars is not None
                and self._dollars_used > self.limits.max_dollars
            ):
                self._trip_locked("spend budget exhausted")

    def record_cost(self, dollars: float) -> None:
        """Record additional observed cost without allowing future dispatch."""
        if dollars < 0:
            raise ValueError("dollars must be >= 0")

        with self._lock:
            self._dollars_used += dollars
            if (
                self.limits.max_dollars is not None
                and self._dollars_used > self.limits.max_dollars
            ):
                self._trip_locked("spend budget exhausted")

    def snapshot(self) -> FuseSnapshot:
        with self._lock:
            return FuseSnapshot(
                steps_used=self._steps_used,
                dollars_used=self._dollars_used,
                elapsed_seconds=self._clock() - self._started_at,
                tripped=self._tripped_reason is not None,
                reason=self._tripped_reason,
            )

    def _check_locked(self) -> None:
        if self._tripped_reason is not None:
            raise FuseTrippedError(self._tripped_reason)

        elapsed = self._clock() - self._started_at
        if (
            self.limits.max_wall_seconds is not None
            and elapsed >= self.limits.max_wall_seconds
        ):
            self._trip_locked("wall-clock budget exhausted")

        if (
            self.limits.max_steps is not None
            and self._steps_used >= self.limits.max_steps
        ):
            self._trip_locked("step budget exhausted")

        if (
            self.limits.max_dollars is not None
            and self._dollars_used >= self.limits.max_dollars
        ):
            self._trip_locked("spend budget exhausted")

    def _trip_locked(self, reason: str) -> None:
        self._tripped_reason = reason
        raise FuseTrippedError(reason)


class LoopDetector:
    """Detect repeated identical actions that make no progress.

    Progress is explicit: either new information arrived or external state
    changed. Different action arguments produce different fingerprints, which
    keeps normal pagination from looking like a loop.
    """

    def __init__(self, repeat_limit: int = 3) -> None:
        if repeat_limit < 2:
            raise ValueError("repeat_limit must be >= 2")
        self.repeat_limit = repeat_limit
        self._last_fingerprint: str | None = None
        self._stalled_repeats = 0

    @staticmethod
    def fingerprint(action: str, arguments: dict[str, Any]) -> str:
        canonical = json.dumps(
            {"action": action, "arguments": arguments},
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def observe(
        self,
        action: str,
        arguments: dict[str, Any],
        *,
        new_information: bool = False,
        state_changed: bool = False,
    ) -> bool:
        fingerprint = self.fingerprint(action, arguments)

        if new_information or state_changed:
            self._last_fingerprint = fingerprint
            self._stalled_repeats = 0
            return False

        if fingerprint == self._last_fingerprint:
            self._stalled_repeats += 1
        else:
            self._last_fingerprint = fingerprint
            self._stalled_repeats = 1

        return self._stalled_repeats >= self.repeat_limit


class FuseController:
    """Combines budget enforcement and loop detection at an action boundary."""

    def __init__(
        self,
        budget: FuseBudget,
        *,
        loop_detector: LoopDetector | None = None,
    ) -> None:
        self.budget = budget
        self.loop_detector = loop_detector or LoopDetector(
            budget.limits.loop_repeat_limit
        )

    def before_dispatch(
        self,
        action: str,
        arguments: dict[str, Any],
        *,
        estimated_cost_usd: float = 0.0,
        new_information: bool = False,
        state_changed: bool = False,
    ) -> None:
        """Run the complete local fuse check before external dispatch."""
        self.budget.check()

        if self.loop_detector.observe(
            action,
            arguments,
            new_information=new_information,
            state_changed=state_changed,
        ):
            raise FuseTrippedError("loop detected: repeated action made no progress")

        self.budget.consume_step(estimated_cost_usd)
