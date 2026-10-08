"""Deterministic execution limits execution fuses.

Fuses are local, deterministic circuit breakers at the action boundary.
They enforce budgets before dispatch and never judge the agent's goal.
"""

from __future__ import annotations

import hashlib
import json
import signal
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from typing import Any


class FuseError(RuntimeError):
    """Base error for a fuse decision."""


class FuseTrippedError(FuseError):
    """Raised when a run cannot safely continue."""


class FuseUnavailableError(FuseError):
    """Raised when the fuse service is unavailable."""


@dataclass(frozen=True)
class FuseLimits:
    max_steps: int | None = None
    max_wall_seconds: float | None = None
    max_dollars: float | None = None
    loop_repeat_limit: int = 3
    degraded_read_steps: int = 10

    def __post_init__(self) -> None:
        if self.max_steps is not None and self.max_steps < 0:
            raise ValueError("max_steps must be >= 0")
        if self.max_wall_seconds is not None and self.max_wall_seconds < 0:
            raise ValueError("max_wall_seconds must be >= 0")
        if self.max_dollars is not None and self.max_dollars < 0:
            raise ValueError("max_dollars must be >= 0")
        if self.loop_repeat_limit < 2:
            raise ValueError("loop_repeat_limit must be >= 2")
        if self.degraded_read_steps < 0:
            raise ValueError("degraded_read_steps must be >= 0")


@dataclass(frozen=True)
class FuseSnapshot:
    steps_used: int
    dollars_used: float
    elapsed_seconds: float
    tripped: bool
    degraded: bool
    reason: str | None


class FuseBudget:
    """In-process atomic budget for one run."""

    def __init__(self, limits: FuseLimits | None = None, *, clock: Any = time.monotonic) -> None:
        self.limits = limits or FuseLimits()
        self._clock = clock
        self._started_at = clock()
        self._steps_used = 0
        self._dollars_used = 0.0
        self._tripped_reason: str | None = None
        self._lock = threading.Lock()

    def check(self) -> None:
        with self._lock:
            self._check_locked()

    def consume_step(self, estimated_cost_usd: float = 0.0) -> None:
        if estimated_cost_usd < 0:
            raise ValueError("estimated_cost_usd must be >= 0")
        with self._lock:
            self._check_locked()
            next_steps = self._steps_used + 1
            next_dollars = self._dollars_used + estimated_cost_usd
            if self.limits.max_steps is not None and next_steps > self.limits.max_steps:
                self._trip_locked("step budget exhausted")
            if self.limits.max_dollars is not None and next_dollars > self.limits.max_dollars:
                self._trip_locked("spend budget exhausted")
            self._steps_used = next_steps
            self._dollars_used = next_dollars

    def reconcile_cost(self, estimated_dollars: float, actual_dollars: float) -> None:
        if estimated_dollars < 0 or actual_dollars < 0:
            raise ValueError("costs must be >= 0")
        with self._lock:
            self._dollars_used += actual_dollars - estimated_dollars
            self._dollars_used = max(0.0, self._dollars_used)
            if self.limits.max_dollars is not None and self._dollars_used > self.limits.max_dollars:
                self._trip_locked("spend budget exhausted")

    def trip(self, reason: str) -> None:
        """Record a refusal reason without raising.

        Used by the loop detector, which refuses a call without holding the
        budget lock. Without recording it the snapshot reported `tripped=False`
        while refusing every subsequent call, so a dashboard would show a
        healthy budget for a run that was already dead.
        """
        """Trip the fuse without taking a lock.

        Used by the signal handler because Python signal handlers must not
        acquire threading locks.
        """
        self._tripped_reason = reason

    def remaining_wall_seconds(self) -> float | None:
        """Return the remaining wall-clock budget without changing state."""
        if self.limits.max_wall_seconds is None:
            return None
        return self.limits.max_wall_seconds - (self._clock() - self._started_at)

    def snapshot(self) -> FuseSnapshot:
        with self._lock:
            return FuseSnapshot(
                steps_used=self._steps_used,
                dollars_used=self._dollars_used,
                elapsed_seconds=self._clock() - self._started_at,
                tripped=self._tripped_reason is not None,
                degraded=False,
                reason=self._tripped_reason,
            )

    def _check_locked(self) -> None:
        if self._tripped_reason is not None:
            raise FuseTrippedError(self._tripped_reason)
        elapsed = self._clock() - self._started_at
        if self.limits.max_wall_seconds is not None and elapsed >= self.limits.max_wall_seconds:
            self._trip_locked("wall-clock budget exhausted")
        if self.limits.max_steps is not None and self._steps_used >= self.limits.max_steps:
            self._trip_locked("step budget exhausted")
        if self.limits.max_dollars is not None and self._dollars_used >= self.limits.max_dollars:
            self._trip_locked("spend budget exhausted")

    def _trip_locked(self, reason: str) -> None:
        self._tripped_reason = reason
        raise FuseTrippedError(reason)


class LoopDetector:
    """Detect repeated actions without explicit progress."""

    def __init__(self, repeat_limit: int = 3) -> None:
        if repeat_limit < 2:
            raise ValueError("repeat_limit must be >= 2")
        self.repeat_limit = repeat_limit
        self._last_fingerprint: str | None = None
        self._stalled_repeats = 0
        self._lock = threading.Lock()

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
        with self._lock:
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
    """Budget, loop, deadline, and availability policy at one action boundary."""

    def __init__(
        self,
        budget: FuseBudget,
        *,
        loop_detector: LoopDetector | None = None,
    ) -> None:
        self.budget = budget
        self.loop_detector = loop_detector or LoopDetector(budget.limits.loop_repeat_limit)
        self._available = True
        self._degraded_reads_used = 0
        self._availability_lock = threading.Lock()

    @property
    def limits(self) -> FuseLimits:
        """The configured budget limits, for callers that report or test policy."""
        return self.budget.limits

    @property
    def degraded(self) -> bool:
        return not self._available

    def mark_unavailable(self) -> None:
        with self._availability_lock:
            self._available = False

    def restore(self) -> None:
        with self._availability_lock:
            self._available = True
            self._degraded_reads_used = 0

    def _is_available(self) -> bool:
        with self._availability_lock:
            return self._available

    def before_dispatch(
        self,
        action: str,
        arguments: dict[str, Any],
        *,
        estimated_cost_usd: float = 0.0,
        new_information: bool = False,
        state_changed: bool = False,
        write: bool = False,
    ) -> None:
        if not self._is_available():
            if write:
                raise FuseTrippedError("cannot check limits, so writes are refused")
            with self._availability_lock:
                if self._degraded_reads_used >= self.budget.limits.degraded_read_steps:
                    raise FuseTrippedError("read allowance used up while limits are unavailable")
                self._degraded_reads_used += 1
            return

        self.budget.check()
        if self.loop_detector.observe(
            action,
            arguments,
            new_information=new_information,
            state_changed=state_changed,
        ):
            reason = "loop detected: repeated action made no progress"
            # Record it so the snapshot and the dashboard agree with reality.
            self.budget.trip(reason)
            raise FuseTrippedError(reason)
        self.budget.consume_step(estimated_cost_usd)

    def snapshot(self) -> FuseSnapshot:
        """Return the current budget counters plus controller state."""
        return replace(self.budget.snapshot(), degraded=self.degraded)

    @contextmanager
    def deadline_guard(self) -> Iterator[None]:
        """Interrupt a long-running Python call at the wall-clock deadline.

        Unix main-thread only. Normal action-boundary checks remain the
        portable enforcement mechanism for other execution contexts.
        """
        if self.budget.limits.max_wall_seconds is None:
            yield
            return
        if threading.current_thread() is not threading.main_thread() or not hasattr(signal, "SIGALRM"):
            yield
            return

        remaining = self.budget.remaining_wall_seconds()
        if remaining is None:
            yield
            return
        if remaining <= 0:
            self.budget.trip("wall-clock budget exhausted")
            raise FuseTrippedError("wall-clock budget exhausted")

        previous_handler = signal.getsignal(signal.SIGALRM)

        def handle_timeout(_signum: int, _frame: Any) -> None:
            self.budget.trip("wall-clock budget exhausted")
            raise FuseTrippedError("wall-clock budget exhausted")

        previous_timer = signal.getitimer(signal.ITIMER_REAL)
        signal.signal(signal.SIGALRM, handle_timeout)
        signal.setitimer(signal.ITIMER_REAL, remaining)
        try:
            yield
        finally:
            signal.setitimer(signal.ITIMER_REAL, *previous_timer)
            signal.signal(signal.SIGALRM, previous_handler)
