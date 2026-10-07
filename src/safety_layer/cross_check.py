"""Deterministic two-source verification for suspicious tool results."""

from dataclasses import dataclass
from typing import Any, Callable, Mapping


class CrossCheckDisagreementError(RuntimeError):
    """Raised when an independent source violates the required invariant."""


@dataclass(frozen=True)
class CrossCheckSpec:
    """Defines exactly how a result is independently verified."""

    first_source: str
    second_source: str
    invariant_name: str
    second_source_fn: Callable[[], Mapping[str, Any]]
    invariant: Callable[[Mapping[str, Any], Mapping[str, Any]], bool]


@dataclass(frozen=True)
class CrossCheckResult:
    first_source: str
    second_source: str
    invariant_name: str
    second_result: Mapping[str, Any]
    agrees: bool

    @property
    def flags(self) -> tuple[str, ...]:
        if self.agrees:
            return ("cross-check-agreement",)
        return ("cross-check-disagreement",)


def perform_cross_check(
    first_result: Mapping[str, Any],
    spec: CrossCheckSpec,
) -> CrossCheckResult:
    """Run the independent source once and evaluate the explicit invariant."""
    second_result = spec.second_source_fn()
    agrees = spec.invariant(first_result, second_result)
    return CrossCheckResult(
        first_source=spec.first_source,
        second_source=spec.second_source,
        invariant_name=spec.invariant_name,
        second_result=second_result,
        agrees=agrees,
    )
