"""Evidence capture policy.

Safety-sensitive evidence is never sampled away; routine reads may be. This is
the rule that keeps an approved destructive action from disappearing from the
trace because it happened to look like ordinary traffic.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class TraceDecision:
    capture: bool
    capture_class: str
    flags: tuple[str, ...] = ()


def suspicious_flags(
    *,
    empty_result: bool = False,
    invariant_failed: bool = False,
    cross_check_failed: bool = False,
) -> tuple[str, ...]:
    flags: list[str] = []
    if empty_result:
        flags.append("empty-result")
    if invariant_failed:
        flags.append("invariant-failed")
    if cross_check_failed:
        flags.append("cross-check-failed")
    return tuple(flags)


def classify_capture(
    *,
    event: str,
    risk: str | None = None,
    flags: tuple[str, ...] = (),
    sample_routine_reads: bool = False,
    routine_read_sample: bool = False,
) -> TraceDecision:
    """Decide whether an event must be persisted.

    Safety-sensitive evidence is never sampled. Routine reads may be sampled.
    """
    normalized_event = event.lower()
    always_capture = (
        risk in {"write", "destructive"}
        or normalized_event in {"error", "approval", "safety", "blocked", "destructive"}
        or bool(flags)
    )
    if always_capture:
        return TraceDecision(True, "always", flags)

    if risk == "read" and sample_routine_reads:
        return TraceDecision(routine_read_sample, "sampled", flags)

    return TraceDecision(True, "always", flags)
