from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping

_SECRET_KEYS = re.compile(
    r"(api[_-]?key|authorization|password|passwd|secret|token|access[_-]?token|refresh[_-]?token)",
    re.IGNORECASE,
)
_PII_KEYS = re.compile(
    r"(email|phone|telephone|mobile|ssn|social[_-]?security|address|dob|date[_-]?of[_-]?birth)",
    re.IGNORECASE,
)
_EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
_BEARER = re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]+\b", re.IGNORECASE)
_LONG_TOKEN = re.compile(r"\b[A-Za-z0-9_-]{32,}\b")


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


def redact(value: Any, *, _key: str | None = None) -> Any:
    """Recursively redact common secrets and direct PII before persistence."""
    if _key and _SECRET_KEYS.search(_key):
        return "[REDACTED_SECRET]"
    if _key and _PII_KEYS.search(_key):
        return "[REDACTED_PII]"

    if isinstance(value, Mapping):
        return {str(k): redact(v, _key=str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact(item) for item in value)
    if isinstance(value, str):
        text = _EMAIL.sub("[REDACTED_EMAIL]", value)
        text = _BEARER.sub("Bearer [REDACTED_SECRET]", text)
        return _LONG_TOKEN.sub("[REDACTED_TOKEN]", text)
    return value


def honest_status(
    *,
    blocked: bool = False,
    suspicious: bool = False,
    unresolved: bool = False,
    error: bool = False,
) -> str:
    """Compute the Phase 6 run status from evidence, never an agent success claim."""
    if blocked:
        return "blocked"
    if suspicious or unresolved or error:
        return "degraded"
    return "ok"
