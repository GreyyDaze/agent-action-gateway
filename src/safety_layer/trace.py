from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

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
# Credential shapes only. A bare "32+ alphanumeric characters" heuristic also
# matches every uuid, idempotency key and provider reference the product relies
# on for evidence, so those are deliberately not redacted.
_VENDOR_TOKEN = re.compile(
    r"\b(?:"
    r"sk-[A-Za-z0-9]{16,}"              # OpenAI-style
    r"|gh[pousr]_[A-Za-z0-9]{16,}"      # GitHub tokens
    r"|AKIA[0-9A-Z]{16}"                # AWS access key ids
    r"|AIza[A-Za-z0-9_-]{35}"           # Google API keys
    r"|xox[abprs]-[A-Za-z0-9-]{10,}"    # Slack
    r")\b"
)


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
        # Do NOT apply a generic "long string" heuristic here. Durable evidence
        # depends on identifiers: run_ids, intent keys, provider references and
        # replay links are all 32+ characters, and redacting them destroys the
        # ability to join a trace back to its own row. Value-based redaction is
        # limited to shapes that are credentials by construction.
        return _VENDOR_TOKEN.sub("[REDACTED_SECRET]", text)
    return value


def honest_status(
    *,
    blocked: bool = False,
    suspicious: bool = False,
    unresolved: bool = False,
    error: bool = False,
) -> str:
    """Compute the observability run status from evidence, never an agent success claim."""
    if blocked:
        return "blocked"
    if suspicious or unresolved or error:
        return "degraded"
    return "ok"



@dataclass(frozen=True)
class FailureSignature:
    """Deterministic Failure Wall key."""

    error_type: str
    failing_step: str
    config_fingerprint: str


@dataclass(frozen=True)
class FailureRecord:
    """Redacted trace evidence used by the Failure Wall."""

    trace_id: int
    run_id: str
    step: int
    event: str
    status: str
    error_type: str
    failing_step: str
    config_fingerprint: str
    flags: tuple[str, ...] = ()


@dataclass
class FailureGroup:
    """Human-reviewable failure group. Ownership starts as unknown."""

    group_id: str
    signature: FailureSignature
    records: list[FailureRecord]
    ownership: str = "unknown"
    state: str = "unconfirmed"


def config_fingerprint(config: Mapping[str, Any] | None) -> str:
    """Create a stable fingerprint for relevant configuration."""
    import hashlib
    import json

    payload = json.dumps(
        dict(config or {}),
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def failure_signature(
    *,
    error_type: str,
    failing_step: str,
    config: Mapping[str, Any] | None,
) -> FailureSignature:
    return FailureSignature(
        error_type=error_type or "unknown",
        failing_step=failing_step or "unknown",
        config_fingerprint=config_fingerprint(config),
    )


def _failure_error_type(trace: Mapping[str, Any]) -> str:
    output = trace.get("output")
    if isinstance(output, Mapping):
        error = output.get("error")
        if isinstance(error, Mapping):
            name = error.get("type") or error.get("name")
            if name:
                return str(name)
        if error:
            return type(error).__name__ if not isinstance(error, str) else "tool-error"

    status = str(trace.get("status", "")).lower()
    if status in {"failed", "error"}:
        return "runtime-error"

    flags = tuple(str(flag) for flag in trace.get("flags", ()))
    if flags:
        return "silent-wrong:" + ",".join(sorted(flags))
    return "unknown"


def _failure_config(trace: Mapping[str, Any]) -> Mapping[str, Any]:
    metadata = trace.get("provider_metadata")
    if not isinstance(metadata, Mapping):
        return {}
    config = metadata.get("config")
    return config if isinstance(config, Mapping) else {}


def failure_record(trace: Mapping[str, Any]) -> FailureRecord | None:
    """Turn a persisted trace into a Failure Wall record.

    Only explicit failures or suspicious observability traces enter the wall.
    """
    status = str(trace.get("status", "")).lower()
    flags = tuple(str(flag) for flag in trace.get("flags", ()))
    if status not in {"failed", "error", "blocked"} and not flags:
        return None

    step = int(trace.get("step", 0))
    event = str(trace.get("event", "unknown"))
    return FailureRecord(
        trace_id=int(trace.get("id", 0)),
        run_id=str(trace.get("run_id", "")),
        step=step,
        event=event,
        status=status,
        error_type=_failure_error_type(trace),
        failing_step=event or str(step),
        config_fingerprint=config_fingerprint(_failure_config(trace)),
        flags=flags,
    )


def build_failure_wall(traces: Iterable[Mapping[str, Any]]) -> list[FailureGroup]:
    """Group by error type × failing step × config fingerprint only."""
    import hashlib

    groups: dict[FailureSignature, FailureGroup] = {}
    for trace in traces:
        record = failure_record(trace)
        if record is None:
            continue
        signature = FailureSignature(
            record.error_type,
            record.failing_step,
            record.config_fingerprint,
        )
        group = groups.get(signature)
        if group is None:
            payload = "|".join(
                (
                    signature.error_type,
                    signature.failing_step,
                    signature.config_fingerprint,
                )
            )
            group = FailureGroup(
                group_id=hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16],
                signature=signature,
                records=[],
            )
            groups[signature] = group
        group.records.append(record)

    return sorted(groups.values(), key=lambda group: group.group_id)


def confirm_failure_group(group: FailureGroup) -> FailureGroup:
    """Human confirmation changes state only; it never assigns ownership."""
    group.state = "confirmed"
    group.ownership = "unknown"
    return group


def merge_failure_groups(groups: Iterable[FailureGroup]) -> FailureGroup:
    """Explicit human merge. The automatic grouper never performs this."""
    selected = list(groups)
    if len(selected) < 2:
        raise ValueError("merge requires at least two groups")
    import hashlib

    payload = "|".join(sorted(group.group_id for group in selected))
    records = [record for group in selected for record in group.records]
    return FailureGroup(
        group_id="merged-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16],
        signature=selected[0].signature,
        records=records,
        ownership="unknown",
        state="confirmed" if all(g.state == "confirmed" for g in selected) else "unconfirmed",
    )


def split_failure_group(
    group: FailureGroup,
    signatures: Iterable[FailureSignature],
) -> list[FailureGroup]:
    """Explicit human split using signatures selected from the evidence."""
    requested = list(signatures)
    if not requested:
        raise ValueError("split requires at least one target signature")
    if len(requested) != len(set(requested)):
        raise ValueError("split target signatures must be unique")

    buckets: dict[FailureSignature, list[FailureRecord]] = {
        signature: [] for signature in requested
    }
    for record in group.records:
        key = FailureSignature(
            record.error_type,
            record.failing_step,
            record.config_fingerprint,
        )
        if key not in buckets:
            raise ValueError("split signature does not match group evidence")
        buckets[key].append(record)

    if any(not records for records in buckets.values()):
        raise ValueError("split target must contain evidence")

    import hashlib

    result = []
    for signature, records in buckets.items():
        payload = "|".join(
            (signature.error_type, signature.failing_step, signature.config_fingerprint)
        )
        result.append(
            FailureGroup(
                group_id=hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16],
                signature=signature,
                records=records,
                ownership="unknown",
                state="unconfirmed",
            )
        )
    return result
