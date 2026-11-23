"""Deterministic Failure Wall grouping.

Failures group by error type, failing step and normalized configuration
fingerprint. Nothing here merges or splits on judgment: those are explicit human
operations, recorded separately.
"""

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any


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

    payload = json.dumps(
        dict(config or {}),
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


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
