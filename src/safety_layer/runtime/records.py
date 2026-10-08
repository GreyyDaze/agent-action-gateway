"""The records a run produces as it executes."""
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class TraceEvent:
    run_id: str
    step: int
    event: str
    input: Any
    output: Any
    status: str
    flags: tuple[str, ...] = ()
    capture_class: str = "always"
    provider_metadata: dict[str, Any] | None = None
    provider_evidence: dict[str, Any] | None = None
    replay_of_trace_id: int | None = None


@dataclass(frozen=True)
class GateVerdict:
    run_id: str
    verdict: str
    score: float
    threshold: float


@dataclass(frozen=True)
class Receipt:
    receipt_id: int
    run_id: str
    step_id: str
    intent_key: str
    action: str
    arguments: dict[str, Any]
    state: str
    provider_ref: str | None
