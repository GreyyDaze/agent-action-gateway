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
    #: The prompt actually sent to the model, when the caller knows it. `input`
    #: records what the *task* was; this records what the model was given, which
    #: can differ once retrieval or memory is in the path. Optional because the
    #: SDK does not own the adopter's model call.
    prompt: str | None = None
    #: The raw model completion. Redacted on the way in like every other field.
    completion: str | None = None
    tokens_in: int | None = None
    tokens_out: int | None = None
    cost_usd: float | None = None
    latency_ms: float | None = None


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
