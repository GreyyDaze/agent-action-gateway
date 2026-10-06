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


@dataclass(frozen=True)
class GateVerdict:
    run_id: str
    verdict: str
    score: float
    threshold: float
