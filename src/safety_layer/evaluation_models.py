from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class GoldenCase:
    case_id: str
    task: str
    expected: Any
    check_type: str
    source: str
    catastrophic: bool = False
    rubric: tuple[str, ...] = ()


@dataclass(frozen=True)
class SampleResult:
    case_id: str
    run_number: int
    score: float
    passed: bool
    catastrophic: bool
    check_type: str


@dataclass(frozen=True)
class EvaluationSummary:
    cases_evaluated: int
    runs_per_case: int
    baseline_score: float
    observed_score: float
    noise_estimate: float
    catastrophic_failure: bool
    samples: tuple[SampleResult, ...]
    judge_version: str
    judge_prompt_version: str
    estimated_cost_usd: float
    runtime_minutes: float


@dataclass(frozen=True)
class GateResult:
    verdict: str
    lane: str
    baseline_score: float
    observed_score: float
    noise_estimate: float
    confidence: float
    cases_evaluated: int
    runs_per_case: int
    judge_version: str
    judge_prompt_version: str
    estimated_cost_usd: float
    runtime_minutes: float
    catastrophic_failure: bool
    reason: str
