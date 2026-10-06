from dataclasses import dataclass
from typing import Any


GOLDEN_SET_VERSION = "golden-v1"
CALIBRATION_SET_VERSION = "calibration-v1"
JUDGE_VERSION = "deterministic-judge-v1"
JUDGE_PROMPT_VERSION = "builtin-rubric-v1"


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
class CalibrationExample:
    example_id: str
    case_id: str
    output: Any
    label: str
    rationale: str


@dataclass(frozen=True)
class SampleResult:
    case_id: str
    run_number: int
    score: float
    passed: bool
    catastrophic: bool
    check_type: str
    label: str
    rationale: str
    confidence: float
    provider: str
    model: str


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
    golden_set_version: str = GOLDEN_SET_VERSION
    candidate_version: str = "unknown"
    created_at: str = ""
    judge_available: bool = True
    judge_error: str = ""


@dataclass(frozen=True)
class Baseline:
    lane: str
    candidate_version: str
    golden_set_version: str
    judge_version: str
    judge_prompt_version: str
    score: float
    cases_evaluated: int
    runs_per_case: int
    estimated_cost_usd: float
    runtime_minutes: float
    created_at: str


@dataclass(frozen=True)
@dataclass(frozen=True)
class CalibrationResult:
    total: int
    agreed: int
    agreement: float
    judge_version: str
    judge_prompt_version: str
    estimated_cost_usd: float
    runtime_seconds: float


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
