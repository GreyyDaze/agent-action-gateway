from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from datetime import datetime, timezone
from time import perf_counter

from .evaluation_models import (
    EvaluationSummary,
    GoldenCase,
    JUDGE_PROMPT_VERSION,
    JUDGE_VERSION,
    SampleResult,
)


class Judge:
    version = JUDGE_VERSION
    prompt_version = JUDGE_PROMPT_VERSION

    def score(self, case: GoldenCase, output: object) -> float:
        if case.check_type == "exact":
            return 1.0 if output == case.expected else 0.0
        if case.check_type == "field-equality":
            if not isinstance(output, dict) or not isinstance(case.expected, dict):
                return 0.0
            matches = sum(
                output.get(key) == value for key, value in case.expected.items()
            )
            return matches / len(case.expected)
        if case.check_type == "regex":
            return 1.0 if re.search(str(case.expected), str(output), re.IGNORECASE) else 0.0
        raise ValueError("unsupported check type: {}".format(case.check_type))


def evaluate_cases(
    cases: Sequence[GoldenCase],
    candidate: Callable[[GoldenCase], object],
    *,
    runs: int,
    judge: Judge | None = None,
    estimated_cost_per_sample: float = 0.0,
    candidate_version: str = "unknown",
) -> EvaluationSummary:
    if runs < 1:
        raise ValueError("runs must be >= 1")
    if not cases:
        raise ValueError("at least one golden case is required")

    evaluator = judge or Judge()
    started = perf_counter()
    samples: list[SampleResult] = []

    for run_number in range(1, runs + 1):
        for case in cases:
            score = evaluator.score(case, candidate(case))
            samples.append(
                SampleResult(
                    case_id=case.case_id,
                    run_number=run_number,
                    score=score,
                    passed=score >= 1.0,
                    catastrophic=case.catastrophic and score < 1.0,
                    check_type=case.check_type,
                )
            )

    runtime_minutes = (perf_counter() - started) / 60
    width = len(cases)
    per_run_scores = []
    for offset in range(0, len(samples), width):
        batch = samples[offset : offset + width]
        per_run_scores.append(sum(sample.score for sample in batch) / width)

    observed = sum(per_run_scores) / len(per_run_scores)
    noise = max(per_run_scores) - min(per_run_scores) if len(per_run_scores) > 1 else 0.0

    return EvaluationSummary(
        cases_evaluated=len(cases),
        runs_per_case=runs,
        baseline_score=observed,
        observed_score=observed,
        noise_estimate=noise,
        catastrophic_failure=any(sample.catastrophic for sample in samples),
        samples=tuple(samples),
        judge_version=evaluator.version,
        judge_prompt_version=evaluator.prompt_version,
        estimated_cost_usd=len(samples) * estimated_cost_per_sample,
        runtime_minutes=runtime_minutes,
        candidate_version=candidate_version,
        created_at=datetime.now(timezone.utc).isoformat(),
    )
