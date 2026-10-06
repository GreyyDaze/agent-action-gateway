from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import datetime, timezone
from time import perf_counter

from .evaluation_models import EvaluationSummary, GoldenCase, SampleResult
from .judge import DeterministicJudge, Judge, is_deterministic


def evaluate_cases(
    cases: Sequence[GoldenCase],
    candidate: Callable[[GoldenCase], object],
    *,
    runs: int,
    judge: Judge | None = None,
    estimated_cost_per_sample: float = 0.0,
    candidate_version: str = "unknown",
) -> EvaluationSummary:
    """Evaluate cases, using deterministic checks before any optional LLM judge.

    A rubric case requires an explicit product-controlled judge. Deterministic
    cases never call that judge, even when one is supplied.
    """
    if runs < 1:
        raise ValueError("runs must be >= 1")
    if not cases:
        raise ValueError("at least one golden case is required")

    deterministic_judge = DeterministicJudge()
    if any(not is_deterministic(case) for case in cases) and judge is None:
        raise ValueError(
            "rubric-based cases require an explicit product-controlled judge"
        )

    started = perf_counter()
    samples: list[SampleResult] = []

    for run_number in range(1, runs + 1):
        for case in cases:
            output = candidate(case)
            evaluator = deterministic_judge if is_deterministic(case) else judge
            assert evaluator is not None
            score = evaluator.score(case, output)
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

    judge_version = judge.version if judge is not None else deterministic_judge.version
    judge_prompt_version = (
        judge.prompt_version if judge is not None else deterministic_judge.prompt_version
    )

    return EvaluationSummary(
        cases_evaluated=len(cases),
        runs_per_case=runs,
        baseline_score=observed,
        observed_score=observed,
        noise_estimate=noise,
        catastrophic_failure=any(sample.catastrophic for sample in samples),
        samples=tuple(samples),
        judge_version=judge_version,
        judge_prompt_version=judge_prompt_version,
        estimated_cost_usd=len(samples) * estimated_cost_per_sample,
        runtime_minutes=runtime_minutes,
        candidate_version=candidate_version,
        created_at=datetime.now(timezone.utc).isoformat(),
    )
