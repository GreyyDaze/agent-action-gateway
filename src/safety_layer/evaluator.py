from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import datetime, timezone
from time import perf_counter

from .evaluation_models import EvaluationSummary, GoldenCase, SampleResult
from .judge import DeterministicJudge, Judge, JudgeDecision, is_deterministic


def evaluate_cases(
    cases: Sequence[GoldenCase],
    candidate: Callable[[GoldenCase], object],
    *,
    runs: int,
    judge: Judge | None = None,
    candidate_version: str = "unknown",
) -> EvaluationSummary:
    """Evaluate deterministically first and use an explicit product judge for rubric cases."""
    if runs < 1:
        raise ValueError("runs must be >= 1")
    if not cases:
        raise ValueError("at least one golden case is required")
    if any(not is_deterministic(case) for case in cases) and judge is None:
        raise ValueError(
            "rubric-based cases require an explicit product-controlled judge"
        )

    deterministic_judge = DeterministicJudge()
    started = perf_counter()
    samples: list[SampleResult] = []
    estimated_cost_usd = 0.0

    for run_number in range(1, runs + 1):
        for case in cases:
            output = candidate(case)
            evaluator: Judge = (
                deterministic_judge if is_deterministic(case) else judge
            )
            assert evaluator is not None
            decision: JudgeDecision = evaluator.evaluate(case, output)
            samples.append(
                SampleResult(
                    case_id=case.case_id,
                    run_number=run_number,
                    score=decision.score,
                    passed=decision.label == "pass",
                    catastrophic=case.catastrophic and decision.label == "fail",
                    check_type=case.check_type,
                    label=decision.label,
                    rationale=decision.rationale,
                    confidence=decision.confidence,
                    provider=decision.provider,
                    model=decision.model,
                )
            )
            estimated_cost_usd += decision.estimated_cost_usd

    runtime_minutes = (perf_counter() - started) / 60
    width = len(cases)
    per_run_scores = [
        sum(sample.score for sample in samples[offset : offset + width]) / width
        for offset in range(0, len(samples), width)
    ]
    observed = sum(per_run_scores) / len(per_run_scores)
    noise = max(per_run_scores) - min(per_run_scores) if len(per_run_scores) > 1 else 0.0

    judge_versions = {
        deterministic_judge.version
        if is_deterministic(case)
        else judge.version
        for case in cases
    }
    prompt_versions = {
        deterministic_judge.prompt_version
        if is_deterministic(case)
        else judge.prompt_version
        for case in cases
    }
    judge_version = ",".join(sorted(judge_versions))
    judge_prompt_version = ",".join(sorted(prompt_versions))

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
        estimated_cost_usd=estimated_cost_usd,
        runtime_minutes=runtime_minutes,
        candidate_version=candidate_version,
        created_at=datetime.now(timezone.utc).isoformat(),
    )
