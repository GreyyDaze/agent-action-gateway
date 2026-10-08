from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from time import perf_counter, sleep

from .judge import (
    DeterministicJudge,
    Judge,
    JudgeDecision,
    JudgeUnavailableError,
    is_deterministic,
)
from .models import EvaluationSummary, GoldenCase, SampleResult


def evaluate_cases(
    cases: Sequence[GoldenCase],
    candidate: Callable[[GoldenCase], object],
    *,
    runs: int,
    judge: Judge | None = None,
    candidate_version: str = "unknown",
    judge_wait_seconds: float = 0.0,
    detail: bool = False,
) -> EvaluationSummary:
    """Evaluate deterministically first and use an explicit product judge for rubric cases."""
    if runs < 1:
        raise ValueError("runs must be >= 1")
    if not cases:
        raise ValueError("at least one golden case is required")
    if judge_wait_seconds < 0:
        raise ValueError("judge_wait_seconds must be >= 0")
    if any(not is_deterministic(case) for case in cases) and judge is None:
        raise ValueError(
            "rubric-based cases require an explicit product-controlled judge"
        )

    deterministic_judge = DeterministicJudge()
    started = perf_counter()
    samples: list[SampleResult] = []
    estimated_cost_usd = 0.0
    judge_available = True
    judge_error = ""
    judge_request_count = 0

    for run_number in range(1, runs + 1):
        if detail:
            print(f"RUN | {run_number}/{runs} | starting")
        if not judge_available:
            break
        for case in cases:
            output = candidate(case)
            # Non-deterministic cases always arrive here with a judge: the
            # guard above raises if any exist without one.
            selected: Judge | None = (
                deterministic_judge if is_deterministic(case) else judge
            )
            if selected is None:
                raise RuntimeError(
                    "rubric cases require an explicitly configured judge"
                )
            evaluator: Judge = selected
            try:
                if not is_deterministic(case):
                    if judge_request_count > 0 and judge_wait_seconds:
                        if detail:
                            print(f"WAIT | {judge_wait_seconds:.1f}s before next judge request")
                        sleep(judge_wait_seconds)
                    judge_request_count += 1
                    if detail:
                        provider_name = getattr(evaluator, "provider", "unknown")
                        model_name = getattr(provider_name, "model", "unknown")
                        provider_text = provider_name if isinstance(provider_name, str) else type(provider_name).__name__
                        print(f"JUDGE-REQUEST | provider={provider_text} | model={model_name} | case={case.case_id} | request={judge_request_count}")
                decision_started = perf_counter()
                decision: JudgeDecision = evaluator.evaluate(case, output)
                decision_seconds = perf_counter() - decision_started
                if detail and not is_deterministic(case):
                    print(f"JUDGE-RESULT | case={case.case_id} | label={decision.label.upper()} | score={decision.score:.4f} | latency={decision_seconds:.2f}s")
            except JudgeUnavailableError as exc:
                judge_available = False
                judge_error = str(exc)
                break
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
    if not judge_available:
        observed = 0.0
        noise = 0.0
    else:
        width = len(cases)
        per_run_scores = [
            sum(sample.score for sample in samples[offset : offset + width]) / width
            for offset in range(0, len(samples), width)
        ]
        observed = sum(per_run_scores) / len(per_run_scores)
        noise = max(per_run_scores) - min(per_run_scores) if len(per_run_scores) > 1 else 0.0

    rubric_judge = judge
    judge_versions = {
        deterministic_judge.version
        if is_deterministic(case)
        else _require_judge(rubric_judge).version
        for case in cases
    }
    prompt_versions = {
        deterministic_judge.prompt_version
        if is_deterministic(case)
        else _require_judge(rubric_judge).prompt_version
        for case in cases
    }
    judge_version = ",".join(sorted(judge_versions))
    judge_prompt_version = ",".join(sorted(prompt_versions))
    provider_versions = {sample.provider for sample in samples}
    model_versions = {sample.model for sample in samples}
    if not provider_versions and judge is not None:
        provider = getattr(judge, "provider", None)
        if isinstance(provider, str):
            provider_versions.add(provider)
    if not model_versions and judge is not None:
        model = getattr(getattr(judge, "provider", None), "model", None)
        if isinstance(model, str):
            model_versions.add(model)

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
        judge_provider=",".join(sorted(provider_versions)),
        judge_model=",".join(sorted(model_versions)),
        candidate_version=candidate_version,
        created_at=datetime.now(UTC).isoformat(),
        judge_available=judge_available,
        judge_error=judge_error,
    )


def _require_judge(judge: Judge | None) -> Judge:
    if judge is None:
        raise RuntimeError("rubric cases require an explicitly configured judge")
    return judge
