from __future__ import annotations

import uuid

from ..runtime.records import GateVerdict
from ..storage.evaluations import EvaluationStore
from ..storage.traces import TraceStore
from .models import Baseline, EvaluationSummary, GateResult
from .verdict import decide

NOT_EVALUATED = "NOT_EVALUATED"


def record_run_status(run_id: str, store: TraceStore, *, failed: bool) -> GateVerdict:
    """Record the honest outcome of a single run.

    A completed run has NOT been evaluated for quality. The regression gate in
    run_gate() is what produces PASS/FAIL/UNCERTAIN, and only after comparing a
    candidate against a recorded baseline. Persisting PASS here, as the previous
    hardcoded score/threshold comparison did, manufactured durable evidence that
    no evaluation ever produced.

    A run that raised is recorded as FAILED because that is a directly observed
    fact, not a judgement about quality.
    """
    result = GateVerdict(
        run_id=run_id,
        verdict="FAIL" if failed else NOT_EVALUATED,
        score=0.0 if failed else 0.0,
        threshold=0.0,
    )
    store.append_gate(result)
    return result


def check_compatibility(
    baseline: Baseline,
    summary: EvaluationSummary,
    *,
    lane: str,
) -> tuple[bool, str]:
    mismatches: list[str] = []

    if baseline.lane != lane:
        mismatches.append("lane")
    if baseline.golden_set_version != summary.golden_set_version:
        mismatches.append("golden-set version")
    if baseline.judge_version != summary.judge_version:
        mismatches.append("judge version")
    if baseline.judge_prompt_version != summary.judge_prompt_version:
        mismatches.append("judge prompt version")
    if baseline.judge_provider != summary.judge_provider:
        mismatches.append("judge provider")
    if baseline.judge_model != summary.judge_model:
        mismatches.append("judge model")

    if mismatches:
        return False, "baseline incompatible: " + ", ".join(mismatches)
    return True, "baseline compatible"


def run_gate(
    summary: EvaluationSummary,
    baseline: Baseline | None,
    *,
    lane: str,
    store: EvaluationStore | None = None,
    unchanged: bool = False,
) -> GateResult:
    if not summary.judge_available:
        result = GateResult(
            verdict="UNCERTAIN", lane=lane,
            baseline_score=baseline.score if baseline is not None else 0.0,
            observed_score=summary.observed_score, noise_estimate=summary.noise_estimate,
            confidence=0.0, cases_evaluated=summary.cases_evaluated,
            runs_per_case=summary.runs_per_case, judge_version=summary.judge_version,
            judge_prompt_version=summary.judge_prompt_version,
            judge_provider=summary.judge_provider,
            judge_model=summary.judge_model,
            estimated_cost_usd=summary.estimated_cost_usd, runtime_minutes=summary.runtime_minutes,
            catastrophic_failure=False,
            reason="semantic judge unavailable: " + summary.judge_error,
        )
    elif baseline is None:
        result = GateResult(
            verdict="UNCERTAIN",
            lane=lane,
            baseline_score=0.0,
            observed_score=summary.observed_score,
            noise_estimate=summary.noise_estimate,
            confidence=0.0,
            cases_evaluated=summary.cases_evaluated,
            runs_per_case=summary.runs_per_case,
            judge_version=summary.judge_version,
            judge_prompt_version=summary.judge_prompt_version,
            judge_provider=summary.judge_provider,
            judge_model=summary.judge_model,
            estimated_cost_usd=summary.estimated_cost_usd,
            runtime_minutes=summary.runtime_minutes,
            catastrophic_failure=summary.catastrophic_failure,
            reason="no compatible baseline is available",
        )
    else:
        compatible, reason = check_compatibility(baseline, summary, lane=lane)
        if not compatible:
            result = GateResult(
                verdict="UNCERTAIN",
                lane=lane,
                baseline_score=baseline.score,
                observed_score=summary.observed_score,
                noise_estimate=summary.noise_estimate,
                confidence=0.0,
                cases_evaluated=summary.cases_evaluated,
                runs_per_case=summary.runs_per_case,
                judge_version=summary.judge_version,
                judge_prompt_version=summary.judge_prompt_version,
                judge_provider=summary.judge_provider,
                judge_model=summary.judge_model,
                estimated_cost_usd=summary.estimated_cost_usd,
                runtime_minutes=summary.runtime_minutes,
                catastrophic_failure=summary.catastrophic_failure,
                reason=reason,
            )
        else:
            result = decide(summary, lane=lane, baseline_score=baseline.score)

    if store is not None:
        evaluation_id = str(uuid.uuid4())
        store.record(evaluation_id, summary, result)
        if unchanged:
            store.record_false_alarm(evaluation_id, summary, result)

    return result
