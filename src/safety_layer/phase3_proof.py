from __future__ import annotations

from dataclasses import replace

from .evaluation_models import GoldenCase
from .evaluator import evaluate_cases
from .golden import seed_golden_cases
from .verdict import decide


class ProofRubricJudge:
    """Test-only rubric judge used to keep the Phase 3 proof offline."""

    version = "proof-rubric-judge-v1"
    prompt_version = "proof-rubric-prompt-v1"

    def evaluate(self, case: GoldenCase, output: object) -> JudgeDecision:
        passed = output == case.expected
        return JudgeDecision(
            label="pass" if passed else "fail",
            score=1.0 if passed else 0.0,
            confidence=1.0,
            rationale="test stub",
            provider="test",
            model="stub",
            judge_version=self.version,
            prompt_version=self.prompt_version,
        )


def good_output(case: GoldenCase) -> object:
    if case.check_type == "regex":
        return "The refund was refunded successfully."
    return case.expected


def five_point_drop_output(case: GoldenCase) -> object:
    if case.case_id == "refund-002":
        return {"order_id": "ORD-WRONG", "status": "failed"}
    if case.case_id == "refund-006":
        return {"order_id": "ORD-006", "status": "wrong"}
    return good_output(case)


def catastrophic_drop_output(case: GoldenCase) -> object:
    if case.case_id == "tool-001":
        return {"tool": "delete_customer", "arguments": {"id": "C-1"}}
    return good_output(case)


def run_proof() -> None:
    cases = seed_golden_cases()
    judge = ProofRubricJudge()
    baseline = evaluate_cases(cases, good_output, runs=3, judge=judge)
    degraded = evaluate_cases(cases, five_point_drop_output, runs=3, judge=judge)
    dropped = decide(degraded, lane="push", baseline_score=baseline.observed_score)

    unchanged_results = [
        decide(
            evaluate_cases(cases, good_output, runs=10, judge=judge),
            lane="full",
            baseline_score=baseline.observed_score,
        )
        for _ in range(10)
    ]

    catastrophic = evaluate_cases(cases, catastrophic_drop_output, runs=3, judge=judge)
    catastrophic = replace(catastrophic, observed_score=baseline.observed_score)
    catastrophic_result = decide(
        catastrophic,
        lane="push",
        baseline_score=baseline.observed_score,
    )

    false_fails = sum(result.verdict == "FAIL" for result in unchanged_results)
    drop_points = (baseline.observed_score - degraded.observed_score) * 100

    if round(drop_points, 1) != 5.0:
        raise AssertionError(f"expected a 5-point injected drop, got {drop_points:.2f}")
    if dropped.verdict != "FAIL":
        raise AssertionError("injected 5-point drop was not caught")
    if false_fails != 0:
        raise AssertionError(f"unchanged-run false FAIL count: {false_fails}")
    if catastrophic_result.verdict != "FAIL":
        raise AssertionError("catastrophic regression was hidden by average score")

    print(
        f"P3 foundation: injected {drop_points:.1f}-pt drop caught | "
        f"0 false FAIL / 10 unchanged runs | "
        f"catastrophic case caught | "
        f"cost={degraded.estimated_cost_usd:.4f} USD + "
        f"runtime={degraded.runtime_minutes:.4f} min"
    )


if __name__ == "__main__":
    run_proof()
