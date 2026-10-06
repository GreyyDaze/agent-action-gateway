import tempfile
import unittest
from pathlib import Path

from safety_layer.evaluation_models import (
    Baseline,
    GoldenCase,
    GOLDEN_SET_VERSION,
    JUDGE_PROMPT_VERSION,
    JUDGE_VERSION,
)
from safety_layer.evaluation_store import EvaluationStore
from safety_layer.evaluator import evaluate_cases
from safety_layer.gate import check_compatibility, run_gate
from safety_layer.golden import seed_golden_cases
from safety_layer.judge import JudgeDecision, UnavailableRubricJudge


class StubRubricJudge:
    version = "test-rubric-judge-v1"
    prompt_version = "test-rubric-prompt-v1"

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


def good(case: GoldenCase) -> object:
    if case.check_type == "regex":
        return "refunded successfully"
    return case.expected


def catastrophic(case: GoldenCase) -> object:
    if case.case_id == "tool-001":
        return {"tool": "delete_customer", "arguments": {"id": "C-1"}}
    return good(case)


def baseline(summary, lane: str = "push", judge_version: str | None = None):
    return Baseline(
        lane=lane,
        candidate_version="baseline",
        golden_set_version=GOLDEN_SET_VERSION,
        judge_version=judge_version or summary.judge_version,
        judge_prompt_version=summary.judge_prompt_version,
        score=summary.observed_score,
        cases_evaluated=summary.cases_evaluated,
        runs_per_case=summary.runs_per_case,
        estimated_cost_usd=summary.estimated_cost_usd,
        runtime_minutes=summary.runtime_minutes,
        created_at=summary.created_at,
    )


class Phase3GatePersistenceTest(unittest.TestCase):
    def test_incompatible_judge_version_refuses_comparison(self) -> None:
        summary = evaluate_cases(seed_golden_cases(), good, runs=3, judge=StubRubricJudge())
        compatible, reason = check_compatibility(
            baseline(summary, judge_version="old-judge"),
            summary,
            lane="push",
        )
        self.assertFalse(compatible)
        self.assertIn("judge version", reason)

    def test_judge_unavailable_is_uncertain(self) -> None:
        summary = evaluate_cases(
            seed_golden_cases(), good, runs=3,
            judge=UnavailableRubricJudge("provider unavailable"),
        )
        result = run_gate(summary, baseline(summary), lane="push")
        self.assertEqual(result.verdict, "UNCERTAIN")
        self.assertIn("provider unavailable", result.reason)

    def test_missing_baseline_is_uncertain(self) -> None:
        summary = evaluate_cases(seed_golden_cases(), good, runs=3, judge=StubRubricJudge())
        result = run_gate(summary, None, lane="push")
        self.assertEqual(result.verdict, "UNCERTAIN")

    def test_evaluation_and_false_alarm_are_persisted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = EvaluationStore(Path(directory) / "evaluations.db")
            summary = evaluate_cases(seed_golden_cases(), good, runs=3, judge=StubRubricJudge())
            result = run_gate(
                summary,
                baseline(summary),
                lane="push",
                store=store,
            )
            self.assertEqual(result.verdict, "PASS")
            self.assertEqual(store.false_alarm_count(), 0)

    def test_failed_gate_is_recorded_in_false_alarm_ledger(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = EvaluationStore(Path(directory) / "evaluations.db")
            summary = evaluate_cases(seed_golden_cases(), catastrophic, runs=3, judge=StubRubricJudge())
            result = run_gate(
                summary,
                baseline(summary),
                lane="push",
                store=store,
                unchanged=True,
            )
            self.assertEqual(result.verdict, "FAIL")
            self.assertEqual(store.false_alarm_count(), 1)


if __name__ == "__main__":
    unittest.main()
