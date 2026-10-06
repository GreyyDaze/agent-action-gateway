import unittest
from dataclasses import replace

from safety_layer.calibration import load_calibration_set, run_calibration
from safety_layer.evaluation_models import CALIBRATION_MIN_AGREEMENT, CalibrationResult, GoldenCase
from safety_layer.evaluator import evaluate_cases
from safety_layer.golden import load_golden_set, seed_golden_cases
from safety_layer.judge import JudgeDecision, UnavailableRubricJudge, is_deterministic
from safety_layer.verdict import decide


def deterministic_cases() -> tuple[GoldenCase, ...]:
    return tuple(case for case in seed_golden_cases() if is_deterministic(case))


class StubRubricJudge:
    version = "test-rubric-judge-v1"
    prompt_version = "test-rubric-prompt-v1"

    def evaluate(self, case: GoldenCase, output: object) -> JudgeDecision:
        # Calibration examples contain human labels, so this test stub mirrors
        # those labels instead of comparing semantic text to case.expected.
        if case.check_type == "rubric":
            calibration = {
                (
                    example.case_id,
                    example.output,
                ): example.label
                for example in load_calibration_set()
            }
            label = calibration.get((case.case_id, output))
            if label is None:
                label = "pass" if output == case.expected else "fail"
        else:
            label = "pass" if output == case.expected else "fail"

        passed = label == "pass"
        return JudgeDecision(
            label=label,
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


class Phase3GateTest(unittest.TestCase):
    def test_canonical_golden_set_is_versioned_and_validated(self) -> None:
        cases = load_golden_set()
        self.assertEqual(len(cases), 30)
        self.assertTrue(any(case.catastrophic for case in cases))
        self.assertEqual(cases[0].case_id, "refund-001")

    def test_semantic_cases_and_calibration_examples_are_present(self) -> None:
        cases = load_golden_set()
        semantic_ids = {
            case.case_id for case in cases if case.check_type == "rubric"
        }
        self.assertEqual(
            semantic_ids,
            {
                "refund-semantic-001",
                "safety-semantic-001",
                "support-semantic-001",
            },
        )

        calibration = load_calibration_set()
        self.assertEqual(len(calibration), 6)
        self.assertEqual(
            {example.label for example in calibration},
            {"pass", "fail"},
        )
        self.assertEqual(
            {example.case_id for example in calibration},
            semantic_ids,
        )

    def test_seed_contains_thirty_cases_and_catastrophic_case(self) -> None:
        cases = seed_golden_cases()
        self.assertEqual(len(cases), 30)
        self.assertTrue(any(case.catastrophic for case in cases))

    def test_deterministic_checks_do_not_call_optional_judge(self) -> None:
        class ExplodingJudge:
            version = "should-not-run"
            prompt_version = "should-not-run"

            def evaluate(self, case: GoldenCase, output: object) -> JudgeDecision:
                raise AssertionError("deterministic case reached the optional judge")

        summary = evaluate_cases(
            deterministic_cases(),
            good,
            runs=1,
            judge=ExplodingJudge(),
        )
        self.assertEqual(summary.observed_score, 1.0)

    def test_rubric_case_requires_explicit_judge(self) -> None:
        case = GoldenCase(
            "rubric-001",
            "Assess the response",
            "acceptable",
            "rubric",
            "test",
        )
        with self.assertRaisesRegex(ValueError, "require an explicit"):
            evaluate_cases((case,), lambda _: "acceptable", runs=1)

    def test_rubric_case_uses_supplied_judge(self) -> None:
        case = GoldenCase(
            "rubric-001",
            "Assess the response",
            "acceptable",
            "rubric",
            "test",
        )
        summary = evaluate_cases(
            (case,),
            lambda _: "acceptable",
            runs=1,
            judge=StubRubricJudge(),
        )
        self.assertEqual(summary.observed_score, 1.0)
        self.assertEqual(summary.judge_version, "test-rubric-judge-v1")

    def test_injected_five_point_drop_fails(self) -> None:
        cases = seed_golden_cases()

        def degraded(case: GoldenCase) -> object:
            if case.case_id == "refund-002":
                return {"order_id": "ORD-WRONG", "status": "failed"}
            if case.case_id == "refund-006":
                return {"order_id": "ORD-006", "status": "wrong"}
            return good(case)

        summary = evaluate_cases(cases, degraded, runs=3, judge=StubRubricJudge())
        result = decide(summary, lane="push", baseline_score=1.0)
        # This fixture is intentionally constructed to produce a 5-point drop.
        # The important proof is that the regression is rejected.
        self.assertAlmostEqual((1.0 - summary.observed_score) * 100, 5.0)
        self.assertEqual(result.verdict, "FAIL")

    def test_ten_unchanged_runs_have_zero_false_failures(self) -> None:
        cases = seed_golden_cases()
        results = [
            decide(
                evaluate_cases(cases, good, runs=10, judge=StubRubricJudge()),
                lane="full",
                baseline_score=1.0,
            )
            for _ in range(10)
        ]
        self.assertEqual([result.verdict for result in results], ["PASS"] * 10)
        self.assertEqual(sum(result.verdict == "FAIL" for result in results), 0)

    def test_catastrophic_failure_is_red_even_when_average_is_flat(self) -> None:
        cases = seed_golden_cases()

        def catastrophic(case: GoldenCase) -> object:
            if case.case_id == "tool-001":
                return {"tool": "delete_customer", "arguments": {"id": "C-1"}}
            return good(case)

        summary = evaluate_cases(cases, catastrophic, runs=3, judge=StubRubricJudge())
        summary = replace(summary, observed_score=1.0)
        result = decide(summary, lane="push", baseline_score=1.0)
        self.assertEqual(result.verdict, "FAIL")

    def test_judge_and_prompt_versions_are_pinned(self) -> None:
        summary = evaluate_cases(deterministic_cases(), good, runs=3)
        self.assertTrue(summary.judge_version)
        self.assertTrue(summary.judge_prompt_version)

    def test_push_and_full_lanes_require_defined_run_counts(self) -> None:
        push = evaluate_cases(deterministic_cases(), good, runs=3)
        full = evaluate_cases(deterministic_cases(), good, runs=10)
        self.assertEqual(decide(push, lane="push", baseline_score=1.0).runs_per_case, 3)
        self.assertEqual(decide(full, lane="full", baseline_score=1.0).runs_per_case, 10)

    def test_provider_unavailable_is_recorded_without_a_pass(self) -> None:
        summary = evaluate_cases(
            seed_golden_cases(),
            good,
            runs=3,
            judge=UnavailableRubricJudge("provider timeout"),
        )
        self.assertFalse(summary.judge_available)
        self.assertIn("provider timeout", summary.judge_error)
        self.assertEqual(summary.observed_score, 0.0)


    def test_calibration_acceptance_requires_configured_threshold(self) -> None:
        self.assertEqual(CALIBRATION_MIN_AGREEMENT, 1.0)
        accepted = CalibrationResult(
            total=6,
            agreed=6,
            agreement=1.0,
            judge_version="test",
            judge_prompt_version="test",
            estimated_cost_usd=0.0,
            runtime_seconds=0.0,
        )
        rejected = CalibrationResult(
            total=6,
            agreed=5,
            agreement=5 / 6,
            judge_version="test",
            judge_prompt_version="test",
            estimated_cost_usd=0.0,
            runtime_seconds=0.0,
        )
        self.assertTrue(accepted.accepted)
        self.assertFalse(rejected.accepted)

    def test_calibration_runner_reports_human_agreement(self) -> None:
        result = run_calibration(seed_golden_cases(), StubRubricJudge())
        self.assertEqual(result.total, 6)
        self.assertEqual(result.agreed, 6)
        self.assertTrue(result.accepted)

    def test_cost_and_runtime_are_reported(self) -> None:
        summary = evaluate_cases(
            deterministic_cases(),
            good,
            runs=3,
        )
        result = decide(summary, lane="push", baseline_score=1.0)
        self.assertEqual(result.estimated_cost_usd, 0.0)
        self.assertGreaterEqual(result.runtime_minutes, 0.0)


if __name__ == "__main__":
    unittest.main()
