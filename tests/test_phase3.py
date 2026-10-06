import unittest
from dataclasses import replace

from safety_layer.calibration import load_calibration_set
from safety_layer.evaluation_models import GoldenCase
from safety_layer.evaluator import evaluate_cases
from safety_layer.golden import load_golden_set, seed_golden_cases
from safety_layer.judge import is_deterministic
from safety_layer.verdict import decide


def deterministic_cases() -> tuple[GoldenCase, ...]:
    return tuple(case for case in seed_golden_cases() if is_deterministic(case))


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

            def score(self, case: GoldenCase, output: object) -> float:
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
        class StubJudge:
            version = "rubric-judge-test"
            prompt_version = "rubric-prompt-test"

            def score(self, case: GoldenCase, output: object) -> float:
                return 1.0 if output == "acceptable" else 0.0

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
            judge=StubJudge(),
        )
        self.assertEqual(summary.observed_score, 1.0)
        self.assertEqual(summary.judge_version, "rubric-judge-test")

    def test_injected_five_point_drop_fails(self) -> None:
        cases = deterministic_cases()

        def degraded(case: GoldenCase) -> object:
            if case.case_id == "refund-002":
                return {"order_id": "ORD-WRONG", "status": "failed"}
            if case.case_id == "refund-006":
                return {"order_id": "ORD-006", "status": "wrong"}
            return good(case)

        summary = evaluate_cases(cases, degraded, runs=3)
        result = decide(summary, lane="push", baseline_score=1.0)
        self.assertAlmostEqual((1.0 - summary.observed_score) * 100, 5.0)
        self.assertEqual(result.verdict, "FAIL")

    def test_catastrophic_failure_is_red_even_when_average_is_flat(self) -> None:
        cases = deterministic_cases()

        def catastrophic(case: GoldenCase) -> object:
            if case.case_id == "tool-001":
                return {"tool": "delete_customer", "arguments": {"id": "C-1"}}
            return good(case)

        summary = evaluate_cases(cases, catastrophic, runs=3)
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

    def test_cost_and_runtime_are_reported(self) -> None:
        summary = evaluate_cases(
            deterministic_cases(),
            good,
            runs=3,
            estimated_cost_per_sample=0.01,
        )
        result = decide(summary, lane="push", baseline_score=1.0)
        self.assertEqual(result.estimated_cost_usd, 0.81)
        self.assertGreaterEqual(result.runtime_minutes, 0.0)


if __name__ == "__main__":
    unittest.main()
