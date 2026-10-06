import unittest
from dataclasses import replace

from safety_layer.evaluation_models import GoldenCase
from safety_layer.evaluator import evaluate_cases
from safety_layer.golden import seed_golden_cases
from safety_layer.verdict import decide


def good(case: GoldenCase) -> object:
    if case.check_type == "regex":
        return "refunded successfully"
    return case.expected


class Phase3GateTest(unittest.TestCase):
    def test_seed_contains_thirty_cases_and_catastrophic_case(self) -> None:
        cases = seed_golden_cases()
        self.assertEqual(len(cases), 30)
        self.assertTrue(any(case.catastrophic for case in cases))

    def test_deterministic_checks_produce_stable_baseline(self) -> None:
        summary = evaluate_cases(seed_golden_cases(), good, runs=3)
        self.assertEqual(summary.observed_score, 1.0)
        self.assertEqual(summary.noise_estimate, 0.0)

    def test_injected_five_point_drop_fails(self) -> None:
        cases = seed_golden_cases()

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
        cases = seed_golden_cases()

        def catastrophic(case: GoldenCase) -> object:
            if case.case_id == "tool-001":
                return {"tool": "delete_customer", "arguments": {"id": "C-1"}}
            return good(case)

        summary = evaluate_cases(cases, catastrophic, runs=3)
        summary = replace(summary, observed_score=1.0)
        result = decide(summary, lane="push", baseline_score=1.0)
        self.assertEqual(result.verdict, "FAIL")

    def test_judge_and_prompt_versions_are_pinned(self) -> None:
        summary = evaluate_cases(seed_golden_cases(), good, runs=3)
        self.assertTrue(summary.judge_version)
        self.assertTrue(summary.judge_prompt_version)

    def test_push_and_full_lanes_require_defined_run_counts(self) -> None:
        push = evaluate_cases(seed_golden_cases(), good, runs=3)
        full = evaluate_cases(seed_golden_cases(), good, runs=10)
        self.assertEqual(decide(push, lane="push", baseline_score=1.0).runs_per_case, 3)
        self.assertEqual(decide(full, lane="full", baseline_score=1.0).runs_per_case, 10)

    def test_cost_and_runtime_are_reported(self) -> None:
        summary = evaluate_cases(
            seed_golden_cases(),
            good,
            runs=3,
            estimated_cost_per_sample=0.01,
        )
        result = decide(summary, lane="push", baseline_score=1.0)
        self.assertEqual(result.estimated_cost_usd, 0.9)
        self.assertGreaterEqual(result.runtime_minutes, 0.0)


if __name__ == "__main__":
    unittest.main()
