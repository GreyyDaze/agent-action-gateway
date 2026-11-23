import unittest

from agent_action_gateway.eval.evaluator import evaluate_cases
from agent_action_gateway.eval.golden import load_golden_set
from agent_action_gateway.eval.judge import JudgeDecision
from agent_action_gateway.eval.models import GoldenCase

PLANTED_FAILURE_OUTPUT = "__PLANTED_FAILURE__"


class PlantedFailureJudge:
    """Offline semantic judge used only by the planted-failure proof."""

    version = "planted-failure-judge-v1"
    prompt_version = "planted-failure-prompt-v1"

    def evaluate(self, case: GoldenCase, output: object) -> JudgeDecision:
        failed = output == PLANTED_FAILURE_OUTPUT
        return JudgeDecision(
            label="fail" if failed else "pass",
            score=0.0 if failed else 1.0,
            confidence=1.0,
            rationale=(
                "Planted failure marker was detected."
                if failed
                else "Control output passed the planted-failure judge."
            ),
            provider="test",
            model="planted-failure",
            judge_version=self.version,
            prompt_version=self.prompt_version,
        )


def planted_failure_output(case: GoldenCase) -> object:
    """Return a deliberately incorrect output for every canonical case."""
    if case.check_type == "exact":
        return {"__planted_failure__": case.case_id}

    if case.check_type == "field-equality":
        if not isinstance(case.expected, dict):
            return PLANTED_FAILURE_OUTPUT
        return {
            key: "__PLANTED_WRONG_VALUE__"
            for key in case.expected
        }

    if case.check_type == "regex":
        return PLANTED_FAILURE_OUTPUT

    if case.check_type == "rubric":
        return PLANTED_FAILURE_OUTPUT

    raise ValueError(f"unsupported golden check type: {case.check_type}")


class SilentFailureProofTests(unittest.TestCase):
    def test_all_thirty_canonical_cases_have_a_detectable_planted_failure(self) -> None:
        cases = load_golden_set()
        self.assertEqual(len(cases), 30)

        judge = PlantedFailureJudge()
        missed: list[str] = []

        for case in cases:
            summary = evaluate_cases(
                (case,),
                lambda current: planted_failure_output(current),
                runs=1,
                judge=judge,
            )

            if len(summary.samples) != 1 or summary.samples[0].label != "fail":
                missed.append(case.case_id)

        self.assertEqual(missed, [])

    def test_planted_failures_cover_every_check_type(self) -> None:
        cases = load_golden_set()
        check_types = {case.check_type for case in cases}

        self.assertEqual(
            check_types,
            {"exact", "field-equality", "regex", "rubric"},
        )

    def test_planted_field_equality_failure_does_not_match_any_expected_field(self) -> None:
        cases = load_golden_set()

        for case in cases:
            if case.check_type != "field-equality":
                continue

            planted = planted_failure_output(case)

            self.assertIsInstance(case.expected, dict)
            self.assertNotEqual(planted, case.expected)
            self.assertTrue(
                all(
                    planted.get(key) != expected
                    for key, expected in case.expected.items()
                )
            )


if __name__ == "__main__":
    unittest.main()
