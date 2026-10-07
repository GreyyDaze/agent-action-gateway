import unittest

from safety_layer.stop_rules import (
    AmbiguityBlockedError,
    ClarificationState,
    CrossEnvironmentError,
    StopPolicy,
    enforce_environment,
)


class Phase4StopRulesTest(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = StopPolicy()

    def test_missing_critical_input_asks_once_per_turn(self) -> None:
        state = ClarificationState()
        first = self.policy.missing_input(state, ["customer_id"])
        self.assertEqual(first.decision, "ASK")

        with self.assertRaises(AmbiguityBlockedError):
            self.policy.missing_input(state, ["customer_id"])

    def test_second_vague_answer_becomes_best_effort_with_caveat(self) -> None:
        state = ClarificationState()
        self.assertEqual(self.policy.missing_input(state, ["customer_id"]).decision, "ASK")
        state.next_turn()
        self.assertEqual(self.policy.missing_input(state, ["customer_id"]).decision, "ASK")
        state.next_turn()

        decision = self.policy.missing_input(state, ["customer_id"])
        self.assertEqual(decision.decision, "BEST_EFFORT_WITH_CAVEAT")
        self.assertIn("customer_id", decision.caveat or "")

    def test_batch_ambiguity_fails_closed(self) -> None:
        with self.assertRaises(AmbiguityBlockedError):
            self.policy.missing_input(
                ClarificationState(),
                ["customer_id"],
                batch=True,
            )

    def test_empty_result_requires_one_cross_check(self) -> None:
        decision = self.policy.empty_result(cross_check_performed=False)
        self.assertEqual(decision.decision, "CROSS_CHECK")
        self.assertTrue(decision.cross_check_required)

        decision = self.policy.empty_result(cross_check_performed=True)
        self.assertEqual(decision.decision, "ASK")
        self.assertIn("empty-result-confirmed", decision.flags)

    def test_batch_empty_result_blocks_after_cross_check(self) -> None:
        decision = self.policy.empty_result(cross_check_performed=True, batch=True)
        self.assertEqual(decision.decision, "BLOCK")

    def test_partial_critical_result_asks(self) -> None:
        decision = self.policy.partial_result(
            {"order": "ORD-100"},
            ["customer_id"],
            missing_critical=True,
        )
        self.assertEqual(decision.decision, "ASK")
        self.assertIn("partial-result", decision.flags)

    def test_partial_noncritical_result_is_reported(self) -> None:
        decision = self.policy.partial_result(
            {"order": "ORD-100"},
            ["optional_note"],
            missing_critical=False,
        )
        self.assertEqual(decision.decision, "REPORT_PARTIAL")

    def test_high_stakes_read_requires_second_source(self) -> None:
        decision = self.policy.high_stakes_read(second_source_confirmed=False)
        self.assertEqual(decision.decision, "ASK")

        decision = self.policy.high_stakes_read(second_source_confirmed=True)
        self.assertEqual(decision.decision, "CONTINUE")

    def test_environment_mismatch_is_blocked(self) -> None:
        with self.assertRaises(CrossEnvironmentError):
            enforce_environment("staging", "prod")

    def test_same_environment_is_allowed(self) -> None:
        enforce_environment("prod", "prod")

    def test_invalid_environment_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            enforce_environment("dev", "prod")


if __name__ == "__main__":
    unittest.main()
