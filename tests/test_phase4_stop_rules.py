import tempfile
import unittest
from pathlib import Path

from safety_layer.cross_check import CrossCheckSpec, perform_cross_check
from safety_layer.runtime import run
from safety_layer.stop_rules import (
    AmbiguityBlockedError,
    ClarificationState,
    CrossEnvironmentError,
    StopPolicy,
    enforce_environment,
)
from safety_layer.locks import ApprovalStore, RiskRegistry
from safety_layer.mock_provider import MockPaymentProvider
from safety_layer.runtime import dispatch_external_action
from safety_layer.store import TraceStore


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

    def test_cross_check_runs_second_source_and_records_invariant(self) -> None:
        calls = []

        spec = CrossCheckSpec(
            first_source="primary-db",
            second_source="replica-db",
            invariant_name="same-record-set",
            second_source_fn=lambda: calls.append("second") or {"records": []},
            invariant=lambda first, second: first == second,
        )

        result = perform_cross_check({"records": []}, spec)

        self.assertEqual(calls, ["second"])
        self.assertTrue(result.agrees)
        self.assertEqual(result.flags, ("cross-check-agreement",))
        self.assertEqual(result.invariant_name, "same-record-set")

    def test_cross_check_disagreement_requires_stop(self) -> None:
        spec = CrossCheckSpec(
            first_source="primary-db",
            second_source="audit-db",
            invariant_name="same-record-set",
            second_source_fn=lambda: {"records": [{"id": "ORD-100"}]},
            invariant=lambda first, second: first == second,
        )

        result = perform_cross_check({"records": []}, spec)
        decision = self.policy.cross_check_result(result)

        self.assertFalse(result.agrees)
        self.assertEqual(decision.decision, "ASK")
        self.assertIn("cross-check-disagreement", decision.flags)

    def test_clarification_state_survives_run_resume(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = TraceStore(Path(tmp) / "runtime.db")
            first = run(
                lambda task: "should not execute",
                "refund request",
                store,
                run_id="resume-1",
                required_inputs={"order_id": None},
            )
            self.assertEqual(first["status"], "needs_clarification")

            second = run(
                lambda task: "should not execute",
                "refund request",
                store,
                run_id="resume-1",
                required_inputs={"order_id": None},
                new_turn=True,
            )
            self.assertEqual(second["status"], "needs_clarification")
            self.assertEqual(second["attempt"], 2)

            persisted = store.load_clarification_state("resume-1")
            self.assertEqual(persisted["attempts"], 2)

            third = run(
                lambda task: "executed only after best effort",
                "refund request",
                store,
                run_id="resume-1",
                required_inputs={"order_id": None},
                new_turn=True,
            )
            self.assertEqual(third["status"], "completed")

    def test_environment_mismatch_is_blocked(self) -> None:
        with self.assertRaises(CrossEnvironmentError):
            enforce_environment("staging", "prod")

    def test_same_environment_is_allowed(self) -> None:
        enforce_environment("prod", "prod")

    def test_invalid_environment_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            enforce_environment("dev", "prod")

    def test_external_dispatch_blocks_cross_environment_before_provider_call(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = TraceStore(Path(tmp) / "runtime.db")
            approvals = ApprovalStore(store)
            registry = RiskRegistry()
            registry.register("lookup_order", "read")
            provider = MockPaymentProvider(dedupe=True)

            with self.assertRaises(CrossEnvironmentError):
                dispatch_external_action(
                    store,
                    provider,
                    "run-env",
                    "step-1",
                    {"order_id": "ORD-100"},
                    "ORD-100",
                    action="lookup_order",
                    registry=registry,
                    approval_store=approvals,
                    session_environment="staging",
                    target_environment="prod",
                )

            self.assertEqual(provider.refunds, [])


    def test_run_stops_and_records_missing_input(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = TraceStore(Path(tmp) / "runtime.db")
            result = run(
                lambda task: "should not execute",
                "refund request",
                store,
                required_inputs={"order_id": None},
            )
            self.assertEqual(result["status"], "needs_clarification")
            events = [e for e in store.snapshot()["traces"] if e["run_id"] == result["run_id"]]
            self.assertEqual(events[-1]["status"], "ask")

    def test_run_batch_ambiguity_blocks_and_records(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = TraceStore(Path(tmp) / "runtime.db")
            result = run(
                lambda task: "should not execute",
                "refund request",
                store,
                required_inputs={"order_id": None},
                batch=True,
            )
            self.assertEqual(result["status"], "blocked")
            events = [e for e in store.snapshot()["traces"] if e["run_id"] == result["run_id"]]
            self.assertEqual(events[-1]["status"], "blocked")


if __name__ == "__main__":
    unittest.main()
