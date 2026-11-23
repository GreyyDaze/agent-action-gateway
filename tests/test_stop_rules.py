import tempfile
import unittest
from pathlib import Path

from agent_action_gateway.policy.cross_check import CrossCheckSpec, perform_cross_check
from agent_action_gateway.policy.locks import ApprovalStore, RiskRegistry
from agent_action_gateway.policy.stop_rules import (
    AmbiguityBlockedError,
    ClarificationState,
    CrossEnvironmentError,
    StopPolicy,
    enforce_environment,
)
from agent_action_gateway.proofs.fakes import MockPaymentProvider
from agent_action_gateway.runtime.orchestrator import (
    dispatch_external_action,
    evaluate_tool_result,
    execute_tool,
    run,
)
from agent_action_gateway.storage.traces import TraceStore


class StopRulesTest(unittest.TestCase):
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

    def test_real_tool_result_is_traced_and_requires_cross_check(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = TraceStore(Path(tmp) / "runtime.db")
            decision = evaluate_tool_result(
                store,
                "tool-run-1",
                "find order",
                {},
            )
            self.assertEqual(decision.decision, "CROSS_CHECK")
            traces = [
                event
                for event in store.snapshot()["traces"]
                if event["run_id"] == "tool-run-1"
            ]
            self.assertEqual(traces[-1]["event"], "tool.result")

    def test_real_empty_tool_result_cross_check_disagreement_asks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = TraceStore(Path(tmp) / "runtime.db")
            spec = CrossCheckSpec(
                first_source="orders",
                second_source="audit",
                invariant_name="same-record-set",
                second_source_fn=lambda: {"records": [{"id": "ORD-100"}]},
                invariant=lambda first, second: first == second,
            )
            decision = evaluate_tool_result(
                store,
                "tool-run-2",
                "find order",
                {},
                cross_check=spec,
            )
            self.assertEqual(decision.decision, "ASK")
            self.assertIn("cross-check-disagreement", decision.flags)

    def test_high_stakes_tool_result_requires_second_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = TraceStore(Path(tmp) / "runtime.db")
            decision = evaluate_tool_result(
                store,
                "tool-run-3",
                "read account",
                {"account_id": "A-1"},
                high_stakes=True,
            )
            self.assertEqual(decision.decision, "ASK")

    def test_execute_tool_passes_allowed_result_to_agent_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = TraceStore(Path(tmp) / "runtime.db")
            calls = []

            outcome = execute_tool(
                store,
                "tool-e2e-1",
                "find order",
                lambda: calls.append("tool") or {"order_id": "ORD-100"},
                required_fields=("order_id",),
            )

            self.assertEqual(calls, ["tool"])
            self.assertEqual(outcome["decision"], "CONTINUE")
            self.assertEqual(outcome["result"], {"order_id": "ORD-100"})

    def test_execute_tool_hides_suspicious_result_and_stops(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = TraceStore(Path(tmp) / "runtime.db")
            outcome = execute_tool(
                store,
                "tool-e2e-2",
                "find order",
                lambda: {},
            )

            self.assertEqual(outcome["decision"], "CROSS_CHECK")
            self.assertIsNone(outcome["result"])
            self.assertEqual(outcome["status"], "stopped")

    def test_execute_tool_runs_exactly_one_second_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = TraceStore(Path(tmp) / "runtime.db")
            calls = []
            spec = CrossCheckSpec(
                first_source="orders",
                second_source="audit",
                invariant_name="same-record-set",
                second_source_fn=lambda: calls.append("second") or {},
                invariant=lambda first, second: first == second,
            )

            outcome = execute_tool(
                store,
                "tool-e2e-3",
                "find order",
                lambda: {},
                cross_check=spec,
            )

            self.assertEqual(calls, ["second"])
            self.assertEqual(outcome["decision"], "ASK")
            self.assertIsNone(outcome["result"])

    def test_execute_tool_records_reason_and_cross_check_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = TraceStore(Path(tmp) / "runtime.db")
            spec = CrossCheckSpec(
                first_source="orders",
                second_source="audit",
                invariant_name="same-record-set",
                second_source_fn=lambda: {"records": [{"id": "ORD-100"}]},
                invariant=lambda first, second: first == second,
            )

            outcome = execute_tool(
                store,
                "tool-e2e-4",
                "find order",
                lambda: {},
                cross_check=spec,
            )
            self.assertEqual(outcome["decision"], "ASK")
            traces = [e for e in store.snapshot()["traces"] if e["run_id"] == "tool-e2e-4"]
            evidence = traces[-1]["output"]
            self.assertEqual(evidence["decision"], "ASK")
            self.assertEqual(evidence["cross_check"]["first_source"], "orders")
            self.assertEqual(evidence["cross_check"]["second_source"], "audit")
            self.assertEqual(evidence["cross_check"]["invariant"], "same-record-set")
            self.assertFalse(evidence["cross_check"]["agrees"])


    def test_five_request_clarification_sequence_preserves_budget(self) -> None:
        """Model the five-request adversarial sequence without allowing tool execution on ASK."""
        with tempfile.TemporaryDirectory() as tmp:
            store = TraceStore(Path(tmp) / "runtime.db")
            calls = []

            def agent(task: str) -> str:
                calls.append(task)
                return "executed"

            first = run(
                agent, "vague request 1", store, run_id="five-requests",
                required_inputs={"order_id": None},
            )
            self.assertEqual(first["status"], "needs_clarification")
            self.assertEqual(calls, [])

            second = run(
                agent, "vague request 2", store, run_id="five-requests",
                required_inputs={"order_id": None}, new_turn=True,
            )
            self.assertEqual(second["status"], "needs_clarification")
            self.assertEqual(calls, [])

            third = run(
                agent, "vague request 3", store, run_id="five-requests",
                required_inputs={"order_id": None}, new_turn=True,
            )
            self.assertEqual(third["status"], "completed")
            self.assertEqual(third["attempt"], 2)
            self.assertEqual(calls, ["vague request 3"])

            fourth = run(
                agent, "vague request 4", store, run_id="five-requests",
                required_inputs={"order_id": None}, new_turn=True,
            )
            self.assertEqual(fourth["status"], "completed")
            self.assertEqual(fourth["attempt"], 2)
            self.assertEqual(calls, ["vague request 3", "vague request 4"])

            fifth = run(
                agent, "vague request 5", store, run_id="five-requests",
                required_inputs={"order_id": None}, batch=True,
            )
            self.assertEqual(fifth["status"], "blocked")
            self.assertEqual(calls, ["vague request 3", "vague request 4"])

            persisted = store.load_clarification_state("five-requests")
            self.assertEqual(persisted["attempts"], 2)

    def test_batch_ambiguity_is_blocked_at_run_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = TraceStore(Path(tmp) / "runtime.db")
            calls = []

            result = run(
                lambda task: calls.append(task) or "unsafe",
                "batch refund",
                store,
                run_id="batch-ambiguity",
                required_inputs={"order_id": None},
                batch=True,
            )

            self.assertEqual(result["status"], "blocked")
            self.assertEqual(calls, [])
            self.assertEqual(result["attempt"], 0)

    def test_high_stakes_cross_check_runs_exactly_once(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = TraceStore(Path(tmp) / "runtime.db")
            calls = []
            spec = CrossCheckSpec(
                first_source="accounts",
                second_source="audit",
                invariant_name="same-account",
                second_source_fn=lambda: calls.append("second") or {"account_id": "A-1"},
                invariant=lambda first, second: first == second,
            )

            decision = evaluate_tool_result(
                store,
                "high-stakes-once",
                "read account",
                {"account_id": "A-1"},
                high_stakes=True,
                cross_check=spec,
            )

            self.assertEqual(decision.decision, "CONTINUE")
            self.assertEqual(calls, ["second"])

    def test_empty_result_cross_check_runs_exactly_once(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = TraceStore(Path(tmp) / "runtime.db")
            calls = []
            spec = CrossCheckSpec(
                first_source="orders",
                second_source="audit",
                invariant_name="same-record-set",
                second_source_fn=lambda: calls.append("second") or {},
                invariant=lambda first, second: first == second,
            )

            first = evaluate_tool_result(
                store, "empty-once", "find order", {}, cross_check=spec,
            )
            second = evaluate_tool_result(
                store, "empty-once", "find order", {}, cross_check=spec,
            )

            self.assertEqual(first.decision, "ASK")
            self.assertEqual(second.decision, "ASK")
            self.assertEqual(calls, ["second", "second"])

    def test_legitimate_pagination_does_not_trigger_false_stops(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = TraceStore(Path(tmp) / "runtime.db")
            for page in range(50):
                outcome = execute_tool(
                    store,
                    f"pagination-{page}",
                    f"fetch page {page}",
                    lambda page=page: {"records": [page]},
                    required_fields=("records",),
                )
                self.assertEqual(outcome["decision"], "CONTINUE")
                self.assertEqual(outcome["status"], "allowed")
                self.assertEqual(outcome["result"], {"records": [page]})

    def test_stop_rule_matrix(self) -> None:
        traps = [
            self.policy.missing_input(ClarificationState(), ["order_id"]).decision,
            self.policy.empty_result(cross_check_performed=False).decision,
            self.policy.partial_result({}, ["order_id"], missing_critical=True).decision,
            self.policy.high_stakes_read(second_source_confirmed=False).decision,
        ]
        self.assertEqual(traps, ["ASK", "CROSS_CHECK", "ASK", "ASK"])

        legitimate = [
            self.policy.partial_result({"order_id": "ORD-1"}, [], missing_critical=True).decision,
            self.policy.high_stakes_read(second_source_confirmed=True).decision,
            self.policy.empty_result(cross_check_performed=True).decision,
        ]
        self.assertEqual(legitimate, ["CONTINUE", "CONTINUE", "ASK"])


    def test_stop_rule_proof_matrix(self) -> None:
        """Lock the validation proof set to explicit traps and legitimate paths."""
        traps = [
            ("missing-critical", self.policy.missing_input(
                ClarificationState(), ["order_id"]
            ).decision, "ASK"),
            ("batch-ambiguity", self._batch_missing_input_decision(), "BLOCK"),
            ("empty-result", self.policy.empty_result(
                cross_check_performed=False
            ).decision, "CROSS_CHECK"),
            ("partial-critical", self.policy.partial_result(
                {}, ["order_id"], missing_critical=True
            ).decision, "ASK"),
            ("high-stakes-unconfirmed", self.policy.high_stakes_read(
                second_source_confirmed=False
            ).decision, "ASK"),
            ("cross-check-disagreement", self._disagreement_decision(), "ASK"),
            ("cross-check-disagreement-batch", self._disagreement_decision(
                batch=True
            ), "BLOCK"),
            ("second-clarification-same-turn", self._second_question_decision(), "BLOCK"),
        ]

        legitimate = [
            ("complete-result", self.policy.partial_result(
                {"order_id": "ORD-1"}, [], missing_critical=True
            ).decision, "CONTINUE"),
            ("noncritical-partial", self.policy.partial_result(
                {"order_id": "ORD-1"}, ["optional_note"], missing_critical=False
            ).decision, "REPORT_PARTIAL"),
            ("confirmed-high-stakes", self.policy.high_stakes_read(
                second_source_confirmed=True
            ).decision, "CONTINUE"),
        ]

        missed_traps = [name for name, actual, expected in traps if actual != expected]
        false_stops = [
            name for name, actual, expected in legitimate if actual != expected
        ]

        self.assertEqual(missed_traps, [], f"missed validation traps: {missed_traps}")
        self.assertEqual(false_stops, [], f"false stops on legitimate paths: {false_stops}")
        self.assertEqual(len(missed_traps), 0)
        self.assertEqual(len(false_stops), 0)
        self.assertEqual(len(traps), 8)
        self.assertEqual(len(legitimate), 3)

    def _batch_missing_input_decision(self) -> str:
        try:
            self.policy.missing_input(
                ClarificationState(), ["order_id"], batch=True
            )
        except AmbiguityBlockedError:
            return "BLOCK"
        return "CONTINUE"

    def _disagreement_decision(self, *, batch: bool = False) -> str:
        spec = CrossCheckSpec(
            first_source="orders",
            second_source="audit",
            invariant_name="same-record-set",
            second_source_fn=lambda: {"records": [{"id": "ORD-100"}]},
            invariant=lambda first, second: first == second,
        )
        return self.policy.cross_check_result(
            perform_cross_check({"records": []}, spec),
            batch=batch,
        ).decision

    def _second_question_decision(self) -> str:
        state = ClarificationState()
        self.policy.missing_input(state, ["order_id"])
        try:
            self.policy.missing_input(state, ["order_id"])
        except AmbiguityBlockedError:
            return "BLOCK"
        return "CONTINUE"

    def test_environment_mismatch_is_blocked(self) -> None:
        with self.assertRaises(CrossEnvironmentError):
            enforce_environment("staging", "prod")

    def test_same_environment_is_allowed(self) -> None:
        enforce_environment("prod", "prod")

    def test_invalid_environment_is_rejected(self) -> None:
        # `dev` became a real environment when the adopter-facing session was
        # added; an unknown label must still be rejected outright.
        with self.assertRaises(ValueError):
            enforce_environment("not-an-environment", "prod")
        with self.assertRaises(ValueError):
            enforce_environment("prod", "not-an-environment")

    def test_dev_is_a_real_environment_and_is_isolated(self) -> None:
        enforce_environment("dev", "dev")
        with self.assertRaises(CrossEnvironmentError):
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
