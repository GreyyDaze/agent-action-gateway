import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

from agent_action_gateway.policy.fuses import (
    FuseBudget,
    FuseController,
    FuseLimits,
    FuseTrippedError,
)
from agent_action_gateway.policy.locks import ApprovalStore, RiskRegistry
from agent_action_gateway.proofs.fakes import MockPaymentProvider
from agent_action_gateway.runtime.orchestrator import dispatch_external_action, execute_tool, run
from agent_action_gateway.storage.traces import TraceStore


class FuseTest(unittest.TestCase):
    def test_concurrent_consumption_never_exceeds_step_cap(self) -> None:
        budget = FuseBudget(FuseLimits(max_steps=25))
        successes = 0
        lock = threading.Lock()

        def attempt() -> None:
            nonlocal successes
            try:
                budget.consume_step()
            except FuseTrippedError:
                return
            with lock:
                successes += 1

        with ThreadPoolExecutor(max_workers=100) as pool:
            list(pool.map(lambda _: attempt(), range(100)))

        self.assertEqual(successes, 25)
        self.assertEqual(budget.snapshot().steps_used, 25)

    def test_wall_clock_fuse_trips_at_deadline(self) -> None:
        now = [0.0]
        budget = FuseBudget(
            FuseLimits(max_wall_seconds=10.0),
            clock=lambda: now[0],
        )

        now[0] = 9.999
        budget.check()

        now[0] = 10.0
        with self.assertRaisesRegex(FuseTrippedError, "wall-clock"):
            budget.check()

    def test_spend_fuse_blocks_before_estimated_cost_is_reserved(self) -> None:
        budget = FuseBudget(FuseLimits(max_dollars=1.00))
        budget.consume_step(estimated_cost_usd=0.60)

        with self.assertRaisesRegex(FuseTrippedError, "spend"):
            budget.consume_step(estimated_cost_usd=0.41)

        self.assertEqual(budget.snapshot().dollars_used, 0.60)

    def test_actual_cost_can_reconcile_downward_or_trip_upward(self) -> None:
        budget = FuseBudget(FuseLimits(max_dollars=1.00))
        budget.consume_step(estimated_cost_usd=0.80)
        budget.reconcile_cost(0.80, 0.50)
        self.assertEqual(budget.snapshot().dollars_used, 0.50)

        budget.consume_step(estimated_cost_usd=0.40)
        with self.assertRaisesRegex(FuseTrippedError, "spend"):
            budget.reconcile_cost(0.40, 0.60)

    def test_loop_stops_repeated_action_without_progress(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = TraceStore(Path(tmp) / "runtime.db")
            fuse = FuseController(
                FuseBudget(FuseLimits(max_steps=10, loop_repeat_limit=3))
            )
            calls = []

            for index in range(3):
                outcome = execute_tool(
                    store,
                    "loop-run",
                    "lookup customer",
                    lambda index=index: calls.append(index) or {"empty": True},
                    fuse=fuse,
                    action="lookup_customer",
                    arguments={"customer_id": "C-1"},
                )
                if index < 2:
                    self.assertEqual(outcome["status"], "allowed")
                else:
                    self.assertEqual(outcome["decision"], "FUSE")
                    self.assertIsNone(outcome["result"])

            self.assertEqual(calls, [0, 1])

    def test_pagination_does_not_false_trip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = TraceStore(Path(tmp) / "runtime.db")
            fuse = FuseController(
                FuseBudget(FuseLimits(max_steps=50, loop_repeat_limit=3))
            )

            for page in range(50):
                outcome = execute_tool(
                    store,
                    f"page-{page}",
                    "fetch page",
                    lambda page=page: {"records": [page]},
                    fuse=fuse,
                    action="fetch_page",
                    arguments={"page": page},
                )
                self.assertEqual(outcome["status"], "allowed")
                self.assertEqual(outcome["result"], {"records": [page]})

    def test_fuse_trips_before_dispatch_and_no_action_runs_after_trip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = TraceStore(Path(tmp) / "runtime.db")
            fuse = FuseController(FuseBudget(FuseLimits(max_steps=1)))
            calls = []

            first = execute_tool(
                store,
                "ordering-run",
                "write once",
                lambda: calls.append("first") or {"ok": True},
                fuse=fuse,
                action="write_once",
                arguments={},
            )
            second = execute_tool(
                store,
                "ordering-run",
                "write twice",
                lambda: calls.append("second") or {"ok": True},
                fuse=fuse,
                action="write_twice",
                arguments={},
            )

            self.assertEqual(first["status"], "allowed")
            self.assertEqual(second["decision"], "FUSE")
            self.assertEqual(calls, ["first"])

    def test_runtime_boundary_concurrency_never_exceeds_step_cap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = TraceStore(Path(tmp) / "runtime.db")
            fuse = FuseController(FuseBudget(FuseLimits(max_steps=20)))
            calls = []
            lock = threading.Lock()

            def tool() -> dict[str, bool]:
                with lock:
                    calls.append(True)
                return {"ok": True}

            def attempt(index: int) -> str:
                outcome = execute_tool(
                    store,
                    "runtime-race",
                    f"read-{index}",
                    tool,
                    fuse=fuse,
                    action="read_record",
                    arguments={"id": index},
                )
                return outcome["status"]

            with ThreadPoolExecutor(max_workers=50) as pool:
                statuses = list(pool.map(attempt, range(50)))

            self.assertEqual(statuses.count("allowed"), 20)
            self.assertEqual(len(calls), 20)
            self.assertEqual(fuse.budget.snapshot().steps_used, 20)

    def test_loop_progress_resets_stall_counter(self) -> None:
        detector = FuseController(
            FuseBudget(FuseLimits(loop_repeat_limit=3))
        ).loop_detector

        self.assertFalse(detector.observe("lookup", {"id": "C-1"}))
        self.assertFalse(detector.observe("lookup", {"id": "C-1"}))
        self.assertFalse(
            detector.observe(
                "lookup",
                {"id": "C-1"},
                new_information=True,
            )
        )
        self.assertFalse(detector.observe("lookup", {"id": "C-1"}))
        self.assertFalse(detector.observe("lookup", {"id": "C-1"}))
        self.assertTrue(detector.observe("lookup", {"id": "C-1"}))

    def test_unavailable_fuse_blocks_real_external_write_before_provider(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = TraceStore(Path(tmp) / "runtime.db")
            approvals = ApprovalStore(store)
            registry = RiskRegistry()
            registry.register("refund", "destructive")
            arguments = {"order_id": "ORD-100", "amount": 400}
            approval = approvals.create(
                "refund", arguments, "human-1",
                datetime.now(UTC) + timedelta(days=1),
            )
            provider = MockPaymentProvider(dedupe=True)
            fuse = FuseController(FuseBudget())
            fuse.mark_unavailable()

            with self.assertRaisesRegex(FuseTrippedError, "writes are refused"):
                dispatch_external_action(
                    store, provider, "run-real-action", "step-1",
                    arguments, "ORD-100",
                    registry=registry, approval_store=approvals,
                    approval_id=approval.approval_id, fuse=fuse,
                )

            self.assertEqual(provider.refunds, [])
            self.assertIsNone(approvals.get(approval.approval_id).consumed_at)

    def test_available_fuse_allows_real_external_write_and_counts_step(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = TraceStore(Path(tmp) / "runtime.db")
            approvals = ApprovalStore(store)
            registry = RiskRegistry()
            registry.register("refund", "destructive")
            arguments = {"order_id": "ORD-101", "amount": 200}
            approval = approvals.create(
                "refund", arguments, "human-1",
                datetime.now(UTC) + timedelta(days=1),
            )
            provider = MockPaymentProvider(dedupe=True)
            fuse = FuseController(FuseBudget(FuseLimits(max_steps=1)))

            result = dispatch_external_action(
                store, provider, "run-real-action", "step-1",
                arguments, "ORD-101",
                registry=registry, approval_store=approvals,
                approval_id=approval.approval_id, fuse=fuse,
            )

            self.assertTrue(result.startswith("mock-"))
            self.assertEqual(len(provider.refunds), 1)
            snapshot = fuse.snapshot()
            self.assertEqual(snapshot.steps_used, 1)
            self.assertFalse(snapshot.degraded)
            self.assertFalse(snapshot.tripped)

    def test_degraded_counter_visibility_reports_controller_state(self) -> None:
        fuse = FuseController(FuseBudget(FuseLimits(degraded_read_steps=2)))
        fuse.mark_unavailable()

        snapshot = fuse.snapshot()

        self.assertEqual(snapshot.steps_used, 0)
        self.assertEqual(snapshot.dollars_used, 0.0)
        self.assertTrue(snapshot.degraded)
        self.assertFalse(snapshot.tripped)

    def test_fuse_unavailable_allows_capped_reads_but_blocks_writes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = TraceStore(Path(tmp) / "runtime.db")
            fuse = FuseController(
                FuseBudget(FuseLimits(degraded_read_steps=2))
            )
            fuse.mark_unavailable()

            first = execute_tool(
                store,
                "degraded-run",
                "read one",
                lambda: {"ok": 1},
                fuse=fuse,
                action="read_one",
                arguments={},
            )
            second = execute_tool(
                store,
                "degraded-run",
                "read two",
                lambda: {"ok": 2},
                fuse=fuse,
                action="read_two",
                arguments={},
            )
            third = execute_tool(
                store,
                "degraded-run",
                "read three",
                lambda: {"ok": 3},
                fuse=fuse,
                action="read_three",
                arguments={},
            )
            write = execute_tool(
                store,
                "degraded-run",
                "write",
                lambda: {"ok": True},
                fuse=fuse,
                action="write",
                arguments={},
                write=True,
            )

            self.assertEqual(first["status"], "allowed")
            self.assertEqual(second["status"], "allowed")
            self.assertEqual(third["decision"], "FUSE")
            self.assertEqual(write["decision"], "FUSE")
            self.assertEqual(fuse.degraded, True)

    def test_burn_without_tool_calls_trips_wall_clock(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = TraceStore(Path(tmp) / "runtime.db")
            fuse = FuseController(
                FuseBudget(FuseLimits(max_wall_seconds=0.05))
            )

            def burn(_task: str) -> str:
                while True:
                    pass

            result = run(burn, "burn", store, fuse=fuse)

            self.assertEqual(result["status"], "blocked")
            self.assertIn("wall-clock", result["reason"])

    def test_run_is_blocked_if_wall_clock_budget_is_already_exhausted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = TraceStore(Path(tmp) / "runtime.db")
            now = [0.0]
            fuse = FuseController(
                FuseBudget(
                    FuseLimits(max_wall_seconds=10.0),
                    clock=lambda: now[0],
                )
            )
            now[0] = 10.0
            calls = []

            result = run(
                lambda task: calls.append(task) or "unsafe",
                "long task",
                store,
                fuse=fuse,
            )

            self.assertEqual(result["status"], "blocked")
            self.assertEqual(calls, [])
            self.assertIn("wall-clock", result["reason"])


if __name__ == "__main__":
    unittest.main()
