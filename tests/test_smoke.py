import tempfile
import unittest
from pathlib import Path

from agent_action_gateway import session
from agent_action_gateway.storage.traces import TraceStore


def restart_agent(task: str) -> dict[str, str]:
    """A minimal agent: it reports one completed action."""
    return {"status": "restarted", "service": "api"}


class SmokeTest(unittest.TestCase):
    def test_full_run_is_recorded_and_reports_completed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = TraceStore(Path(tmp) / "runtime.db")
            with session(store=store) as ctx:
                result = ctx.run(restart_agent, "Restart the api service")
            events = [t["event"] for t in store.snapshot()["traces"]]

            self.assertEqual(result["status"], "completed")
            self.assertEqual(result["enforcement"], "enforced")
            self.assertIn("session.start", events)
            self.assertIn("session.end", events)

    def test_run_records_its_budget_for_the_dashboard(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = TraceStore(Path(tmp) / "runtime.db")
            with session(store=store) as ctx:
                result = ctx.run(restart_agent, "Restart the api service")
            budgets = store.dashboard_snapshot()["budgets"]
            self.assertEqual([b["run_id"] for b in budgets], [result["run_id"]])

    def test_a_run_that_raises_is_recorded_as_failed(self) -> None:
        def exploding_agent(task: str) -> str:
            raise RuntimeError("agent exploded")

        with tempfile.TemporaryDirectory() as tmp:
            store = TraceStore(Path(tmp) / "runtime.db")
            with session(store=store) as ctx:
                result = ctx.run(exploding_agent, "do a thing")

            self.assertEqual(result["status"], "failed")
            failed = [t for t in store.snapshot()["traces"] if t["status"] == "failed"]
            self.assertTrue(failed, "the failure must be recorded")


if __name__ == "__main__":
    unittest.main()
