import tempfile
import unittest
from pathlib import Path

from safety_layer.providers.mock import MockProvider
from safety_layer.providers.refund_demo_agent import make_refund_agent
from safety_layer.runtime.orchestrator import run
from safety_layer.storage.traces import TraceStore


class SmokeTest(unittest.TestCase):
    def test_full_run_wires_trace_receipt_and_run_status(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = TraceStore(Path(tmp) / "runtime.db")
            result = run(make_refund_agent(MockProvider()), "Process the refund for Ava", store)
            snapshot = store.snapshot()

            self.assertEqual(result["status"], "completed")
            self.assertGreaterEqual(len(snapshot["traces"]), 1)
            self.assertEqual(len(snapshot["receipts"]), 1)
            self.assertEqual(len(snapshot["gate_verdicts"]), 1)
            # A completed run has not been evaluated for quality. Recording
            # PASS here would manufacture durable evidence that no evaluation
            # produced; quality verdicts come from `safety gate check`.
            self.assertEqual(
                snapshot["gate_verdicts"][0]["verdict"], "NOT_EVALUATED"
            )
            self.assertEqual(result["run_status"], "NOT_EVALUATED")

    def test_a_run_that_raises_is_recorded_as_failed(self) -> None:
        def exploding_agent(task: str) -> str:
            raise RuntimeError("agent exploded")

        with tempfile.TemporaryDirectory() as tmp:
            store = TraceStore(Path(tmp) / "runtime.db")
            result = run(exploding_agent, "do a thing", store)

            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["run_status"], "FAIL")
            self.assertEqual(store.snapshot()["gate_verdicts"][0]["verdict"], "FAIL")


if __name__ == "__main__":
    unittest.main()
