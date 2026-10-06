import tempfile
import unittest
from pathlib import Path

from safety_layer.mock_provider import MockProvider
from safety_layer.refund_agent import make_refund_agent
from safety_layer.runtime import run
from safety_layer.store import TraceStore


class Phase0SmokeTest(unittest.TestCase):
    def test_full_run_wires_trace_receipt_and_gate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = TraceStore(Path(tmp) / "runtime.db")
            result = run(make_refund_agent(MockProvider()), "Process the refund for Ava", store)
            snapshot = store.snapshot()

            self.assertEqual(result["status"], "completed")
            self.assertGreaterEqual(len(snapshot["traces"]), 1)
            self.assertEqual(len(snapshot["receipts"]), 1)
            self.assertEqual(len(snapshot["gate_verdicts"]), 1)
            self.assertEqual(snapshot["gate_verdicts"][0]["verdict"], "PASS")


if __name__ == "__main__":
    unittest.main()
