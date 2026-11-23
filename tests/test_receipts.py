import tempfile
import unittest
from pathlib import Path

from agent_action_gateway.audit.receipts import execute_side_effect, resolve_unknown
from agent_action_gateway.proofs.fakes import MockEffectProvider
from agent_action_gateway.storage.traces import TraceStore


class ReceiptLifecycleTest(unittest.TestCase):
    def test_write_before_and_idempotent_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = TraceStore(Path(tmp) / "runtime.db")
            receipt = store.create_receipt("run-1", "step-1", "external_action", {"deployment_id": "DEP-100"})
            same = store.create_receipt("run-1", "step-1", "external_action", {"deployment_id": "DEP-100"})
            self.assertEqual(receipt.intent_key, "run-1:step-1")
            self.assertEqual(receipt.receipt_id, same.receipt_id)
            self.assertEqual(receipt.state, "unknown")

    def test_dedupe_and_no_dedupe_modes_share_the_same_intent_key(self):
        dedupe = MockEffectProvider(dedupe=True)
        first = dedupe.execute("DEP-100", "run-1:step-1")
        second = dedupe.execute("DEP-100", "run-1:step-1")
        self.assertEqual(first, second)
        self.assertEqual(len(dedupe.rollbacks), 1)

        no_dedupe = MockEffectProvider(dedupe=False)
        first = no_dedupe.execute("DEP-100", "run-1:step-1")
        second = no_dedupe.execute("DEP-100", "run-1:step-1")
        self.assertNotEqual(first, second)
        self.assertEqual(len(no_dedupe.rollbacks), 2)

    def test_timeout_after_provider_acceptance_resolves_without_retry(self):
        class TimeoutProvider(MockEffectProvider):
            def execute(self, target: str, intent_key: str) -> str:
                _ = super().execute(target, intent_key)
                raise TimeoutError("response lost after provider accepted request")

        with tempfile.TemporaryDirectory() as tmp:
            store = TraceStore(Path(tmp) / "runtime.db")
            provider = TimeoutProvider(dedupe=False)
            with self.assertRaises(TimeoutError):
                execute_side_effect(
                    store,
                    provider,
                    "run-timeout",
                    "step-1",
                    {"deployment_id": "DEP-100"},
                    "DEP-100",
                )
            resolve_unknown(store, provider)
            self.assertEqual(len(provider.rollbacks), 1)
            self.assertEqual(len(store.unknown_receipts()), 0)

    def test_unknown_provider_result_is_resolved_before_retry(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = TraceStore(Path(tmp) / "runtime.db")
            provider = MockEffectProvider(dedupe=False)
            receipt = store.create_receipt("run-2", "step-1", "external_action", {"target": "DEP-100"})
            provider_ref = provider.execute("DEP-100", receipt.intent_key)
            resolve_unknown(store, provider)
            self.assertEqual(len(provider.rollbacks), 1)
            self.assertEqual(store.snapshot()["receipts"][0]["provider_ref"], provider_ref)
            self.assertEqual(store.snapshot()["receipts"][0]["state"], "resolved")


if __name__ == "__main__":
    unittest.main()
