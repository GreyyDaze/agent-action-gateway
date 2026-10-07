import tempfile
import unittest
from pathlib import Path

from safety_layer.models import TraceEvent
from safety_layer.phase6_trace import (
    classify_capture,
    honest_status,
    redact,
    suspicious_flags,
)
from safety_layer.store import TraceStore


class Phase6TraceTests(unittest.TestCase):
    def test_silent_wrong_signals_are_recorded(self) -> None:
        flags = suspicious_flags(invariant_failed=True)
        self.assertIn("invariant-failed", flags)
        decision = classify_capture(event="phase4.tool_result", flags=flags)
        self.assertTrue(decision.capture)
        self.assertEqual(decision.capture_class, "always")

    def test_routine_reads_can_be_sampled_but_writes_cannot(self) -> None:
        sampled = classify_capture(
            event="tool.read",
            risk="read",
            sample_routine_reads=True,
            routine_read_sample=False,
        )
        self.assertFalse(sampled.capture)

        write = classify_capture(
            event="tool.write",
            risk="write",
            sample_routine_reads=True,
            routine_read_sample=False,
        )
        self.assertTrue(write.capture)

    def test_redaction_happens_before_storage(self) -> None:
        payload = {
            "api_key": "secret-value",
            "email": "alice@example.com",
            "nested": {"authorization": "Bearer super-secret"},
        }
        cleaned = redact(payload)
        self.assertEqual(cleaned["api_key"], "[REDACTED_SECRET]")
        self.assertEqual(cleaned["email"], "[REDACTED_PII]")
        self.assertEqual(cleaned["nested"]["authorization"], "[REDACTED_SECRET]")

    def test_store_never_keeps_secret_or_pii(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = TraceStore(Path(directory) / "trace.db")
            store.append_trace(
                TraceEvent(
                    "run-1",
                    1,
                    "write",
                    {"email": "alice@example.com", "token": "secret-token-value"},
                    {"authorization": "Bearer abc"},
                    "ok",
                    flags=("write",),
                )
            )
            snapshot = store.snapshot()
            raw = str(snapshot["traces"][0])
            self.assertNotIn("alice@example.com", raw)
            self.assertNotIn("secret-token-value", raw)
            self.assertNotIn("Bearer abc", raw)

    def test_honest_status_never_uses_agent_success_claim(self) -> None:
        self.assertEqual(honest_status(), "ok")
        self.assertEqual(honest_status(suspicious=True), "degraded")
        self.assertEqual(honest_status(blocked=True), "blocked")
        self.assertEqual(honest_status(error=True), "degraded")


if __name__ == "__main__":
    unittest.main()
