import tempfile
import unittest
from pathlib import Path

from safety_layer.models import TraceEvent
from safety_layer.trace import (
    classify_capture,
    honest_status,
    redact,
    suspicious_flags,
)
from safety_layer.store import TraceStore


class TraceEvidenceTests(unittest.TestCase):
    def test_silent_wrong_signals_are_recorded(self) -> None:
        flags = suspicious_flags(invariant_failed=True)
        self.assertIn("invariant-failed", flags)
        decision = classify_capture(event="tool.result", flags=flags)
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

    def test_provider_evidence_is_persisted_and_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = TraceStore(Path(directory) / "trace.db")
            trace_id = store.append_trace(
                TraceEvent(
                    "run-provider",
                    1,
                    "provider.call",
                    {"prompt": "x"},
                    {"ok": True},
                    "ok",
                    provider_evidence={
                        "provider": "example",
                        "provider_version": "v1",
                        "model": "model-a",
                        "response_status": 200,
                        "response_headers": {
                            "x-request-id": "safe-id",
                            "authorization": "Bearer secret",
                        },
                    },
                )
            )

            trace = store.snapshot()["traces"][0]
            self.assertEqual(trace["id"], trace_id)
            self.assertEqual(trace["provider_evidence"]["provider"], "example")
            self.assertEqual(trace["provider_evidence"]["provider_version"], "v1")
            self.assertEqual(trace["provider_evidence"]["response_status"], 200)
            self.assertEqual(
                trace["provider_evidence"]["response_headers"]["authorization"],
                "[REDACTED_SECRET]",
            )

    def test_replay_creates_new_trace_and_preserves_original_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = TraceStore(Path(directory) / "trace.db")
            original_id = store.append_trace(
                TraceEvent(
                    "run-original",
                    2,
                    "provider.call",
                    {"request": "original"},
                    {"error": {"type": "TimeoutError"}},
                    "failed",
                    flags=("provider-timeout",),
                    provider_evidence={"provider": "example", "response_status": 504},
                )
            )

            replay_id = store.append_replay(
                original_id,
                TraceEvent(
                    "run-replay",
                    2,
                    "provider.call",
                    {"request": "original"},
                    {"ok": True},
                    "ok",
                    provider_evidence={"provider": "example", "response_status": 200},
                ),
            )

            traces = store.snapshot()["traces"]
            original = next(trace for trace in traces if trace["id"] == original_id)
            replay = next(trace for trace in traces if trace["id"] == replay_id)

            self.assertEqual(original["status"], "failed")
            self.assertEqual(original["output"], {"error": {"type": "TimeoutError"}})
            self.assertIsNone(original["replay_of_trace_id"])
            self.assertEqual(replay["status"], "ok")
            self.assertEqual(replay["replay_of_trace_id"], original_id)
            self.assertNotEqual(replay["id"], original_id)

    def test_honest_status_never_uses_agent_success_claim(self) -> None:
        self.assertEqual(honest_status(), "ok")
        self.assertEqual(honest_status(suspicious=True), "degraded")
        self.assertEqual(honest_status(blocked=True), "blocked")
        self.assertEqual(honest_status(error=True), "degraded")



class FailureWallGroupingTests(unittest.TestCase):
    def test_same_error_step_and_config_are_one_group(self) -> None:
        from safety_layer.trace import build_failure_wall
        traces = [
            {"id": 1, "run_id": "run-1", "step": 4, "event": "tool.execute", "status": "failed",
             "output": {"error": {"type": "TimeoutError"}},
             "provider_metadata": {"config": {"model": "m1", "timeout": 10}}},
            {"id": 2, "run_id": "run-2", "step": 4, "event": "tool.execute", "status": "failed",
             "output": {"error": {"type": "TimeoutError"}},
             "provider_metadata": {"config": {"timeout": 10, "model": "m1"}}},
        ]
        groups = build_failure_wall(traces)
        self.assertEqual(len(groups), 1)
        self.assertEqual(len(groups[0].records), 2)

    def test_different_config_does_not_merge(self) -> None:
        from safety_layer.trace import build_failure_wall
        traces = [
            {"id": 1, "run_id": "run-1", "step": 4, "event": "tool.execute", "status": "failed",
             "output": {"error": {"type": "TimeoutError"}},
             "provider_metadata": {"config": {"model": "m1"}}},
            {"id": 2, "run_id": "run-2", "step": 4, "event": "tool.execute", "status": "failed",
             "output": {"error": {"type": "TimeoutError"}},
             "provider_metadata": {"config": {"model": "m2"}}},
        ]
        self.assertEqual(len(build_failure_wall(traces)), 2)

    def test_silent_wrong_run_is_grouped(self) -> None:
        from safety_layer.trace import build_failure_wall
        traces = [
            {"id": 1, "run_id": "run-1", "step": 3, "event": "tool.result", "status": "completed",
             "flags": ["empty-result"], "provider_metadata": {"config": {"model": "m1"}}},
            {"id": 2, "run_id": "run-2", "step": 3, "event": "tool.result", "status": "completed",
             "flags": ["empty-result"], "provider_metadata": {"config": {"model": "m1"}}},
        ]
        groups = build_failure_wall(traces)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0].signature.error_type, "silent-wrong:empty-result")

    def test_confirmation_keeps_ownership_unknown(self) -> None:
        from safety_layer.trace import build_failure_wall, confirm_failure_group
        group = build_failure_wall([{"id": 1, "run_id": "run-1", "step": 1, "event": "tool",
            "status": "failed", "output": {"error": {"type": "ValueError"}}}])[0]
        confirm_failure_group(group)
        self.assertEqual(group.state, "confirmed")
        self.assertEqual(group.ownership, "unknown")

    def test_human_can_merge_groups(self) -> None:
        from safety_layer.trace import build_failure_wall, merge_failure_groups
        first = build_failure_wall([{"id": 1, "run_id": "run-1", "step": 1, "event": "tool-a",
            "status": "failed", "output": {"error": {"type": "ValueError"}}}])[0]
        second = build_failure_wall([{"id": 2, "run_id": "run-2", "step": 2, "event": "tool-b",
            "status": "failed", "output": {"error": {"type": "ValueError"}}}])[0]
        merged = merge_failure_groups([first, second])
        self.assertEqual(len(merged.records), 2)
        self.assertEqual(merged.ownership, "unknown")

    def test_human_can_split_group(self) -> None:
        from safety_layer.trace import build_failure_wall, merge_failure_groups, split_failure_group
        traces = [
            {"id": 1, "run_id": "run-1", "step": 1, "event": "tool-a", "status": "failed",
             "output": {"error": {"type": "ValueError"}}, "provider_metadata": {"config": {"model": "m1"}}},
            {"id": 2, "run_id": "run-2", "step": 2, "event": "tool-b", "status": "failed",
             "output": {"error": {"type": "ValueError"}}, "provider_metadata": {"config": {"model": "m1"}}},
        ]
        groups = build_failure_wall(traces)
        split = split_failure_group(merge_failure_groups(groups), [g.signature for g in groups])
        self.assertEqual(len(split), 2)
        self.assertEqual({len(group.records) for group in split}, {1})


class FailureWallPersistenceTests(unittest.TestCase):
    def _group(self, trace_id: int, run_id: str, error: str = "TimeoutError"):
        from safety_layer.trace import build_failure_wall

        return build_failure_wall([{
            "id": trace_id,
            "run_id": run_id,
            "step": 4,
            "event": "tool.execute",
            "status": "failed",
            "output": {"error": {"type": error}},
            "provider_metadata": {"config": {"model": "m1"}},
        }])[0]

    def test_group_survives_store_reopen(self) -> None:
        from safety_layer.failure_wall_store import FailureWallStore

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "failure-wall.db"
            group = self._group(101, "run-101")
            FailureWallStore(path).save_group(group)

            reopened = FailureWallStore(path).get_group(group.group_id)

            self.assertIsNotNone(reopened)
            assert reopened is not None
            self.assertEqual(reopened.signature, group.signature)
            self.assertEqual(reopened.records, group.records)
            self.assertEqual(reopened.state, "unconfirmed")
            self.assertEqual(reopened.ownership, "unknown")

    def test_confirmation_is_persistent_and_audited(self) -> None:
        from safety_layer.failure_wall_store import FailureWallStore

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "failure-wall.db"
            group = self._group(102, "run-102")
            store = FailureWallStore(path)
            store.save_group(group)

            store.confirm(group.group_id)
            reopened = FailureWallStore(path).get_group(group.group_id)

            self.assertIsNotNone(reopened)
            assert reopened is not None
            self.assertEqual(reopened.state, "confirmed")
            self.assertEqual(reopened.ownership, "unknown")
            self.assertEqual(FailureWallStore(path).decisions(group.group_id)[0]["decision"], "confirm")

    def test_reject_is_persistent_and_audited(self) -> None:
        from safety_layer.failure_wall_store import FailureWallStore

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "failure-wall.db"
            group = self._group(103, "run-103")
            store = FailureWallStore(path)
            store.save_group(group)

            store.reject(group.group_id)
            reopened = FailureWallStore(path).get_group(group.group_id)

            self.assertIsNotNone(reopened)
            assert reopened is not None
            self.assertEqual(reopened.state, "rejected")
            self.assertEqual(reopened.ownership, "unknown")
            self.assertEqual(FailureWallStore(path).decisions(group.group_id)[0]["decision"], "reject")

    def test_merge_persists_both_evidence_and_marks_sources_merged(self) -> None:
        from safety_layer.failure_wall_store import FailureWallStore
        from safety_layer.trace import merge_failure_groups

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "failure-wall.db"
            store = FailureWallStore(path)
            first = self._group(104, "run-104", "TimeoutError")
            second = self._group(105, "run-105", "ValueError")
            store.save_groups([first, second])

            merged = merge_failure_groups([first, second])
            store.merge([first.group_id, second.group_id], merged)

            reopened = FailureWallStore(path).get_group(merged.group_id)
            self.assertIsNotNone(reopened)
            assert reopened is not None
            self.assertEqual({r.trace_id for r in reopened.records}, {104, 105})
            self.assertEqual(FailureWallStore(path).get_group(first.group_id).state, "merged")
            self.assertEqual(FailureWallStore(path).get_group(second.group_id).state, "merged")
            self.assertEqual(FailureWallStore(path).decisions(first.group_id)[0]["decision"], "merge")

    def test_split_persists_result_groups_and_marks_source_split(self) -> None:
        from safety_layer.failure_wall_store import FailureWallStore
        from safety_layer.trace import merge_failure_groups, split_failure_group

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "failure-wall.db"
            store = FailureWallStore(path)
            first = self._group(106, "run-106", "TimeoutError")
            second = self._group(107, "run-107", "ValueError")
            merged = merge_failure_groups([first, second])
            store.save_group(merged)

            split = split_failure_group(merged, [first.signature, second.signature])
            store.split(merged.group_id, split)

            self.assertEqual(FailureWallStore(path).get_group(merged.group_id).state, "split")
            self.assertEqual(len(FailureWallStore(path).get_group(first.group_id).records), 1)
            self.assertEqual(len(FailureWallStore(path).get_group(second.group_id).records), 1)
            self.assertEqual(FailureWallStore(path).decisions(merged.group_id)[0]["decision"], "split")


if __name__ == "__main__":
    unittest.main()
