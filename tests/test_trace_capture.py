"""The model exchange is recorded, redacted, and readable back.

`input_json` records the task and `output_json` the tool result. Neither
records what was actually sent to the model or what came back, so the
exchange could not be reconstructed.

These tests are the guard on that claim. The redaction ones matter most: a
prompt is the part of a system most likely to contain whatever a user typed,
and a leaked key or personal detail is exactly what this library exists to keep out
of storage.
"""

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from agent_action_gateway.runtime.records import TraceEvent
from agent_action_gateway.storage.traces import TraceStore


class ExchangeCaptureTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.store = TraceStore(Path(self._tmp.name) / "runtime.db")

    def _event(self, **overrides) -> TraceEvent:
        base = {
            "run_id": "run-1",
            "step": 1,
            "event": "agent",
            "input": {"deployment_id": "DEP-1"},
            "output": {"status": "ok"},
            "status": "completed",
        }
        return TraceEvent(**{**base, **overrides})

    def _row(self, trace_id: int) -> dict:
        return next(t for t in self.store.snapshot()["traces"] if t["id"] == trace_id)

    # -- round trip -------------------------------------------------------

    def test_prompt_and_completion_survive_a_round_trip(self) -> None:
        trace_id = self.store.append_trace(
            self._event(prompt="roll back deployment DEP-1", completion="rolled back DEP-1")
        )
        row = self._row(trace_id)
        self.assertEqual(row["prompt"], "roll back deployment DEP-1")
        self.assertEqual(row["completion"], "rolled back DEP-1")

    def test_cost_and_latency_survive_a_round_trip(self) -> None:
        trace_id = self.store.append_trace(
            self._event(
                tokens_in=1200,
                tokens_out=340,
                cost_usd=0.0042,
                latency_ms=812.5,
            )
        )
        row = self._row(trace_id)
        self.assertEqual(row["tokens_in"], 1200)
        self.assertEqual(row["tokens_out"], 340)
        self.assertAlmostEqual(row["cost_usd"], 0.0042)
        self.assertAlmostEqual(row["latency_ms"], 812.5)

    def test_a_step_that_never_called_a_model_records_nothing(self) -> None:
        """Absence means "we were not told", which is different from empty.

        A NULL must not be flattened into "" or 0, because a reader would then
        believe a cost of zero was measured rather than never captured.
        """
        trace_id = self.store.append_trace(self._event())
        row = self._row(trace_id)
        self.assertIsNone(row["prompt"])
        self.assertIsNone(row["completion"])
        self.assertIsNone(row["tokens_in"])
        self.assertIsNone(row["cost_usd"])

    # -- redaction --------------------------------------------------------

    def test_a_card_number_in_a_prompt_is_never_stored(self) -> None:
        trace_id = self.store.append_trace(
            self._event(prompt="rollback card 4111111111111111 please")
        )
        self.assertNotIn("4111111111111111", self._row(trace_id)["prompt"])
        self.assertIn("REDACTED", self._row(trace_id)["prompt"])

    def test_an_email_in_a_prompt_is_never_stored(self) -> None:
        trace_id = self.store.append_trace(
            self._event(prompt="email ava@example.com about the rollback")
        )
        self.assertNotIn("ava@example.com", self._row(trace_id)["prompt"])

    def test_a_bearer_token_in_a_completion_is_never_stored(self) -> None:
        trace_id = self.store.append_trace(
            self._event(completion="called with Authorization: Bearer sk_live_abcdef123456")
        )
        self.assertNotIn("sk_live_abcdef123456", self._row(trace_id)["completion"])

    def test_the_raw_database_does_not_contain_the_secret(self) -> None:
        """Not just the decoded row — the bytes on disk."""
        self.store.append_trace(self._event(prompt="card 4111111111111111 ok"))
        path = Path(self._tmp.name) / "runtime.db"
        raw = path.read_bytes().decode("utf-8", "ignore")
        self.assertNotIn("4111111111111111", raw)

    # -- replay -----------------------------------------------------------

    def test_a_replay_carries_the_exchange_forward(self) -> None:
        original = self.store.append_trace(
            self._event(prompt="p", completion="c", cost_usd=0.5, tokens_in=10)
        )
        replay = self.store.append_replay(original, self._event(prompt="p2", completion="c2"))
        row = self._row(replay)
        self.assertEqual(row["prompt"], "p2")
        self.assertEqual(row["completion"], "c2")
        self.assertEqual(row["replay_of_trace_id"], original)


class MigrationTest(unittest.TestCase):
    def test_an_older_database_opens_without_losing_rows(self) -> None:
        """The exchange columns are additive, so a pre-v5 file must still work.

        Simulated by rolling the file back -- columns dropped and the migration
        rows removed -- then reopening it.
        """
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.db"
            store = TraceStore(path)
            store.append_trace(
                TraceEvent("run-old", 1, "agent", {"a": 1}, {"b": 2}, "completed")
            )
            with sqlite3.connect(path) as connection:
                for column in (
                    "prompt_json",
                    "completion_json",
                    "tokens_in",
                    "tokens_out",
                    "cost_usd",
                    "latency_ms",
                ):
                    connection.execute(f"ALTER TABLE trace_events DROP COLUMN {column}")
                connection.execute(
                    "ALTER TABLE trace_events DROP COLUMN exchange_pruned_at"
                )
                connection.execute(
                    "DELETE FROM schema_migrations WHERE store = ? AND version IN (5, 6)",
                    (TraceStore.store_name,),
                )

            reopened = TraceStore(path)
            self.assertEqual(reopened.applied_migrations(), (1, 2, 3, 4, 5, 6, 7))
            reopened.append_trace(
                TraceEvent("run-new", 1, "agent", {"a": 1}, {"b": 2}, "completed", prompt="hi")
            )
            traces = reopened.snapshot()["traces"]
            # The pre-v5 row survived, and the new column is usable again.
            self.assertEqual(len(traces), 2)
            self.assertIsNone(traces[0]["prompt"])
            self.assertEqual(traces[1]["prompt"], "hi")


if __name__ == "__main__":
    unittest.main()
