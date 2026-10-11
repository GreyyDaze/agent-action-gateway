"""Retention: discarding a payload must never look like never having had one.

Prompts and completions are several times larger than the rest of a trace row,
so a system recording exchanges grows fast. That is a real problem. Deleting an
audit trail by surprise is a worse one.

The contract these tests hold:

- the row survives, with its action, timing, cost and outcome;
- the pruning is stamped, so "captured then discarded" is distinguishable from
  "never captured";
- receipts are never touched;
- nothing happens without an explicit bound, and a dry run changes nothing.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from safety_layer.runtime.records import TraceEvent
from safety_layer.storage.traces import TraceStore


def exchange(run_id: str, step: int, prompt: str) -> TraceEvent:
    return TraceEvent(
        run_id, step, "model.exchange", None, None, "completed",
        prompt=prompt, completion=f"reply {step}",
        tokens_in=100, tokens_out=20, cost_usd=0.001, latency_ms=10.0,
    )


class PruneTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.store = TraceStore(Path(self._tmp.name) / "runtime.db")

    def _seed(self, run_id: str, count: int) -> list[int]:
        ids = []
        for step in range(1, count + 1):
            ids.append(
                self.store.append_trace(exchange(run_id, step, f"prompt {run_id} {step}"))
            )
        return ids

    def _row(self, trace_id: int) -> dict:
        return next(t for t in self.store.snapshot()["traces"] if t["id"] == trace_id)


class NothingIsDeletedSilentlyTest(PruneTest):
    def test_pruning_requires_a_bound(self) -> None:
        self._seed("r", 3)
        with self.assertRaises(ValueError) as raised:
            self.store.prune_exchanges()
        self.assertIn("older_than_days", str(raised.exception))
        # And nothing moved.
        self.assertEqual(len(self.store.snapshot()["traces"]), 3)

    def test_a_dry_run_changes_nothing(self) -> None:
        self._seed("r", 3)
        report = self.store.prune_exchanges(keep_latest_per_run=1, dry_run=True)
        self.assertEqual(report["selected"], 2)
        self.assertTrue(report["dry_run"])
        for row in self.store.snapshot()["traces"]:
            self.assertIsNotNone(row["prompt"], "a dry run must not remove anything")

    def test_negative_bounds_are_refused(self) -> None:
        with self.assertRaises(ValueError):
            self.store.prune_exchanges(older_than_days=-1)
        with self.assertRaises(ValueError):
            self.store.prune_exchanges(keep_latest_per_run=-1)


class TheEvidenceSurvivesTest(PruneTest):
    def test_the_row_still_exists_after_pruning(self) -> None:
        ids = self._seed("r", 3)
        self.store.prune_exchanges(keep_latest_per_run=1)
        rows = self.store.snapshot()["traces"]
        self.assertEqual(len(rows), 3, "pruning must not delete rows")
        self.assertEqual([r["id"] for r in rows], ids)

    def test_action_cost_and_timing_are_untouched(self) -> None:
        """These are the record that something happened. Losing them would make
        a pruned run unreadable."""
        ids = self._seed("r", 2)
        self.store.prune_exchanges(keep_latest_per_run=0)
        row = self._row(ids[0])
        self.assertIsNone(row["prompt"])
        self.assertEqual(row["event"], "model.exchange")
        self.assertEqual(row["step"], 1)
        self.assertEqual(row["tokens_in"], 100)
        self.assertEqual(row["cost_usd"], 0.001)
        self.assertEqual(row["latency_ms"], 10.0)

    def test_a_pruned_row_is_marked_not_silently_null(self) -> None:
        ids = self._seed("r", 2)
        self.store.prune_exchanges(keep_latest_per_run=0)
        row = self._row(ids[0])
        self.assertIsNotNone(row["exchange_pruned_at"])
        self.assertEqual(row["exchange_state"], "pruned")

    def test_never_recorded_is_a_third_state(self) -> None:
        """A row that never had an exchange must not read as a pruned one."""
        plain = self.store.append_trace(
            TraceEvent("r", 1, "before", {"task": "x"}, None, "started")
        )
        self.store.prune_exchanges(keep_latest_per_run=0)
        self.assertEqual(self._row(plain)["exchange_state"], "never_recorded")

    def test_a_captured_row_reads_as_captured(self) -> None:
        ids = self._seed("r", 1)
        self.assertEqual(self._row(ids[0])["exchange_state"], "captured")


class SelectionTest(PruneTest):
    def test_keep_latest_keeps_the_newest(self) -> None:
        ids = self._seed("r", 5)
        self.store.prune_exchanges(keep_latest_per_run=2)
        kept = [i for i in ids if self._row(i)["prompt"] is not None]
        self.assertEqual(kept, ids[-2:])

    def test_the_count_is_per_run(self) -> None:
        a = self._seed("a", 4)
        b = self._seed("b", 4)
        self.store.prune_exchanges(keep_latest_per_run=1)
        self.assertIsNone(self._row(a[0])["prompt"])
        self.assertIsNotNone(self._row(a[-1])["prompt"])
        self.assertIsNone(self._row(b[0])["prompt"])
        self.assertIsNotNone(self._row(b[-1])["prompt"])

    def test_bounds_compose_rather_than_fight(self) -> None:
        """With both given, a row must satisfy both to be pruned."""
        ids = self._seed("r", 3)
        report = self.store.prune_exchanges(
            older_than_days=36500, keep_latest_per_run=1, dry_run=True
        )
        # Nothing is 10000 days old, so nothing matches regardless of the bound.
        self.assertEqual(report["selected"], 0)
        self.assertIsNotNone(self._row(ids[0])["prompt"])

    def test_keep_latest_zero_prunes_everything_recorded(self) -> None:
        self._seed("r", 3)
        report = self.store.prune_exchanges(keep_latest_per_run=0)
        self.assertEqual(report["selected"], 3)

    def test_receipts_are_never_touched(self) -> None:
        """The receipt is the replay record and is small. It stays."""
        with self.store.connection() as connection:
            connection.execute(
                "INSERT INTO receipts(run_id, step_id, intent_key, action,"
                " arguments_json, state) VALUES ('r', '1', 'k', 'charge', '{}', 'done')"
            )
        self._seed("r", 2)
        self.store.prune_exchanges(keep_latest_per_run=0)
        receipts = self.store.snapshot()["receipts"]
        self.assertEqual(len(receipts), 1)
        self.assertEqual(receipts[0]["state"], "done")

    def test_rows_with_no_exchange_are_not_candidates(self) -> None:
        self.store.append_trace(TraceEvent("r", 1, "before", {"a": 1}, None, "started"))
        self._seed("r", 2)
        report = self.store.prune_exchanges(keep_latest_per_run=0, dry_run=True)
        self.assertEqual(report["candidates"], 2)


class GrowthTest(unittest.TestCase):
    def test_pruning_actually_shrinks_the_file(self) -> None:
        """Otherwise the feature is a no-op that reports success."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.db"
            store = TraceStore(path)
            for step in range(200):
                store.append_trace(exchange("r", step, f"a long prompt {step} " * 40))
            store.connection  # noqa: B018 - keep the handle shape obvious
            size_before = path.stat().st_size
            store.prune_exchanges(keep_latest_per_run=0)
            # WAL means the main file may not shrink immediately; checkpoint.
            with store.connection() as connection:
                connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            size_after = path.stat().st_size
            self.assertLess(size_after, size_before)

    def test_the_pruned_text_is_not_recoverable_from_the_file(self) -> None:
        """A prune that leaves the payload on disk has not pruned."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.db"
            store = TraceStore(path)
            marker = "sk_secret_marker_9f3a2b"
            for step in range(50):
                store.append_trace(exchange("r", step, f"prompt carrying {marker} {step}"))
            store.prune_exchanges(keep_latest_per_run=0)
            with store.connection() as connection:
                connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            raw = b"".join(p.read_bytes() for p in Path(directory).glob("runtime.db*"))
            self.assertNotIn(marker.encode(), raw)


if __name__ == "__main__":
    unittest.main()
