"""Tests for the shared SQLite persistence base.

These pin the three properties the base class exists to guarantee: connections
are always closed, migrations are recorded per store so stores sharing one file
do not collide, and a re-open is a no-op.
"""

from __future__ import annotations

import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

from agent_action_gateway.policy.locks import ApprovalStore
from agent_action_gateway.storage.base import SqliteStore
from agent_action_gateway.storage.traces import TraceStore


class CountingStore(SqliteStore):
    """Minimal concrete store used to exercise the base class."""

    store_name = "counting_test"

    def _migrations(self):
        yield 1, ["CREATE TABLE IF NOT EXISTS counting (id INTEGER PRIMARY KEY, n INTEGER);"]
        yield 2, ["ALTER TABLE counting ADD COLUMN label TEXT;"]


class OtherStoreOnSameFile(SqliteStore):
    """A second logical store sharing one database file."""

    store_name = "other_test"

    def _migrations(self):
        yield 1, ["CREATE TABLE IF NOT EXISTS other (id INTEGER PRIMARY KEY);"]
        yield 2, ["ALTER TABLE other ADD COLUMN note TEXT;"]


class ConnectionLifecycleTest(unittest.TestCase):
    def test_context_manager_closes_the_connection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = CountingStore(Path(directory) / "c.db")
            with store.connection() as connection:
                connection.execute("INSERT INTO counting (n) VALUES (1)")
                captured = connection
            # The bare sqlite3 context manager only commits; this asserts the
            # handle is actually released rather than left to refcounting.
            with self.assertRaises(sqlite3.ProgrammingError):
                captured.execute("SELECT 1")

    def test_commit_persists(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = CountingStore(Path(directory) / "c.db")
            with store.connection() as connection:
                connection.execute("INSERT INTO counting (n) VALUES (7)")
            with store.connection() as connection:
                value = connection.execute("SELECT n FROM counting").fetchone()[0]
            self.assertEqual(value, 7)

    def test_error_rolls_back(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = CountingStore(Path(directory) / "c.db")
            with self.assertRaises(sqlite3.OperationalError):
                with store.connection() as connection:
                    connection.execute("INSERT INTO counting (n) VALUES (1)")
                    connection.execute("INSERT INTO nonexistent (n) VALUES (1)")
            with store.connection() as connection:
                count = connection.execute("SELECT COUNT(*) FROM counting").fetchone()[0]
            self.assertEqual(count, 0)

    def test_busy_timeout_is_applied(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = CountingStore(Path(directory) / "c.db")
            with store.connection() as connection:
                self.assertEqual(
                    connection.execute("PRAGMA busy_timeout").fetchone()[0], 30000
                )


class MigrationTest(unittest.TestCase):
    def test_all_migrations_applied_once(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = CountingStore(Path(directory) / "c.db")
            self.assertEqual(store.applied_migrations(), (1, 2))

    def test_reopening_applies_nothing_new(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "c.db"
            first = CountingStore(path)
            self.assertEqual(first.applied_migrations(), (1, 2))
            # Re-opening must be idempotent: recorded migrations are not re-run,
            # so an ALTER TABLE would fail on the second open if they were.
            second = CountingStore(path)
            self.assertEqual(second.applied_migrations(), (1, 2))

    def test_migration_added_later_applies_on_reopen(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "c.db"

            class V1Only(SqliteStore):
                store_name = "incremental_test"

                def _migrations(self):
                    yield 1, ["CREATE TABLE IF NOT EXISTS incr (id INTEGER PRIMARY KEY);"]

            V1Only(path)

            class V2Store(V1Only):
                def _migrations(self):
                    yield 1, ["CREATE TABLE IF NOT EXISTS incr (id INTEGER PRIMARY KEY);"]
                    yield 2, ["ALTER TABLE incr ADD COLUMN extra TEXT;"]

            store = V2Store(path)
            self.assertEqual(store.applied_migrations(), (1, 2))
            with store.connection() as connection:
                self.assertIn("extra", {r["name"] for r in connection.execute("PRAGMA table_info(incr)")})

    def test_stores_sharing_one_file_do_not_collide(self) -> None:
        """Approvals share the runtime database; each must migrate independently."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "shared.db"
            CountingStore(path)
            other = OtherStoreOnSameFile(path)
            self.assertEqual(other.applied_migrations(), (1, 2))
            # Both logical schemas coexist in the same file.
            with other.connection() as connection:
                names = {
                    row["name"]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                }
            self.assertIn("counting", names)
            self.assertIn("other", names)

    def test_traces_and_approvals_coexist_in_one_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.db"
            traces = TraceStore(path)
            approvals = ApprovalStore(traces)
            self.assertEqual(traces.applied_migrations(), (1, 2, 3, 4, 5, 6, 7))
            self.assertEqual(approvals.applied_migrations(), (1, 2, 3))
            with approvals.connection() as connection:
                names = {
                    row["name"]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                }
            self.assertIn("approvals", names)
            self.assertIn("trace_events", names)

    def test_approval_store_accepts_a_bare_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            approvals = ApprovalStore(Path(directory) / "approvals.db")
            self.assertEqual(approvals.applied_migrations(), (1, 2, 3))


class ConcurrencyTest(unittest.TestCase):
    def test_concurrent_writers_do_not_leak_handles(self) -> None:
        """Many threads opening connections must not exhaust file handles."""
        with tempfile.TemporaryDirectory() as directory:
            store = CountingStore(Path(directory) / "c.db")
            errors: list[BaseException] = []

            def worker(index: int) -> None:
                try:
                    for _ in range(10):
                        with store.connection() as connection:
                            connection.execute(
                                "INSERT INTO counting (n) VALUES (?)", (index,)
                            )
                except BaseException as exc:  # pragma: no cover - failure path
                    errors.append(exc)

            threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            self.assertEqual(errors, [])
            with store.connection() as connection:
                count = connection.execute("SELECT COUNT(*) FROM counting").fetchone()[0]
            self.assertEqual(count, 80)



if __name__ == "__main__":
    unittest.main()
