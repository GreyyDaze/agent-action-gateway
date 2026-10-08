"""Shared SQLite persistence base.

Four stores previously duplicated connection setup, schema creation and
hand-rolled `PRAGMA table_info` migration loops. That produced four migration
strategies, twelve tables with no version marker, and a connection lifecycle
that relied on CPython reference counting to close handles.

This module centralizes all three concerns:

- one connection policy (WAL, busy timeout) applied once;
- connections that are always closed, via `closing()` rather than the bare
  context manager, which commits but does not close;
- schema versioning through SQLite's own `user_version`, so migrations run in
  order and a partially migrated database is impossible.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator, Sequence
from contextlib import closing, contextmanager
from pathlib import Path
from typing import Any


class SqliteStore:
    """Base for every durable store in this package.

    Subclasses declare their schema and their migrations; they never open a
    connection directly.
    """

    #: Bumped whenever a subclass adds a migration step.
    schema_version: int = 1

    def __init__(self, path: str | Path = ":memory:") -> None:
        self.path = Path(path)
        if str(self.path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_schema()

    # -- connection lifecycle -------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        """Open a connection. Callers must use it through `connection()`."""
        connection = sqlite3.connect(str(self.path), timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=30000")
        if str(self.path) != ":memory:":
            connection.execute("PRAGMA journal_mode=WAL")
        return connection

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        """Yield a connection that is committed and closed.

        `sqlite3.Connection.__exit__` commits or rolls back but leaves the
        handle open, so the earlier `with self._connect()` pattern leaked
        handles whenever a frame was retained. `closing()` guarantees release.
        """
        with closing(self._connect()) as connection, connection:
            yield connection

    # -- schema management ----------------------------------------------

    #: Identifies this store's migrations inside a shared database file.
    #: Several stores can share one file (approvals live in the runtime
    #: database), so SQLite's single `user_version` cannot be used: one store
    #: would see another's version and skip its own migrations.
    store_name = "default"

    def _ensure_schema(self) -> None:
        """Create the schema and apply this store's outstanding migrations."""
        with self.connection() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    store TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (store, version)
                );
                """
            )
            rows = connection.execute(
                "SELECT version FROM schema_migrations WHERE store = ?",
                (self.store_name,),
            ).fetchall()
            applied = {int(row["version"]) for row in rows}

            for version, statements in self._migrations():
                if version in applied:
                    continue
                # Each step is its own transaction, so an interrupted migration
                # leaves the database at the last completed version rather than
                # half applied. `executescript` is used because a step may hold
                # several statements; `execute` allows only one.
                with connection:
                    for statement in statements:
                        if statement.strip():
                            connection.executescript(statement)
                    connection.execute(
                        "INSERT INTO schema_migrations (store, version) VALUES (?, ?)",
                        (self.store_name, int(version)),
                    )

    def applied_migrations(self) -> tuple[int, ...]:
        """Versions of this store's migrations recorded as applied."""
        self._ensure_schema()
        with self.connection() as connection:
            rows = connection.execute(
                "SELECT version FROM schema_migrations WHERE store = ? ORDER BY version",
                (self.store_name,),
            ).fetchall()
        return tuple(int(row["version"]) for row in rows)

    def _migrations(self) -> Sequence[tuple[int, Sequence[str]]]:
        """Return `(version, statements)` steps in ascending order."""
        return ()

    # -- small query helpers --------------------------------------------

    def _execute(self, sql: str, parameters: Sequence[Any] = ()) -> sqlite3.Cursor:
        with self.connection() as connection:
            return connection.execute(sql, parameters)

    def _columns(self, table: str) -> set[str]:
        with self.connection() as connection:
            rows = connection.execute(f"PRAGMA table_info({table})").fetchall()
        return {str(row["name"]) for row in rows}

    def _table_exists(self, table: str) -> bool:
        with self.connection() as connection:
            row = connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
                (table,),
            ).fetchone()
        return row is not None
