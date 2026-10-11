"""Shared persistence base, for SQLite and PostgreSQL alike.

Four stores previously duplicated connection setup, schema creation and
hand-rolled `PRAGMA table_info` migration loops. That produced four migration
strategies, twelve tables with no version marker, and a connection lifecycle
that relied on CPython reference counting to close handles.

This module centralizes all three concerns:

- one connection policy (WAL, busy timeout) applied once;
- connections that are always closed, via `closing()` rather than the bare
  context manager, which commits but does not close;
- schema versioning in one place, so migrations run in order and a partially
  migrated database is impossible.

The backend is chosen from the target string: a filesystem path is SQLite, a
`postgres://` URL is PostgreSQL. Subclasses declare `_migrations()` once and
never learn which backend they are on -- `connection()`, `_columns()` and
`_table_exists()` are the only things that differ, and they are the only things
overridden. That is what makes `tests/test_backend_agreement.py` meaningful: the
same statements run against both engines.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator, Sequence
from contextlib import closing, contextmanager
from pathlib import Path
from typing import Any

#: URL schemes that select a backend. A bare path is SQLite; these are not
#: silently treated as file names, because a typo'd URL must not create an
#: empty SQLite database and report success.
POSTGRES_SCHEMES = ("postgres://", "postgresql://")


def _resolve(target: str | Path) -> tuple[str, str]:
    """Pick a backend from the `--db` target."""
    text = str(target)
    if text.startswith(POSTGRES_SCHEMES):
        return "postgres", text
    if "://" in text:
        scheme = text.split("://", 1)[0]
        raise ValueError(
            f"unsupported database scheme {scheme!r}; use a filesystem path, "
            ":memory:, or a postgres:// URL"
        )
    return "sqlite", text


class Store:
    """Base for every durable store in this package.

    Subclasses declare their schema and their migrations; they never open a
    connection directly and never branch on the backend.
    """

    #: Bumped whenever a subclass adds a migration step.
    schema_version: int = 1

    def __init__(self, target: str | Path = ":memory:") -> None:
        self.backend, self.path = _resolve(target)
        if self.backend == "sqlite" and self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._ensure_schema()

    # -- connection lifecycle -------------------------------------------

    def _connect(self) -> Any:
        """Open a connection. Callers must use it through `connection()`."""
        if self.backend == "postgres":
            import psycopg
            from psycopg.rows import dict_row

            from .postgres import PostgresConnection

            return PostgresConnection(
                psycopg.connect(self.path, row_factory=dict_row, autocommit=False)
            )
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=30000")
        if self.path != ":memory:":
            connection.execute("PRAGMA journal_mode=WAL")
        return connection

    @contextmanager
    def connection(self) -> Iterator[Any]:
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
                    # Committed per step, not at the end of the whole loop. The
                    # next step inspects the schema through its own connection,
                    # which cannot see uncommitted DDL from this one -- so
                    # without this the later ALTER steps would decide the
                    # columns were missing and re-run, or see none at all.
                    connection.commit()

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
        """Columns on a table, answered by whichever backend is in use."""
        if self.backend == "postgres":
            with self.connection() as connection:
                return connection.table_columns(table)
        with self.connection() as connection:
            rows = connection.execute(f"PRAGMA table_info({table})").fetchall()
        return {str(row["name"]) for row in rows}

    def _table_exists(self, table: str) -> bool:
        if self.backend == "postgres":
            with self.connection() as connection:
                return connection.has_table(table)
        with self.connection() as connection:
            row = connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
                (table,),
            ).fetchone()
        return row is not None


#: The original name, kept so existing imports and adopters' code still work.
#: It has always been "the store base"; the backend it defaults to was simply
#: implicit.
SqliteStore = Store
