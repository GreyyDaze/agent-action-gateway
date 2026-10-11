"""PostgreSQL persistence, alongside SQLite.

SQLite is a single-node store. An adopter running several gateway replicas, or
several agent hosts writing one database, cannot use it -- and at that point
"documented ceiling" is just "not usable". So both backends are supported.

The expensive-sounding part is not the second backend, it is the second *copy*
of every query. This module avoids that entirely with a connection shim:

- `?` placeholders become `%s`, so subclass SQL is unchanged.
- Rows behave like `sqlite3.Row`, so `row["name"]` works unchanged.
- `SELECT last_insert_rowid()` becomes `lastval()`.
- `PRAGMA table_info` and `sqlite_master` are answered from `information_schema`.
- `INTEGER PRIMARY KEY AUTOINCREMENT` is rewritten to an identity column.

That means `TraceStore` and the approval store run **the same statements**
against either backend, and `tests/test_backend_agreement.py` runs the same
assertions against both. If that suite passes for both, the backend is
swappable in fact and not just in the documentation.

Writes are still single-writer-per-row by design. Postgres removes the
single-host ceiling; it does not turn this into a distributed lock service.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Sequence
from typing import Any

#: `INTEGER PRIMARY KEY AUTOINCREMENT` has no PostgreSQL equivalent.
_AUTOINCREMENT = re.compile(
    r"INTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT", re.IGNORECASE
)
#: A placeholder count of 1 would also match inside a quoted string, but our DDL
#: and queries contain none, and the alternative is parsing SQL properly.
_LAST_ROWID = re.compile(r"last_insert_rowid\s*\(\s*\)", re.IGNORECASE)


class _Row(dict):
    """A result row that answers to both names and positions.

    `sqlite3.Row` accepts `row["name"]` and `row[0]`; the store code uses both
    (named for its own columns, positional in a couple of introspection
    queries). psycopg's `dict_row` gives only the first, so both are provided
    rather than rewriting queries that work on either backend unchanged.
    """

    def __getitem__(self, key: Any) -> Any:
        if isinstance(key, int) and key not in self.keys():
            try:
                return dict.__getitem__(self, list(self.keys())[key])
            except IndexError:
                raise KeyError(key) from None
        return dict.__getitem__(self, key)


class _Cursor:
    """The subset of cursor behaviour the stores rely on."""

    def __init__(self, cursor: Any) -> None:
        self._cursor = cursor
        self.rowcount = cursor.rowcount
        self.lastrowid: int | None = None

    def fetchone(self) -> Any:
        row = self._cursor.fetchone()
        return None if row is None else _Row(row)

    def fetchall(self) -> list[Any]:
        return [_Row(row) for row in self._cursor.fetchall()]

    def __iter__(self) -> Iterator[Any]:
        for row in self._cursor:
            yield _Row(row)

    def close(self) -> None:
        self._cursor.close()


class PostgresConnection:
    """Translates SQLite-flavoured SQL into PostgreSQL.

    Deliberately narrow: it translates only what this package emits. Anything
    outside that raises rather than being passed through and failing obscurely
    in the database.
    """

    def __init__(self, raw: Any) -> None:
        self._raw = raw
        self._transaction_depth = 0

    def execute(self, sql: str, parameters: Sequence[Any] = ()) -> _Cursor:
        translated = self._translate(sql)
        cursor = self._raw.execute(translated, tuple(parameters) or None)
        return _Cursor(cursor)

    def executescript(self, script: str) -> None:
        """Run a multi-statement script.

        psycopg has no `executescript`. Splitting on `;` is safe here because
        the package's DDL contains no semicolon inside a quoted literal; a
        statement containing one would be caught by the backend-agreement tests
        rather than silently truncated.
        """
        for statement in _split_statements(script):
            self._raw.execute(self._translate(statement))

    def close(self) -> None:
        self._raw.close()

    def commit(self) -> None:
        self._raw.commit()

    def rollback(self) -> None:
        self._raw.rollback()

    def __enter__(self) -> PostgresConnection:
        # Deliberately does not delegate to the psycopg context manager.
        # `psycopg.Connection.__exit__` closes the connection, and the stores
        # nest `with connection:` inside `connection()`; delegating would close
        # the handle after the inner block and every later statement would fail
        # with "the connection is closed". Closing belongs to the outer
        # `closing()` and nowhere else.
        self._transaction_depth += 1
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self._transaction_depth -= 1
        if self._transaction_depth > 0:
            # An inner block inside an open transaction: do not commit early,
            # or a later failure could not roll the whole step back.
            return
        if exc_type is None:
            self._raw.commit()
        else:
            self._raw.rollback()

    # -- translation ------------------------------------------------------

    @staticmethod
    def _translate(sql: str) -> str:
        text = _AUTOINCREMENT.sub("INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY", sql)
        text = _LAST_ROWID.sub("lastval()", text)
        # Placeholders last: a `%` inside a literal would otherwise be mistaken
        # for one, but the package emits none.
        return text.replace("?", "%s")

    def table_columns(self, table: str) -> set[str]:
        """Columns of `table` in the connection's *current* schema.

        Scoped deliberately. `information_schema` is database-wide, so an
        unscoped query returns the union across every schema holding a table of
        that name. With more than one schema present, an unrelated schema's
        columns make a migration believe a column already exists and skip the
        ALTER -- so the table is left without it and every later write fails.
        That is a silent schema bug wearing a migration bug's clothes.

        Named access, not positional: the connection uses `dict_row`, so a
        tuple-style index would raise KeyError rather than anything clear.
        """
        cursor = self._raw.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_schema = current_schema() AND table_name = %s",
            (table,),
        )
        return {str(row["column_name"]) for row in cursor.fetchall()}

    def has_table(self, table: str) -> bool:
        cursor = self._raw.execute(
            "SELECT 1 AS present FROM information_schema.tables "
            "WHERE table_schema = current_schema() AND table_name = %s LIMIT 1",
            (table,),
        )
        return cursor.fetchone() is not None


def _split_statements(script: str) -> list[str]:
    statements = []
    for chunk in script.split(";"):
        if chunk.strip():
            statements.append(chunk.strip())
    return statements


#: The backend contract itself lives in `storage.base.Store`, which picks this
#: connection when the target is a `postgres://` URL. Only the SQL dialect and
#: connection handling belong here -- a second store base would be a second
#: copy of the migration machinery, and the two would drift.
__all__ = ["PostgresConnection"]
