"""Decide whether a SQL text only reads.

Many database MCP servers expose one tool, such as `run_sql`, for reads and
writes alike. A fixed risk for that tool is wrong either way: `read` lets a
`DROP TABLE` through, and `destructive` makes every `SELECT` wait for a person.
`is_read_only_sql` lets the proxy decide per call.

It is deliberately strict. A text counts as read-only only when every statement
starts with a read keyword (SELECT, WITH, SHOW, EXPLAIN, VALUES, TABLE) and no
word anywhere in it can change data, take a lock, or change the session. Comments,
string literals and quoted names are removed first, so a word inside them does not
count. Anything it cannot read with certainty, such as an unclosed quote, is not
read-only. Strings are read the PostgreSQL way with `standard_conforming_strings`
on (the default since 9.1): a backslash escapes only inside `E'...'`.

What it cannot see: a function that writes. `SELECT my_cleanup()` looks like a
read. Known server functions that act (for example `pg_terminate_backend`,
`set_config`, `nextval`) are treated as writes, but a function your own database
defines is not known. For a hard guarantee, connect the reading path with a
database role that cannot write.
"""

from __future__ import annotations

import re

_READ_STARTS = frozenset({"select", "with", "show", "explain", "values", "table"})

# Any of these words, outside comments and strings, makes the text not
# read-only. Statements that start with another keyword (DROP, COPY, SET, CALL,
# BEGIN, ...) are already refused by the first-word check; this list catches the
# writes that can hide inside a statement that starts like a read:
# `WITH x AS (DELETE ...) SELECT`, `SELECT ... INTO new_table`, row locks
# (`FOR UPDATE`, `FOR SHARE`) and server functions that act. A column that
# happens to share one of these names makes a read count as a write: that is the
# safe direction.
_WRITE_WORDS = frozenset(
    {
        "insert", "update", "delete", "merge", "into", "share",
        "drop", "alter", "truncate", "create", "grant", "revoke",
        # server functions that act
        "nextval", "setval", "set_config", "pg_terminate_backend",
        "pg_cancel_backend", "pg_reload_conf", "pg_rotate_logfile",
        "pg_promote", "pg_switch_wal", "pg_create_restore_point",
        "pg_advisory_lock", "pg_advisory_xact_lock", "pg_try_advisory_lock",
        "pg_try_advisory_xact_lock", "lo_import", "lo_export", "lo_unlink",
        "lo_create", "lo_put", "lo_from_bytea", "dblink", "dblink_exec",
        "pg_read_file", "pg_read_binary_file", "pg_ls_dir", "pg_stat_file",
        "pg_file_write", "pg_logical_emit_message", "txid_current",
        "pg_current_xact_id",
    }
)

_WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_$]*")
_DOLLAR_TAG = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)?\$")


class _Unreadable(Exception):
    """The text cannot be read with certainty (for example an unclosed quote)."""


def _strip(sql: str) -> str:
    """Return the text with comments, strings and quoted names blanked out.

    Statement separators stay, so the result can be split on ';'.
    """
    out: list[str] = []
    i, n = 0, len(sql)
    while i < n:
        c = sql[i]
        nxt = sql[i + 1] if i + 1 < n else ""
        if c == "-" and nxt == "-":
            end = sql.find("\n", i)
            i = n if end == -1 else end
            out.append(" ")
        elif c == "/" and nxt == "*":
            # PostgreSQL block comments nest.
            depth, i = 1, i + 2
            while i < n and depth:
                if sql.startswith("/*", i):
                    depth, i = depth + 1, i + 2
                elif sql.startswith("*/", i):
                    depth, i = depth - 1, i + 2
                else:
                    i += 1
            if depth:
                raise _Unreadable("unclosed comment")
            out.append(" ")
        elif c == "'":
            # E'...' allows backslash escapes; a plain string doubles the quote.
            escapes = bool(out) and out[-1].lower() == "e" and (
                len(out) < 2 or not (out[-2].isalnum() or out[-2] == "_")
            )
            i += 1
            while True:
                if i >= n:
                    raise _Unreadable("unclosed string")
                if escapes and sql[i] == "\\":
                    i += 2
                    continue
                if sql[i] == "'":
                    if i + 1 < n and sql[i + 1] == "'":
                        i += 2
                        continue
                    i += 1
                    break
                i += 1
            out.append(" '' ")
        elif c == '"':
            i += 1
            while True:
                if i >= n:
                    raise _Unreadable("unclosed quoted name")
                if sql[i] == '"':
                    if i + 1 < n and sql[i + 1] == '"':
                        i += 2
                        continue
                    i += 1
                    break
                i += 1
            out.append(" quoted_name ")
        elif c == "$" and (match := _DOLLAR_TAG.match(sql, i)) and not (
            out and (out[-1].isalnum() or out[-1] == "_")
        ):
            tag = match.group(0)
            end = sql.find(tag, match.end())
            if end == -1:
                raise _Unreadable("unclosed dollar-quoted string")
            i = end + len(tag)
            out.append(" '' ")
        elif c == "`":
            # MySQL-style quoted names. Not valid in PostgreSQL; refuse rather
            # than guess what is inside.
            raise _Unreadable(f"unsupported quote {c!r}")
        else:
            out.append(c)
            i += 1
    return "".join(out)


def is_read_only_sql(sql: object) -> bool:
    """True only when the text certainly does nothing but read."""
    if not isinstance(sql, str) or not sql.strip():
        return False
    try:
        text = _strip(sql)
    except _Unreadable:
        return False
    statements = [s for s in text.split(";") if s.strip()]
    if not statements:
        return False
    for statement in statements:
        words = [w.lower() for w in _WORD.findall(statement)]
        if not words or words[0] not in _READ_STARTS:
            return False
        if any(w in _WRITE_WORDS for w in words):
            return False
    return True
