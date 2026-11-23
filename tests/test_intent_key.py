"""A destructive tool receives `intent_key` only if it can accept it.

A tool written without an `intent_key` parameter used to fail with a TypeError
the first time it was approved. Accepting the key is how a tool passes an
idempotency key to its provider; not accepting it must not crash, and must not
weaken the once-only guarantee.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from agent_action_gateway import session
from agent_action_gateway.storage.traces import TraceStore


def _approved_call(ctx, tool, **arguments: Any) -> dict[str, Any]:
    approval = ctx.request_approval("db.drop_table", arguments)
    ctx.approve(approval.approval_id, "tester")
    return tool(**arguments, approval_id=approval.approval_id)


def test_tool_without_intent_key_runs_once(tmp_path: Path) -> None:
    calls: list[str] = []

    def drop_table(table: str) -> dict:
        calls.append(table)
        return {"dropped": table}

    with session(store=TraceStore(tmp_path / "r.db"), environment="prod") as ctx:
        drop = ctx.tool(drop_table, action="db.drop_table", risk="destructive")
        first = _approved_call(ctx, drop, table="users")
        second = _approved_call(ctx, drop, table="users")

    assert first["status"] == "allowed"
    assert second["status"] == "allowed"
    assert second["decision"] == "DEDUPLICATED"
    assert calls == ["users"], "the same effect must not run twice"


def test_tool_that_names_intent_key_receives_it(tmp_path: Path) -> None:
    keys: list[str] = []

    def drop_table(table: str, intent_key: str = "") -> dict:
        keys.append(intent_key)
        return {"dropped": table}

    with session(store=TraceStore(tmp_path / "r.db"), environment="prod") as ctx:
        drop = ctx.tool(drop_table, action="db.drop_table", risk="destructive")
        _approved_call(ctx, drop, table="users")

    assert len(keys) == 1 and keys[0], "the tool must receive a non-empty key"


def test_tool_with_var_keywords_receives_it(tmp_path: Path) -> None:
    received: list[dict] = []

    def drop_table(table: str, **extra: Any) -> dict:
        received.append(extra)
        return {"dropped": table}

    with session(store=TraceStore(tmp_path / "r.db"), environment="prod") as ctx:
        drop = ctx.tool(drop_table, action="db.drop_table", risk="destructive")
        _approved_call(ctx, drop, table="users")

    assert received and received[0].get("intent_key")
