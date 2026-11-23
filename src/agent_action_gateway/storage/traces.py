"""Durable trace, receipt and budget persistence.

The clarification-state tables live here too: resetting them on restart would
let a paused run buy itself a fresh safety budget, so they are stored with the
run rather than in memory.
"""

import json
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from agent_action_gateway.guards.redaction import redact
from agent_action_gateway.runtime.records import GateVerdict, Receipt, TraceEvent
from agent_action_gateway.storage.base import SqliteStore

_TRACE_EVENTS = """
CREATE TABLE IF NOT EXISTS trace_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    step INTEGER NOT NULL,
    event TEXT NOT NULL,
    input_json TEXT NOT NULL,
    output_json TEXT NOT NULL,
    status TEXT NOT NULL,
    flags_json TEXT NOT NULL DEFAULT '[]',
    capture_class TEXT NOT NULL DEFAULT 'always',
    provider_metadata_json TEXT NOT NULL DEFAULT '{}',
    provider_evidence_json TEXT NOT NULL DEFAULT '{}',
    replay_of_trace_id INTEGER
);
"""

_CORE_TABLES = """
CREATE TABLE IF NOT EXISTS receipts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    step_id TEXT NOT NULL,
    intent_key TEXT NOT NULL UNIQUE,
    action TEXT NOT NULL,
    arguments_json TEXT NOT NULL,
    state TEXT NOT NULL,
    provider_ref TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_receipts_state ON receipts(state);
CREATE TABLE IF NOT EXISTS gate_verdicts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    verdict TEXT NOT NULL,
    score REAL NOT NULL,
    threshold REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS clarification_states (
    run_id TEXT PRIMARY KEY,
    attempts INTEGER NOT NULL,
    max_attempts INTEGER NOT NULL,
    asked_this_turn INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS run_budgets (
    run_id TEXT PRIMARY KEY,
    steps_used INTEGER NOT NULL,
    dollars_used REAL NOT NULL,
    elapsed_seconds REAL NOT NULL,
    tripped INTEGER NOT NULL,
    degraded INTEGER NOT NULL,
    reason TEXT
);
"""

_VIRTUAL_KEYS_TABLE = """
CREATE TABLE IF NOT EXISTS virtual_keys (
    key TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    routes_json TEXT NOT NULL,
    expires_at REAL,
    revoked INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""

_TRACE_COLUMNS = (
    "flags_json",
    "capture_class",
    "provider_metadata_json",
    "provider_evidence_json",
    "replay_of_trace_id",
)


class TraceStore(SqliteStore):
    """Durable SQLite store for the self-hosted single-node production path."""

    store_name = "traces"

    def __init__(self, path: str | Path = "data/runtime.db") -> None:
        super().__init__(path)

    def _migrations(self):
        # v1: original trace table plus every supporting table.
        yield 1, [_TRACE_EVENTS, _CORE_TABLES]
        # v2: columns added after the first release. Applied additively so an
        # existing database keeps its rows.
        existing = self._columns("trace_events")
        additions = [
            "ALTER TABLE trace_events ADD COLUMN flags_json TEXT NOT NULL DEFAULT '[]'",
            "ALTER TABLE trace_events ADD COLUMN capture_class TEXT NOT NULL DEFAULT 'always'",
            "ALTER TABLE trace_events ADD COLUMN provider_metadata_json TEXT NOT NULL DEFAULT '{}'",
            "ALTER TABLE trace_events ADD COLUMN provider_evidence_json TEXT NOT NULL DEFAULT '{}'",
            "ALTER TABLE trace_events ADD COLUMN replay_of_trace_id INTEGER",
        ]
        if existing:
            yield 2, [stmt for stmt in additions if _added_column(stmt) not in existing]
        else:
            yield 2, []

        # v3: record which path a run took. Without this persisted, an audit
        # cannot answer after the fact whether a run was enforced or merely
        # observed, which is the difference between "recorded" and "protected".
        after_v2 = existing | {
            _added_column(stmt) for stmt in additions
        }
        enforcement = "ALTER TABLE trace_events ADD COLUMN enforcement TEXT"
        if not after_v2 or "enforcement" not in after_v2:
            yield 3, [enforcement]
        else:
            yield 3, []

        # v4: virtual keys table for gateway caller authentication
        yield 4, [_VIRTUAL_KEYS_TABLE]

        # v5: the model exchange itself. `input_json`/`output_json` record the
        # task and the tool result; neither records what was actually sent to the
        # model or what came back, so an audit could not reconstruct the
        # exchange. Cost and latency live here too, because a run's spend is a
        # property of its steps.
        exchange = [
            "ALTER TABLE trace_events ADD COLUMN prompt_json TEXT",
            "ALTER TABLE trace_events ADD COLUMN completion_json TEXT",
            "ALTER TABLE trace_events ADD COLUMN tokens_in INTEGER",
            "ALTER TABLE trace_events ADD COLUMN tokens_out INTEGER",
            "ALTER TABLE trace_events ADD COLUMN cost_usd REAL",
            "ALTER TABLE trace_events ADD COLUMN latency_ms REAL",
        ]
        current = self._columns("trace_events")
        if current:
            yield 5, [stmt for stmt in exchange if _added_column(stmt) not in current]
        else:
            yield 5, []

        # v6: when an exchange was pruned, and when the row was written at all.
        #
        # `exchange_pruned_at` records that a payload was discarded, so it stays
        # distinguishable from one that never had one -- "we do not have it and
        # cannot say why" is the failure this project exists to prevent, and a
        # bare NULL cannot express it.
        #
        # `created_at` existed because retention needed it: `trace_events` had no
        # timestamp of any kind, so "prune anything older than 30 days" had
        # nothing to measure against. Backfilled to the migration time, which is
        # the truth for a row written before the column existed -- an invented
        # older date would sort ahead of real history.
        additions_v6 = [
            "ALTER TABLE trace_events ADD COLUMN exchange_pruned_at TEXT",
            "ALTER TABLE trace_events ADD COLUMN created_at TEXT",
        ]
        seen = self._columns("trace_events")
        if not seen:
            yield 6, []
        else:
            missing = [s for s in additions_v6 if _added_column(s) not in seen]
            if any("created_at" in s for s in missing):
                missing.append(
                    "UPDATE trace_events SET created_at = CURRENT_TIMESTAMP "
                    "WHERE created_at IS NULL"
                )
            yield 6, missing

        # v7: the identity of an *effect*, as distinct from the identity of an
        # attempt.
        #
        # `intent_key` is `{run_id}:{step_id}`, so it is unique per attempt and
        # can never detect a duplicate: a retry after a crash, a second worker,
        # and the same action issued twice each produce a different key and
        # never collide. `effect_key` is a hash of what the action is, so the
        # same effect claims the same key on any host in any run, and a unique
        # constraint on it is sufficient to make the effect happen once.
        #
        # NULL for every existing row. The unique index is partial so those rows
        # are excluded rather than forced to collide on backfill: a backfill
        # would have to guess an effect identity for history it never saw, and a
        # wrong guess silently suppresses a real action.
        seen_receipts = self._columns("receipts")
        if not seen_receipts:
            yield 7, []
        else:
            yield 7, [
                "ALTER TABLE receipts ADD COLUMN effect_key TEXT",
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_receipts_effect "
                "ON receipts(effect_key) WHERE effect_key IS NOT NULL",
            ] if "effect_key" not in seen_receipts else []

    def append_trace(self, event: TraceEvent, *, enforcement: str | None = None) -> int:
        """Persist a trace event after deterministic redaction.

        `enforcement` records which path produced this event: "enforced" when a
        session checked it, "observe" when the run only recorded it.
        """
        with self.connection() as connection:
            connection.execute(
                """
                INSERT INTO trace_events(
                    run_id, step, event, input_json, output_json, status,
                    flags_json, capture_class, provider_metadata_json,
                    provider_evidence_json, replay_of_trace_id, enforcement,
                    prompt_json, completion_json, tokens_in, tokens_out,
                    cost_usd, latency_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.run_id,
                    event.step,
                    event.event,
                    json.dumps(redact(event.input), default=str),
                    json.dumps(redact(event.output), default=str),
                    event.status,
                    json.dumps(list(event.flags), sort_keys=True),
                    event.capture_class,
                    json.dumps(redact(event.provider_metadata or {}), sort_keys=True),
                    json.dumps(redact(event.provider_evidence or {}), sort_keys=True),
                    event.replay_of_trace_id,
                    enforcement,
                    # Prompts carry whatever the user typed, so they go through
                    # the same recursive redaction as every other field rather
                    # than being trusted because they are "just text".
                    json.dumps(redact(event.prompt), default=str)
                    if event.prompt is not None
                    else None,
                    json.dumps(redact(event.completion), default=str)
                    if event.completion is not None
                    else None,
                    event.tokens_in,
                    event.tokens_out,
                    event.cost_usd,
                    event.latency_ms,
                ),
            )
            return int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])

    def append_replay(self, original_trace_id: int, event: TraceEvent) -> int:
        """Append a new trace linked to an original trace without mutating it."""
        if event.replay_of_trace_id is not None:
            raise ValueError("replay event already has a replay source")
        if self._trace_row(original_trace_id) is None:
            raise KeyError(f"unknown trace: {original_trace_id}")
        return self.append_trace(
            TraceEvent(
                run_id=event.run_id,
                step=event.step,
                event=event.event,
                input=event.input,
                output=event.output,
                status=event.status,
                flags=event.flags,
                capture_class=event.capture_class,
                provider_metadata=event.provider_metadata,
                provider_evidence=event.provider_evidence,
                replay_of_trace_id=original_trace_id,
                prompt=event.prompt,
                completion=event.completion,
                tokens_in=event.tokens_in,
                tokens_out=event.tokens_out,
                cost_usd=event.cost_usd,
                latency_ms=event.latency_ms,
            )
        )

    def _trace_row(self, trace_id: int) -> sqlite3.Row | None:
        with self.connection() as connection:
            return connection.execute(
                "SELECT * FROM trace_events WHERE id = ?", (trace_id,)
            ).fetchone()

    def load_clarification_state(self, run_id: str) -> dict[str, Any] | None:
        """Load persisted Phase 4 clarification state for a run."""
        with self.connection() as connection:
            row = connection.execute(
                "SELECT attempts, max_attempts, asked_this_turn "
                "FROM clarification_states WHERE run_id = ?",
                (run_id,),
            ).fetchone()
        if row is None:
            return None
        return {
            "attempts": row["attempts"],
            "max_attempts": row["max_attempts"],
            "asked_this_turn": bool(row["asked_this_turn"]),
        }

    def save_clarification_state(self, run_id: str, state: Any) -> None:
        """Persist Phase 4 clarification state atomically for a run."""
        with self.connection() as connection:
            connection.execute(
                """
                INSERT INTO clarification_states(
                    run_id, attempts, max_attempts, asked_this_turn
                ) VALUES (?, ?, ?, ?)
                ON CONFLICT(run_id) DO UPDATE SET
                    attempts=excluded.attempts,
                    max_attempts=excluded.max_attempts,
                    asked_this_turn=excluded.asked_this_turn
                """,
                (
                    run_id,
                    int(state.attempts),
                    int(state.max_attempts),
                    int(bool(state.asked_this_turn)),
                ),
            )

    def append_receipt(self, run_id: str, line: str) -> None:
        """Append a legacy audit receipt without reusing a unique intent key."""
        intent_key = f"phase0:{run_id}:{uuid4()}"
        with self.connection() as connection:
            connection.execute(
                "INSERT INTO receipts(run_id, step_id, intent_key, action, arguments_json, state) VALUES (?, ?, ?, ?, ?, 'done')",
                (run_id, "phase0", intent_key, "legacy", json.dumps({"line": line})),
            )

    def create_receipt(self, run_id: str, step_id: str, action: str, arguments: dict[str, Any]) -> Receipt:
        intent_key = f"{run_id}:{step_id}"
        with self.connection() as connection:
            connection.execute(
                "INSERT INTO receipts(run_id, step_id, intent_key, action, arguments_json, state) VALUES (?, ?, ?, ?, ?, 'unknown') ON CONFLICT(intent_key) DO NOTHING",
                (run_id, step_id, intent_key, action, json.dumps(arguments, sort_keys=True)),
            )
            row = connection.execute("SELECT * FROM receipts WHERE intent_key = ?", (intent_key,)).fetchone()
        if row is None:
            # Explicit rather than `assert`: this is load-bearing control flow
            # and must survive `python -O`.
            raise RuntimeError(f"receipt row missing after upsert: {intent_key}")
        return self._receipt(row)

    def claim_receipt(
        self,
        effect_key: str,
        run_id: str,
        step_id: str,
        action: str,
        arguments: dict[str, Any],
    ) -> tuple[Receipt, bool]:
        """Claim an effect, or report that someone already claimed it.

        Returns `(receipt, is_new)`. `is_new` is true only when this call
        created the row, which is the signal that this caller owns the effect
        and may execute it. A false value means the effect already exists and
        must not be executed again.

        The insert is atomic and the partial unique index on `effect_key`
        resolves the race, so two workers claiming the same effect at the same
        moment produce exactly one winner -- the loser reads back the winner's
        row rather than creating a second one.

        A retry of the *same step* arrives with an `intent_key` that already
        exists. That is not a conflicting effect, it is the same caller asking
        again, so the existing row is returned and `is_new` stays true. Which
        constraint fired is decided by inspecting the row rather than by
        guessing: an effect claimed by a different step is a genuine conflict
        and must report `is_new=False`.
        """
        intent_key = f"{run_id}:{step_id}"
        with self.connection() as connection:
            connection.execute(
                "INSERT INTO receipts(run_id, step_id, intent_key, action, arguments_json,"
                " state, effect_key) VALUES (?, ?, ?, ?, ?, 'pending', ?)"
                " ON CONFLICT DO NOTHING",
                (run_id, step_id, intent_key, action, json.dumps(arguments, sort_keys=True), effect_key),
            )
            row = connection.execute(
                "SELECT * FROM receipts WHERE effect_key = ?", (effect_key,)
            ).fetchone()
            if row is None:
                row = connection.execute(
                    "SELECT * FROM receipts WHERE intent_key = ?", (intent_key,)
                ).fetchone()
        if row is None:
            raise RuntimeError(f"receipt row missing after claim: {effect_key}")
        # The row belongs to this caller only when its step is this step. A row
        # another step created means another worker owns this effect.
        owned = str(row["intent_key"]) == intent_key
        return self._receipt(row), owned

    def mark_done(self, intent_key: str, provider_ref: str | None) -> None:
        with self.connection() as connection:
            connection.execute(
                "UPDATE receipts SET state='done', provider_ref=?, updated_at=CURRENT_TIMESTAMP "
                "WHERE intent_key=? AND state IN ('unknown', 'pending')",
                (provider_ref, intent_key),
            )

    def mark_failed(self, intent_key: str) -> None:
        with self.connection() as connection:
            connection.execute(
                "UPDATE receipts SET state='failed', updated_at=CURRENT_TIMESTAMP "
                "WHERE intent_key=? AND state IN ('unknown', 'pending')",
                (intent_key,),
            )

    def mark_resolved(self, intent_key: str, provider_ref: str | None) -> None:
        with self.connection() as connection:
            connection.execute(
                "UPDATE receipts SET state='resolved', provider_ref=?, updated_at=CURRENT_TIMESTAMP "
                "WHERE intent_key=? AND state IN ('unknown', 'pending')",
                (provider_ref, intent_key),
            )

    def unknown_receipts(self) -> list[Receipt]:
        with self.connection() as connection:
            rows = connection.execute(
                "SELECT * FROM receipts WHERE state IN ('unknown', 'pending') ORDER BY id"
            ).fetchall()
        return [self._receipt(row) for row in rows]

    def snapshot(self) -> dict[str, Any]:
        with self.connection() as connection:
            trace_rows = connection.execute("SELECT * FROM trace_events ORDER BY id").fetchall()
            receipts = []
            for row in connection.execute("SELECT * FROM receipts ORDER BY id"):
                receipt = dict(row)
                # Decoded like traces are. Left raw, the dashboard's arguments
                # column renders the JSON text as a string rather than a
                # structure, and a reader cannot compare two receipts by eye.
                receipt["arguments"] = json.loads(receipt.pop("arguments_json"))
                receipts.append(receipt)
            gates = [dict(row) for row in connection.execute("SELECT * FROM gate_verdicts ORDER BY id")]

        traces = []
        for row in trace_rows:
            trace = dict(row)
            trace["input"] = json.loads(trace.pop("input_json"))
            trace["output"] = json.loads(trace.pop("output_json"))
            trace["flags"] = json.loads(trace.pop("flags_json", "[]"))
            trace["provider_metadata"] = json.loads(trace.pop("provider_metadata_json", "{}"))
            trace["provider_evidence"] = json.loads(trace.pop("provider_evidence_json", "{}"))
            trace["replay_of_trace_id"] = trace.pop("replay_of_trace_id", None)
            # The exchange columns are NULL for rows written before v5, and for
            # every step that never called a model. Absence is meaningful: it
            # means "we were not told", not "it was empty".
            for column, field in (("prompt_json", "prompt"), ("completion_json", "completion")):
                raw = trace.pop(column, None)
                trace[field] = json.loads(raw) if raw is not None else None
            # Three states, not two: captured, never captured, and captured then
            # discarded. Collapsing the last into the middle would leave a reader
            # unable to tell a missing record from a deleted one.
            trace["exchange_pruned_at"] = trace.pop("exchange_pruned_at", None)
            trace["exchange_state"] = (
                "pruned" if trace["exchange_pruned_at"]
                else "captured" if trace["prompt"] is not None or trace["completion"] is not None
                else "never_recorded"
            )
            traces.append(trace)

        return {"traces": traces, "receipts": receipts, "gate_verdicts": gates}

    def record_fuse_snapshot(self, run_id: str, snapshot: Any) -> None:
        with self.connection() as connection:
            connection.execute(
                """
                INSERT INTO run_budgets(
                    run_id, steps_used, dollars_used, elapsed_seconds,
                    tripped, degraded, reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(run_id) DO UPDATE SET
                    steps_used=excluded.steps_used,
                    dollars_used=excluded.dollars_used,
                    elapsed_seconds=excluded.elapsed_seconds,
                    tripped=excluded.tripped,
                    degraded=excluded.degraded,
                    reason=excluded.reason
                """,
                (
                    run_id,
                    int(snapshot.steps_used),
                    float(snapshot.dollars_used),
                    float(snapshot.elapsed_seconds),
                    int(bool(snapshot.tripped)),
                    int(bool(snapshot.degraded)),
                    snapshot.reason,
                ),
            )

    def dashboard_snapshot(self) -> dict[str, Any]:
        snapshot = self.snapshot()
        runs_by_id: dict[str, dict[str, Any]] = {}
        for trace in snapshot["traces"]:
            run = runs_by_id.setdefault(
                trace["run_id"],
                {"run_id": trace["run_id"], "status": trace["status"]},
            )
            if trace["status"] in {"failed", "blocked"}:
                run["status"] = trace["status"]
        with self.connection() as connection:
            budgets = [
                dict(row)
                for row in connection.execute(
                    "SELECT run_id, steps_used, dollars_used, elapsed_seconds, tripped, degraded, reason "
                    "FROM run_budgets ORDER BY run_id"
                )
            ]
        for budget in budgets:
            budget["tripped"] = bool(budget["tripped"])
            budget["degraded"] = bool(budget["degraded"])
        return {
            **snapshot,
            "runs": list(runs_by_id.values()),
            "budgets": budgets,
        }

    def append_gate(self, verdict: GateVerdict) -> None:
        with self.connection() as connection:
            connection.execute(
                "INSERT INTO gate_verdicts(run_id, verdict, score, threshold) VALUES (?, ?, ?, ?)",
                (verdict.run_id, verdict.verdict, verdict.score, verdict.threshold),
            )

    @staticmethod
    def _receipt(row: sqlite3.Row) -> Receipt:
        return Receipt(
            receipt_id=row["id"],
            run_id=row["run_id"],
            step_id=row["step_id"],
            intent_key=row["intent_key"],
            action=row["action"],
            arguments=json.loads(row["arguments_json"]),
            state=row["state"],
            provider_ref=row["provider_ref"],
        )

    # Virtual key management methods
    def prune_exchanges(
        self,
        *,
        older_than_days: float | None = None,
        keep_latest_per_run: int | None = None,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """Drop recorded prompts and completions, keeping the evidence around them.

        Prompts and completions are several times larger than the rest of a trace
        row, so a system recording exchanges grows quickly. That growth is a real
        operational problem -- but so is deleting an audit trail by surprise.

        The rules follow from that:

        - **The row survives.** Only the payload columns are cleared. The action,
          the timing, the cost and the outcome stay, because those are the record
          that something happened.
        - **The pruning is recorded.** `exchange_pruned_at` is stamped, so a
          later reader can tell "this was captured and has since been discarded"
          apart from "this was never captured". A bare NULL cannot say which,
          and that ambiguity is the one this project refuses to create.
        - **Nothing runs automatically.** Pruning is a command someone typed. A
          silent retention policy is a silent deletion of evidence.
        - **Receipts are never touched.** They are the replay record and are small.

        `older_than_days` and `keep_latest_per_run` combine: a row is pruned only
        if it matches *both* when both are given, so "keep the last 10 of each
        run" and "only anything past 30 days" compose instead of fighting.

        `dry_run` reports what would go without changing anything.
        """
        if older_than_days is None and keep_latest_per_run is None:
            raise ValueError(
                "give older_than_days, keep_latest_per_run, or both"
            )
        if older_than_days is not None and older_than_days < 0:
            raise ValueError("older_than_days must not be negative")
        if keep_latest_per_run is not None and keep_latest_per_run < 0:
            raise ValueError("keep_latest_per_run must not be negative")

        with self.connection() as connection:
            rows = connection.execute(
                "SELECT id, run_id, step FROM trace_events "
                "WHERE prompt_json IS NOT NULL OR completion_json IS NOT NULL "
                "ORDER BY run_id, id"
            ).fetchall()

            # Rows arrive ordered by (run_id, id), so walking backwards gives
            # each run's newest rows first and the counter is exact rather than
            # a guess about ordering.
            selected: list[int] = []
            kept_in_run = 0
            previous_run: str | None = None
            for row in reversed(rows):
                run_id, trace_id = str(row["run_id"]), int(row["id"])
                if run_id != previous_run:
                    previous_run, kept_in_run = run_id, 0
                kept_in_run += 1
                if keep_latest_per_run is not None and kept_in_run <= keep_latest_per_run:
                    continue
                if older_than_days is not None:
                    age = _age_days(connection, trace_id)
                    if age is None or age < older_than_days:
                        continue
                selected.append(trace_id)
            selected.sort()

            report = {
                "candidates": len(rows),
                "selected": len(selected),
                "dry_run": dry_run,
                "trace_ids": selected,
            }
            if dry_run or not selected:
                return report

            stamped = datetime.now(UTC).isoformat(timespec="seconds")
            for trace_id in selected:
                connection.execute(
                    "UPDATE trace_events SET prompt_json = NULL, "
                    "completion_json = NULL, exchange_pruned_at = ? WHERE id = ?",
                    (stamped, trace_id),
                )
            report["pruned_at"] = stamped

        # Outside the transaction above, because SQLite refuses to VACUUM from
        # within one. Clearing a column frees pages for reuse but does not return
        # them to the filesystem, so the file keeps its old size and a prune
        # that shrinks nothing reads as a no-op that reported success.
        # PostgreSQL reclaims space on its own; this is SQLite-only.
        if not dry_run and selected and self.backend == "sqlite":
            with closing(self._connect()) as connection, connection:
                connection.execute("VACUUM")
            report["compacted"] = True
        return report


    def save_virtual_key(self, key: str, name: str, routes: list[str], expires_at: float | None, revoked: bool = False) -> None:
        """Save or update a virtual key."""
        import json
        with self.connection() as connection:
            connection.execute(
                """
                INSERT INTO virtual_keys(key, name, routes_json, expires_at, revoked)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    name=excluded.name,
                    routes_json=excluded.routes_json,
                    expires_at=excluded.expires_at,
                    revoked=excluded.revoked
                """,
                (key, name, json.dumps(routes), expires_at, int(revoked)),
            )

    def load_virtual_keys(self) -> list[dict]:
        """Load all virtual keys from the database."""
        import json
        with self.connection() as connection:
            rows = connection.execute(
                # Ordered explicitly. Without it the row order is whatever the
                # engine feels like returning, which differed between SQLite and
                # PostgreSQL -- and any caller comparing two listings would see a
                # difference that is not a difference in the data.
                "SELECT key, name, routes_json, expires_at, revoked "
                "FROM virtual_keys ORDER BY key"
            ).fetchall()
            return [
                {
                    "key": row["key"],
                    "name": row["name"],
                    "routes": json.loads(row["routes_json"]),
                    "expires_at": row["expires_at"],
                    "revoked": bool(row["revoked"]),
                }
                for row in rows
            ]

    def revoke_virtual_key(self, key: str) -> bool:
        """Revoke a virtual key. Returns True if key was found."""
        with self.connection() as connection:
            cursor = connection.execute(
                "UPDATE virtual_keys SET revoked=1 WHERE key=?", (key,)
            )
            return cursor.rowcount > 0



def _age_days(connection: Any, trace_id: int) -> float | None:
    """Days since a row was written, or None if it carries no timestamp."""
    row = connection.execute(
        "SELECT created_at FROM trace_events WHERE id = ?", (trace_id,)
    ).fetchone()
    if row is None:
        return None
    raw = str(row["created_at"] or "").strip()
    if not raw:
        return None
    try:
        stamp = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=UTC)
    return (datetime.now(UTC) - stamp).total_seconds() / 86400.0


def _added_column(statement: str) -> str:
    """Extract the column name from an `ALTER TABLE ... ADD COLUMN x` step."""
    return statement.split("ADD COLUMN", 1)[1].split()[0].strip()
