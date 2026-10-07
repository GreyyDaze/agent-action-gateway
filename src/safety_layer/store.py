import json
import sqlite3
from pathlib import Path
from typing import Any
from uuid import uuid4

from .models import GateVerdict, Receipt, TraceEvent
from .phase6_trace import redact


class TraceStore:
    # Clarification state is persisted with the run to prevent safety-budget resets.
    """Durable SQLite store for the self-hosted single-node production path."""

    def __init__(self, path: str | Path = "data/runtime.db") -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    def _init_db(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
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
            )
            columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(trace_events)").fetchall()
            }
            migrations = {
                "flags_json": "ALTER TABLE trace_events ADD COLUMN flags_json TEXT NOT NULL DEFAULT '[]'",
                "capture_class": "ALTER TABLE trace_events ADD COLUMN capture_class TEXT NOT NULL DEFAULT 'always'",
                "provider_metadata_json": "ALTER TABLE trace_events ADD COLUMN provider_metadata_json TEXT NOT NULL DEFAULT '{}'",
                "provider_evidence_json": "ALTER TABLE trace_events ADD COLUMN provider_evidence_json TEXT NOT NULL DEFAULT '{}'",
                "replay_of_trace_id": "ALTER TABLE trace_events ADD COLUMN replay_of_trace_id INTEGER",
            }
            for name, statement in migrations.items():
                if name not in columns:
                    connection.execute(statement)

            connection.executescript(
                """
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
            )

    def append_trace(self, event: TraceEvent) -> int:
        """Persist a trace event after deterministic redaction."""
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO trace_events(
                    run_id, step, event, input_json, output_json, status,
                    flags_json, capture_class, provider_metadata_json,
                    provider_evidence_json, replay_of_trace_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            )
        )

    def _trace_row(self, trace_id: int) -> sqlite3.Row | None:
        with self._connect() as connection:
            return connection.execute(
                "SELECT * FROM trace_events WHERE id = ?", (trace_id,)
            ).fetchone()

    def load_clarification_state(self, run_id: str) -> dict[str, Any] | None:
        """Load persisted Phase 4 clarification state for a run."""
        with self._connect() as connection:
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
        with self._connect() as connection:
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
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO receipts(run_id, step_id, intent_key, action, arguments_json, state) VALUES (?, ?, ?, ?, ?, 'done')",
                (run_id, "phase0", intent_key, "legacy", json.dumps({"line": line})),
            )

    def create_receipt(self, run_id: str, step_id: str, action: str, arguments: dict[str, Any]) -> Receipt:
        intent_key = f"{run_id}:{step_id}"
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO receipts(run_id, step_id, intent_key, action, arguments_json, state) VALUES (?, ?, ?, ?, ?, 'unknown') ON CONFLICT(intent_key) DO NOTHING",
                (run_id, step_id, intent_key, action, json.dumps(arguments, sort_keys=True)),
            )
            row = connection.execute("SELECT * FROM receipts WHERE intent_key = ?", (intent_key,)).fetchone()
        assert row is not None
        return self._receipt(row)

    def mark_done(self, intent_key: str, provider_ref: str | None) -> None:
        with self._connect() as connection:
            connection.execute(
                "UPDATE receipts SET state='done', provider_ref=?, updated_at=CURRENT_TIMESTAMP WHERE intent_key=? AND state='unknown'",
                (provider_ref, intent_key),
            )

    def mark_failed(self, intent_key: str) -> None:
        with self._connect() as connection:
            connection.execute(
                "UPDATE receipts SET state='failed', updated_at=CURRENT_TIMESTAMP WHERE intent_key=? AND state='unknown'",
                (intent_key,),
            )

    def mark_resolved(self, intent_key: str, provider_ref: str | None) -> None:
        with self._connect() as connection:
            connection.execute(
                "UPDATE receipts SET state='resolved', provider_ref=?, updated_at=CURRENT_TIMESTAMP WHERE intent_key=? AND state='unknown'",
                (provider_ref, intent_key),
            )

    def unknown_receipts(self) -> list[Receipt]:
        with self._connect() as connection:
            rows = connection.execute("SELECT * FROM receipts WHERE state='unknown' ORDER BY id").fetchall()
        return [self._receipt(row) for row in rows]

    def snapshot(self) -> dict[str, Any]:
        with self._connect() as connection:
            trace_rows = connection.execute("SELECT * FROM trace_events ORDER BY id").fetchall()
            receipts = [dict(row) for row in connection.execute("SELECT * FROM receipts ORDER BY id")]
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
            traces.append(trace)

        return {"traces": traces, "receipts": receipts, "gate_verdicts": gates}

    def record_fuse_snapshot(self, run_id: str, snapshot: Any) -> None:
        with self._connect() as connection:
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
        with self._connect() as connection:
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
        with self._connect() as connection:
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


