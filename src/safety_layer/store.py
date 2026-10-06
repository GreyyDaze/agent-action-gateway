import json
import sqlite3
from pathlib import Path
from typing import Any

from .models import GateVerdict, Receipt, TraceEvent


class TraceStore:
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
                    status TEXT NOT NULL
                );
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
                """
            )

    def append_trace(self, event: TraceEvent) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO trace_events(run_id, step, event, input_json, output_json, status) VALUES (?, ?, ?, ?, ?, ?)",
                (event.run_id, event.step, event.event, json.dumps(event.input, default=str), json.dumps(event.output, default=str), event.status),
            )

    def append_receipt(self, run_id: str, line: str) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO receipts(run_id, step_id, intent_key, action, arguments_json, state) VALUES (?, ?, ?, ?, ?, ?)",
                (run_id, "phase0", f"phase0:{run_id}", "legacy", json.dumps({"line": line}), "done"),
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
            traces = [dict(row) for row in connection.execute("SELECT * FROM trace_events ORDER BY id")]
            receipts = [dict(row) for row in connection.execute("SELECT * FROM receipts ORDER BY id")]
            gates = [dict(row) for row in connection.execute("SELECT * FROM gate_verdicts ORDER BY id")]
        return {"traces": traces, "receipts": receipts, "gate_verdicts": gates}

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
