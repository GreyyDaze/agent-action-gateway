import json
import sqlite3
from pathlib import Path
from typing import Any

from .models import GateVerdict, TraceEvent


class TraceStore:
    """Small append-only SQLite store used by Phase 0."""

    def __init__(self, path: str | Path = "data/runtime.db") -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    def _init_db(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS trace_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    step INTEGER NOT NULL,
                    event TEXT NOT NULL,
                    input_json TEXT NOT NULL,
                    output_json TEXT NOT NULL,
                    status TEXT NOT NULL
                )"""
            )
            connection.execute(
                """CREATE TABLE IF NOT EXISTS receipts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    line TEXT NOT NULL
                )"""
            )
            connection.execute(
                """CREATE TABLE IF NOT EXISTS gate_verdicts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    score REAL NOT NULL,
                    threshold REAL NOT NULL
                )"""
            )

    def append_trace(self, event: TraceEvent) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO trace_events(run_id, step, event, input_json, output_json, status) VALUES (?, ?, ?, ?, ?, ?)",
                (event.run_id, event.step, event.event, json.dumps(event.input, default=str), json.dumps(event.output, default=str), event.status),
            )

    def append_receipt(self, run_id: str, line: str) -> None:
        with self._connect() as connection:
            connection.execute("INSERT INTO receipts(run_id, line) VALUES (?, ?)", (run_id, line))

    def append_gate(self, verdict: GateVerdict) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO gate_verdicts(run_id, verdict, score, threshold) VALUES (?, ?, ?, ?)",
                (verdict.run_id, verdict.verdict, verdict.score, verdict.threshold),
            )

    def snapshot(self) -> dict[str, Any]:
        with self._connect() as connection:
            traces = [dict(row) for row in connection.execute("SELECT * FROM trace_events ORDER BY id")]
            receipts = [dict(row) for row in connection.execute("SELECT * FROM receipts ORDER BY id")]
            gates = [dict(row) for row in connection.execute("SELECT * FROM gate_verdicts ORDER BY id")]
        return {"traces": traces, "receipts": receipts, "gate_verdicts": gates}
