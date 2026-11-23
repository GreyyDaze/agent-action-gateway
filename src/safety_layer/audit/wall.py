"""Durable storage for the grouped failure signatures."""
from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable
from pathlib import Path

from safety_layer.audit.failure_wall import FailureGroup, FailureRecord, FailureSignature
from safety_layer.storage.base import SqliteStore


class FailureWallStore(SqliteStore):
    """Durable SQLite repository for observability Failure Wall records and decisions."""

    store_name = "failure_wall"

    def __init__(self, path: str | Path = "data/runtime.db") -> None:
        super().__init__(path)

    def _migrations(self):
        yield 1, ["""
                CREATE TABLE IF NOT EXISTS failure_groups (
                    group_id TEXT PRIMARY KEY,
                    error_type TEXT NOT NULL,
                    failing_step TEXT NOT NULL,
                    config_fingerprint TEXT NOT NULL,
                    state TEXT NOT NULL,
                    ownership TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS failure_records (
                    group_id TEXT NOT NULL,
                    trace_id INTEGER NOT NULL,
                    run_id TEXT NOT NULL,
                    step INTEGER NOT NULL,
                    event TEXT NOT NULL,
                    status TEXT NOT NULL,
                    error_type TEXT NOT NULL,
                    failing_step TEXT NOT NULL,
                    config_fingerprint TEXT NOT NULL,
                    flags_json TEXT NOT NULL DEFAULT '[]',
                    PRIMARY KEY (group_id, trace_id),
                    FOREIGN KEY (group_id) REFERENCES failure_groups(group_id)
                );

                CREATE TABLE IF NOT EXISTS failure_decisions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    group_id TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    details_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (group_id) REFERENCES failure_groups(group_id)
                );

                CREATE INDEX IF NOT EXISTS idx_failure_records_group
                    ON failure_records(group_id);
                CREATE INDEX IF NOT EXISTS idx_failure_decisions_group
                    ON failure_decisions(group_id);
                """]

    def save_group(self, group: FailureGroup) -> None:
        """Create or replace one complete group and its evidence records."""
        with self.connection() as connection:
            connection.execute(
            """
                INSERT INTO failure_groups(
                    group_id, error_type, failing_step, config_fingerprint,
                    state, ownership
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(group_id) DO UPDATE SET
                    error_type=excluded.error_type,
                    failing_step=excluded.failing_step,
                    config_fingerprint=excluded.config_fingerprint,
                    state=excluded.state,
                    ownership=excluded.ownership,
                    updated_at=CURRENT_TIMESTAMP
            """,
            (
                    group.group_id,
                    group.signature.error_type,
                    group.signature.failing_step,
                    group.signature.config_fingerprint,
                    group.state,
                    group.ownership,
                ),
            )
            connection.execute(
                "DELETE FROM failure_records WHERE group_id = ?",
                (group.group_id,),
            )
            connection.executemany(
            """
                INSERT INTO failure_records(
                    group_id, trace_id, run_id, step, event, status,
                    error_type, failing_step, config_fingerprint, flags_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                    (
                        group.group_id,
                        record.trace_id,
                        record.run_id,
                        record.step,
                        record.event,
                        record.status,
                        record.error_type,
                        record.failing_step,
                        record.config_fingerprint,
                        json.dumps(list(record.flags), sort_keys=True),
                    )
                for record in group.records
            ],
        )

    def save_groups(self, groups: Iterable[FailureGroup]) -> None:
        for group in groups:
            self.save_group(group)

    def get_group(self, group_id: str) -> FailureGroup | None:
        with self.connection() as connection:
            group = connection.execute(
                "SELECT * FROM failure_groups WHERE group_id = ?",
                (group_id,),
            ).fetchone()
            if group is None:
                return None
            records = connection.execute(
                "SELECT * FROM failure_records WHERE group_id = ? ORDER BY trace_id",
                (group_id,),
            ).fetchall()
        return self._to_group(group, records)

    def list_groups(self) -> list[FailureGroup]:
        with self.connection() as connection:
            groups = connection.execute(
                "SELECT * FROM failure_groups ORDER BY group_id"
            ).fetchall()
        result: list[FailureGroup] = []
        for row in groups:
            group = self.get_group(row["group_id"])
            if group is not None:
                result.append(group)
        return result

    def _record_decision(
        self,
        connection: sqlite3.Connection,
        group_id: str,
        decision: str,
        details: dict | None = None,
    ) -> None:
        connection.execute(
            """
            INSERT INTO failure_decisions(group_id, decision, details_json)
            VALUES (?, ?, ?)
            """,
            (group_id, decision, json.dumps(details or {}, sort_keys=True)),
        )

    def confirm(self, group_id: str) -> FailureGroup:
        return self._set_state(group_id, "confirmed", "confirm")

    def reject(self, group_id: str) -> FailureGroup:
        return self._set_state(group_id, "rejected", "reject")

    def _set_state(self, group_id: str, state: str, decision: str) -> FailureGroup:
        with self.connection() as connection:
            exists = connection.execute(
                "SELECT 1 FROM failure_groups WHERE group_id = ?",
                (group_id,),
            ).fetchone()
            if exists is None:
                raise KeyError(f"unknown failure group: {group_id}")
            connection.execute(
                """
                UPDATE failure_groups
                SET state = ?, ownership = 'unknown', updated_at = CURRENT_TIMESTAMP
                WHERE group_id = ?
                """,
                (state, group_id),
            )
            self._record_decision(connection, group_id, decision)
        group = self.get_group(group_id)
        if group is None:
            raise RuntimeError(f"failure group missing after decision: {group_id}")
        return group

    def merge(self, group_ids: Iterable[str], merged: FailureGroup) -> FailureGroup:
        selected = list(group_ids)
        if len(selected) < 2:
            raise ValueError("merge requires at least two group ids")

        with self.connection() as connection:
            placeholders = ",".join("?" for _ in selected)
            rows = connection.execute(
                f"SELECT group_id FROM failure_groups WHERE group_id IN ({placeholders})",
                selected,
            ).fetchall()
            if len(rows) != len(set(selected)):
                raise KeyError("merge includes an unknown failure group")

            self.save_group(merged)
            for group_id in selected:
                self._record_decision(
                    connection,
                    group_id,
                    "merge",
                    {"merged_into": merged.group_id},
                )
                if group_id != merged.group_id:
                    connection.execute(
                        """
                        UPDATE failure_groups
                        SET state = 'merged', updated_at = CURRENT_TIMESTAMP
                        WHERE group_id = ?
                        """,
                        (group_id,),
                    )
        return self.get_group(merged.group_id) or merged

    def split(
        self,
        group_id: str,
        groups: Iterable[FailureGroup],
    ) -> list[FailureGroup]:
        new_groups = list(groups)
        if not new_groups:
            raise ValueError("split requires at least one resulting group")

        with self.connection() as connection:
            exists = connection.execute(
                "SELECT 1 FROM failure_groups WHERE group_id = ?",
                (group_id,),
            ).fetchone()
            if exists is None:
                raise KeyError(f"unknown failure group: {group_id}")

            for group in new_groups:
                self.save_group(group)
            self._record_decision(
                connection,
                group_id,
                "split",
                {"result_groups": [group.group_id for group in new_groups]},
            )
            connection.execute(
                """
                UPDATE failure_groups
                SET state = 'split', updated_at = CURRENT_TIMESTAMP
                WHERE group_id = ?
                """,
                (group_id,),
            )

        return [
            self.get_group(group.group_id) or group
            for group in new_groups
        ]

    def decisions(self, group_id: str) -> list[dict]:
        with self.connection() as connection:
            rows = connection.execute(
                """
                SELECT id, group_id, decision, details_json, created_at
                FROM failure_decisions
                WHERE group_id = ?
                ORDER BY id
                """,
                (group_id,),
            ).fetchall()
        return [
            {
                "id": row["id"],
                "group_id": row["group_id"],
                "decision": row["decision"],
                "details": json.loads(row["details_json"]),
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    @staticmethod
    def _to_group(row: sqlite3.Row, records: list[sqlite3.Row]) -> FailureGroup:
        return FailureGroup(
            group_id=row["group_id"],
            signature=FailureSignature(
                error_type=row["error_type"],
                failing_step=row["failing_step"],
                config_fingerprint=row["config_fingerprint"],
            ),
            records=[
                FailureRecord(
                    trace_id=record["trace_id"],
                    run_id=record["run_id"],
                    step=record["step"],
                    event=record["event"],
                    status=record["status"],
                    error_type=record["error_type"],
                    failing_step=record["failing_step"],
                    config_fingerprint=record["config_fingerprint"],
                    flags=tuple(json.loads(record["flags_json"])),
                )
                for record in records
            ],
            ownership=row["ownership"],
            state=row["state"],
        )
