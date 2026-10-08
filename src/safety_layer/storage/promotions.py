"""Durable storage for promoted baseline versions."""
from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..evaluation.models import GoldenCase
from ..evidence.failure_wall import FailureGroup
from .base import SqliteStore
from .wall import FailureWallStore

_ALLOWED_CHECK_TYPES = frozenset({"exact", "field-equality", "regex", "rubric"})


@dataclass(frozen=True)
class GoldenCasePromotion:
    """A evaluation golden case promoted from confirmed observability evidence."""

    case: GoldenCase
    failure_group_id: str
    source_trace_ids: tuple[int, ...]
    promoted_at: str


class GoldenCasePromotionStore(SqliteStore):
    """Durable store for human-promoted golden cases and their provenance."""

    store_name = "golden_promotions"

    def __init__(self, path: str | Path = "data/golden-promotions.db") -> None:
        super().__init__(path)

    def _migrations(self):
        yield 1, [
            """
            CREATE TABLE IF NOT EXISTS golden_case_promotions (
                case_id TEXT PRIMARY KEY,
                task_json TEXT NOT NULL,
                expected_json TEXT NOT NULL,
                check_type TEXT NOT NULL,
                source TEXT NOT NULL,
                catastrophic INTEGER NOT NULL,
                rubric_json TEXT NOT NULL,
                failure_group_id TEXT NOT NULL UNIQUE,
                source_trace_ids_json TEXT NOT NULL,
                promoted_at TEXT NOT NULL
            );
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_golden_promotions_group
            ON golden_case_promotions(failure_group_id);
            """,
        ]

    def save(self, promotion: GoldenCasePromotion) -> None:
        if not promotion.case.case_id:
            raise ValueError("golden case_id must be non-empty")
        if promotion.case.check_type not in _ALLOWED_CHECK_TYPES:
            raise ValueError(
                f"unsupported golden check type: {promotion.case.check_type!r}"
            )
        if not promotion.failure_group_id:
            raise ValueError("failure_group_id must be non-empty")
        if not promotion.source_trace_ids:
            raise ValueError("at least one source trace is required")

        with self.connection() as connection:
            existing_case = connection.execute(
                "SELECT 1 FROM golden_case_promotions WHERE case_id = ?",
                (promotion.case.case_id,),
            ).fetchone()
            if existing_case is not None:
                raise ValueError(
                    f"golden case already promoted: {promotion.case.case_id}"
                )

            existing_group = connection.execute(
                "SELECT 1 FROM golden_case_promotions WHERE failure_group_id = ?",
                (promotion.failure_group_id,),
            ).fetchone()
            if existing_group is not None:
                raise ValueError(
                    f"Failure Wall group already promoted: {promotion.failure_group_id}"
                )

            connection.execute(
                """
                INSERT INTO golden_case_promotions (
                    case_id, task_json, expected_json, check_type, source,
                    catastrophic, rubric_json, failure_group_id,
                    source_trace_ids_json, promoted_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    promotion.case.case_id,
                    json.dumps(promotion.case.task, sort_keys=True),
                    json.dumps(promotion.case.expected, sort_keys=True),
                    promotion.case.check_type,
                    promotion.case.source,
                    int(promotion.case.catastrophic),
                    json.dumps(list(promotion.case.rubric), sort_keys=True),
                    promotion.failure_group_id,
                    json.dumps(list(promotion.source_trace_ids)),
                    promotion.promoted_at,
                ),
            )

    def get(self, case_id: str) -> GoldenCasePromotion | None:
        with self.connection() as connection:
            row = connection.execute(
                "SELECT * FROM golden_case_promotions WHERE case_id = ?",
                (case_id,),
            ).fetchone()
        return self._to_promotion(row) if row is not None else None

    def list(self) -> list[GoldenCasePromotion]:
        with self.connection() as connection:
            rows = connection.execute(
                "SELECT * FROM golden_case_promotions ORDER BY promoted_at, case_id"
            ).fetchall()
        return [self._to_promotion(row) for row in rows]

    @staticmethod
    def _to_promotion(row: sqlite3.Row) -> GoldenCasePromotion:
        return GoldenCasePromotion(
            case=GoldenCase(
                case_id=row["case_id"],
                task=json.loads(row["task_json"]),
                expected=json.loads(row["expected_json"]),
                check_type=row["check_type"],
                source=row["source"],
                catastrophic=bool(row["catastrophic"]),
                rubric=tuple(json.loads(row["rubric_json"])),
            ),
            failure_group_id=row["failure_group_id"],
            source_trace_ids=tuple(json.loads(row["source_trace_ids_json"])),
            promoted_at=row["promoted_at"],
        )


def promote_failure_group(
    failure_wall: FailureWallStore,
    promotions: GoldenCasePromotionStore,
    group_id: str,
    *,
    case_id: str,
    task: Any,
    expected: Any,
    check_type: str,
    catastrophic: bool = False,
    rubric: Iterable[str] = (),
) -> GoldenCasePromotion:
    """Promote a confirmed Failure Wall group into a evaluation golden case.

    The expected result is supplied by the human promoting the case. The
    failure trace is evidence, not the expected answer.
    """
    group = failure_wall.get_group(group_id)
    if group is None:
        raise KeyError(f"unknown Failure Wall group: {group_id}")
    _require_confirmed_group(group)

    source_trace_ids = tuple(sorted({record.trace_id for record in group.records}))
    if not source_trace_ids:
        raise ValueError("cannot promote a Failure Wall group without evidence")

    rubric_values = tuple(rubric)
    case = GoldenCase(
        case_id=case_id,
        task=task,
        expected=expected,
        check_type=check_type,
        source=f"failure-wall:{group.group_id}",
        catastrophic=catastrophic,
        rubric=rubric_values,
    )
    promotion = GoldenCasePromotion(
        case=case,
        failure_group_id=group.group_id,
        source_trace_ids=source_trace_ids,
        promoted_at=datetime.now(UTC).isoformat(),
    )
    promotions.save(promotion)
    return promotion


def _require_confirmed_group(group: FailureGroup) -> None:
    if group.state != "confirmed":
        raise ValueError(
            f"Failure Wall group must be confirmed before promotion: {group.group_id}"
        )
