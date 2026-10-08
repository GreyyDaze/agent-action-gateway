from __future__ import annotations

from pathlib import Path

from ..evaluation.models import Baseline, EvaluationSummary, GateResult
from .base import SqliteStore


class EvaluationStore(SqliteStore):
    """Durable local history for evaluation runs and false-alarm evidence."""

    store_name = "evaluations"

    def __init__(self, path: str | Path = "data/evaluations.db") -> None:
        super().__init__(path)

    def _migrations(self):
        yield 1, ["""
                CREATE TABLE IF NOT EXISTS evaluation_runs (
                    evaluation_id TEXT PRIMARY KEY,
                    candidate_version TEXT NOT NULL,
                    golden_set_version TEXT NOT NULL,
                    lane TEXT NOT NULL,
                    judge_version TEXT NOT NULL,
                    judge_prompt_version TEXT NOT NULL,
                    judge_provider TEXT NOT NULL DEFAULT '',
                    judge_model TEXT NOT NULL DEFAULT '',
                    baseline_score REAL NOT NULL,
                    observed_score REAL NOT NULL,
                    noise_estimate REAL NOT NULL,
                    verdict TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    cases_evaluated INTEGER NOT NULL,
                    runs_per_case INTEGER NOT NULL,
                    estimated_cost_usd REAL NOT NULL,
                    runtime_minutes REAL NOT NULL,
                    reason TEXT NOT NULL,
                    catastrophic_failure INTEGER NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS false_alarm_ledger (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    evaluation_id TEXT NOT NULL,
                    candidate_version TEXT NOT NULL,
                    lane TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS baselines (
                    lane TEXT PRIMARY KEY,
                    candidate_version TEXT NOT NULL,
                    golden_set_version TEXT NOT NULL,
                    judge_version TEXT NOT NULL,
                    judge_prompt_version TEXT NOT NULL,
                    judge_provider TEXT NOT NULL DEFAULT '',
                    judge_model TEXT NOT NULL DEFAULT '',
                    score REAL NOT NULL,
                    cases_evaluated INTEGER NOT NULL,
                    runs_per_case INTEGER NOT NULL,
                    estimated_cost_usd REAL NOT NULL,
                    runtime_minutes REAL NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_evaluation_runs_created
                    ON evaluation_runs(created_at);
                CREATE INDEX IF NOT EXISTS idx_false_alarm_created
                    ON false_alarm_ledger(created_at);
                """]
        # Provider/model identity columns were added after the first release so
        # provider and model identity can be recorded without recreating the table.
        additions = []
        for table in ("evaluation_runs", "baselines"):
            if not self._table_exists(table):
                continue
            existing = self._columns(table)
            for name in ("judge_provider", "judge_model"):
                if name not in existing:
                    additions.append(
                        f"ALTER TABLE {table} ADD COLUMN {name} TEXT NOT NULL DEFAULT ''"
                    )
        yield 2, additions

    def record(self, evaluation_id: str, summary: EvaluationSummary, result: GateResult) -> None:
        with self.connection() as connection:
            connection.execute(
                """
                INSERT INTO evaluation_runs (
                    evaluation_id, candidate_version, golden_set_version,
                    lane, judge_version, judge_prompt_version,
                    judge_provider, judge_model,
                    baseline_score, observed_score, noise_estimate,
                    verdict, confidence, cases_evaluated, runs_per_case,
                    estimated_cost_usd, runtime_minutes, reason,
                    catastrophic_failure
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    evaluation_id,
                    summary.candidate_version,
                    summary.golden_set_version,
                    result.lane,
                    result.judge_version,
                    result.judge_prompt_version,
                    summary.judge_provider,
                    summary.judge_model,
                    result.baseline_score,
                    result.observed_score,
                    result.noise_estimate,
                    result.verdict,
                    result.confidence,
                    result.cases_evaluated,
                    result.runs_per_case,
                    result.estimated_cost_usd,
                    result.runtime_minutes,
                    result.reason,
                    int(result.catastrophic_failure),
                ),
            )

    def record_false_alarm(self, evaluation_id: str, summary: EvaluationSummary, result: GateResult) -> None:
        if result.verdict != "FAIL":
            return
        with self.connection() as connection:
            connection.execute(
                """
                INSERT INTO false_alarm_ledger (
                    evaluation_id, candidate_version, lane, verdict, reason
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    evaluation_id,
                    summary.candidate_version,
                    result.lane,
                    result.verdict,
                    result.reason,
                ),
            )

    def evaluation_count(self) -> int:
        with self.connection() as connection:
            row = connection.execute(
                "SELECT COUNT(*) AS count FROM evaluation_runs"
            ).fetchone()
        if row is None:
            raise RuntimeError("evaluation_runs count query returned no row")
        return int(row["count"])

    def false_alarm_count(self) -> int:
        with self.connection() as connection:
            row = connection.execute(
                "SELECT COUNT(*) AS count FROM false_alarm_ledger"
            ).fetchone()
        if row is None:
            raise RuntimeError("false_alarm_ledger count query returned no row")
        return int(row["count"])

    def save_baseline(self, baseline: Baseline) -> None:
        with self.connection() as connection:
            connection.execute(
                """
                INSERT INTO baselines (
                    lane, candidate_version, golden_set_version,
                    judge_version, judge_prompt_version, judge_provider, judge_model, score,
                    cases_evaluated, runs_per_case,
                    estimated_cost_usd, runtime_minutes, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(lane) DO UPDATE SET
                    candidate_version=excluded.candidate_version,
                    golden_set_version=excluded.golden_set_version,
                    judge_version=excluded.judge_version,
                    judge_prompt_version=excluded.judge_prompt_version,
                    judge_provider=excluded.judge_provider,
                    judge_model=excluded.judge_model,
                    score=excluded.score,
                    cases_evaluated=excluded.cases_evaluated,
                    runs_per_case=excluded.runs_per_case,
                    estimated_cost_usd=excluded.estimated_cost_usd,
                    runtime_minutes=excluded.runtime_minutes,
                    created_at=excluded.created_at
                """,
                (
                    baseline.lane,
                    baseline.candidate_version,
                    baseline.golden_set_version,
                    baseline.judge_version,
                    baseline.judge_prompt_version,
                    baseline.judge_provider,
                    baseline.judge_model,
                    baseline.score,
                    baseline.cases_evaluated,
                    baseline.runs_per_case,
                    baseline.estimated_cost_usd,
                    baseline.runtime_minutes,
                    baseline.created_at,
                ),
            )

    def get_baseline(self, lane: str) -> Baseline | None:
        with self.connection() as connection:
            row = connection.execute(
                "SELECT * FROM baselines WHERE lane = ?", (lane,)
            ).fetchone()
        if row is None:
            return None
        return Baseline(
            lane=row["lane"],
            candidate_version=row["candidate_version"],
            golden_set_version=row["golden_set_version"],
            judge_version=row["judge_version"],
            judge_prompt_version=row["judge_prompt_version"],
            score=row["score"],
            judge_provider=row["judge_provider"],
            judge_model=row["judge_model"],
            cases_evaluated=row["cases_evaluated"],
            runs_per_case=row["runs_per_case"],
            estimated_cost_usd=row["estimated_cost_usd"],
            runtime_minutes=row["runtime_minutes"],
            created_at=row["created_at"],
        )
