from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Protocol

from .evaluation_models import GoldenCase


DETERMINISTIC_CHECK_TYPES = frozenset({"exact", "field-equality", "regex"})
DETERMINISTIC_JUDGE_VERSION = "deterministic-judge-v2"


@dataclass(frozen=True)
class JudgeDecision:
    label: str
    score: float
    confidence: float
    rationale: str
    provider: str
    model: str
    judge_version: str
    prompt_version: str
    latency_ms: float = 0.0
    estimated_cost_usd: float = 0.0

    def __post_init__(self) -> None:
        if self.label not in {"pass", "fail"}:
            raise ValueError("judge label must be 'pass' or 'fail'")
        if not 0.0 <= self.score <= 1.0:
            raise ValueError("judge score must be between 0 and 1")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("judge confidence must be between 0 and 1")
        if not self.rationale.strip():
            raise ValueError("judge rationale must be non-empty")


class Judge(Protocol):
    version: str
    prompt_version: str

    def evaluate(self, case: GoldenCase, output: object) -> JudgeDecision:
        ...


class DeterministicJudge:
    """Verifies cases whose expected result can be checked without an LLM."""

    version = DETERMINISTIC_JUDGE_VERSION
    prompt_version = "not-applicable"

    def evaluate(self, case: GoldenCase, output: object) -> JudgeDecision:
        score = self._score(case, output)
        return JudgeDecision(
            label="pass" if score >= 1.0 else "fail",
            score=score,
            confidence=1.0,
            rationale=self._rationale(case, score),
            provider="builtin",
            model="deterministic",
            judge_version=self.version,
            prompt_version=self.prompt_version,
        )

    def _score(self, case: GoldenCase, output: object) -> float:
        if case.check_type == "exact":
            return 1.0 if output == case.expected else 0.0

        if case.check_type == "field-equality":
            if not isinstance(output, dict) or not isinstance(case.expected, dict):
                return 0.0
            if not case.expected:
                return 1.0
            matches = sum(
                output.get(key) == value for key, value in case.expected.items()
            )
            return matches / len(case.expected)

        if case.check_type == "regex":
            return (
                1.0
                if re.search(str(case.expected), str(output), re.IGNORECASE)
                else 0.0
            )

        raise ValueError(
            "deterministic judge cannot evaluate check type: "
            + str(case.check_type)
        )

    @staticmethod
    def _rationale(case: GoldenCase, score: float) -> str:
        if score >= 1.0:
            return "Deterministic check passed."
        return "Deterministic check failed for case " + case.case_id + "."


def is_deterministic(case: GoldenCase) -> bool:
    return case.check_type in DETERMINISTIC_CHECK_TYPES
