from __future__ import annotations

import re
from typing import Protocol

from .evaluation_models import GoldenCase, JUDGE_PROMPT_VERSION, JUDGE_VERSION


DETERMINISTIC_CHECK_TYPES = frozenset({"exact", "field-equality", "regex"})


class Judge(Protocol):
    """Interface for rubric-based evaluation controlled by this product."""

    version: str
    prompt_version: str

    def score(self, case: GoldenCase, output: object) -> float:
        ...


class DeterministicJudge:
    """Verifies cases whose expected result can be checked without an LLM."""

    version = JUDGE_VERSION
    prompt_version = JUDGE_PROMPT_VERSION

    def score(self, case: GoldenCase, output: object) -> float:
        if case.check_type == "exact":
            return 1.0 if output == case.expected else 0.0

        if case.check_type == "field-equality":
            if not isinstance(output, dict) or not isinstance(case.expected, dict):
                return 0.0
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
            f"{case.check_type}"
        )


def is_deterministic(case: GoldenCase) -> bool:
    return case.check_type in DETERMINISTIC_CHECK_TYPES
