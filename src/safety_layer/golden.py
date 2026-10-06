from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .evaluation_models import GOLDEN_SET_VERSION, GoldenCase


DEFAULT_GOLDEN_SET_PATH = (
    Path(__file__).resolve().parents[2] / "data" / "golden" / "golden-v1.json"
)
_ALLOWED_CHECK_TYPES = frozenset({"exact", "field-equality", "regex", "rubric"})


def load_golden_set(path: str | Path = DEFAULT_GOLDEN_SET_PATH) -> tuple[GoldenCase, ...]:
    artifact_path = Path(path)
    try:
        payload = json.loads(artifact_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"golden set not found: {artifact_path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"golden set is not valid JSON: {artifact_path}") from exc

    if not isinstance(payload, dict):
        raise ValueError("golden set must be a JSON object")

    version = payload.get("version")
    if version != GOLDEN_SET_VERSION:
        raise ValueError(
            f"unsupported golden set version: {version!r}; "
            f"expected {GOLDEN_SET_VERSION!r}"
        )

    raw_cases = payload.get("cases")
    if not isinstance(raw_cases, list) or not raw_cases:
        raise ValueError("golden set must contain a non-empty cases array")

    cases: list[GoldenCase] = []
    seen_ids: set[str] = set()

    for raw_case in raw_cases:
        cases.append(_parse_case(raw_case, seen_ids))

    if len(cases) != 30:
        raise ValueError(f"golden-v1 must contain exactly 30 cases, got {len(cases)}")
    if not any(case.catastrophic for case in cases):
        raise ValueError("golden-v1 must contain at least one catastrophic case")

    return tuple(cases)


def _parse_case(raw_case: Any, seen_ids: set[str]) -> GoldenCase:
    if not isinstance(raw_case, dict):
        raise ValueError("each golden case must be a JSON object")

    required = ("case_id", "task", "expected", "check_type", "source")
    missing = [field for field in required if field not in raw_case]
    if missing:
        raise ValueError(f"golden case missing fields: {', '.join(missing)}")

    case_id = raw_case["case_id"]
    check_type = raw_case["check_type"]
    if not isinstance(case_id, str) or not case_id:
        raise ValueError("golden case_id must be a non-empty string")
    if case_id in seen_ids:
        raise ValueError(f"duplicate golden case_id: {case_id}")
    if check_type not in _ALLOWED_CHECK_TYPES:
        raise ValueError(f"unsupported golden check type: {check_type!r}")

    seen_ids.add(case_id)
    rubric = raw_case.get("rubric", [])
    if not isinstance(rubric, list) or not all(isinstance(item, str) for item in rubric):
        raise ValueError(f"golden rubric must be a string list: {case_id}")

    return GoldenCase(
        case_id=case_id,
        task=raw_case["task"],
        expected=raw_case["expected"],
        check_type=check_type,
        source=raw_case["source"],
        catastrophic=bool(raw_case.get("catastrophic", False)),
        rubric=tuple(rubric),
    )


def seed_golden_cases() -> tuple[GoldenCase, ...]:
    """Backward-compatible name for the canonical versioned golden set."""
    return load_golden_set()


def case_count() -> int:
    return len(load_golden_set())
