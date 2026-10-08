"""The golden set of labelled agent outputs."""
from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .models import GOLDEN_SET_VERSION, GoldenCase

if TYPE_CHECKING:
    from .golden_promotion import GoldenCasePromotionStore


GOLDEN_SET_RESOURCE = "data/golden/golden-v1.json"
_ALLOWED_CHECK_TYPES = frozenset({"exact", "field-equality", "regex", "rubric"})

# A golden set has to be large enough for a baseline comparison to mean
# something. This is a floor, not a target: the shipped set is an example,
# and an adopter's own set is free to be any size at or above it.
MIN_GOLDEN_CASES = 10


def default_golden_set_path() -> Path:
    """Materialize the packaged golden set and return its concrete path.

    The JSON ships as package data, so this works from a wheel, an editable
    install, and a source checkout without guessing a filesystem layout.
    """
    # The artifacts ship inside the installed package, one level above this
    # module. Resolving from __file__ works identically from a wheel, an
    # editable install and a source checkout, and needs no filesystem guessing.
    package_root = Path(__file__).resolve().parent.parent
    return package_root / GOLDEN_SET_RESOURCE


def load_golden_set(path: str | Path | None = None) -> tuple[GoldenCase, ...]:
    artifact_path = Path(path) if path is not None else default_golden_set_path()
    try:
        payload = json.loads(artifact_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"no case file at {artifact_path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"{artifact_path} is not valid JSON: {exc}") from exc

    if not isinstance(payload, dict):
        raise ValueError(f"the top level of {artifact_path} must be a JSON object")

    version = payload.get("version")
    if version != GOLDEN_SET_VERSION:
        raise ValueError(
            f'unsupported "version": {version!r}; this build reads '
            f'"{GOLDEN_SET_VERSION}" only'
        )

    raw_cases = payload.get("cases")
    if not isinstance(raw_cases, list) or not raw_cases:
        raise ValueError('the "cases" key must be a non-empty list')

    cases: list[GoldenCase] = []
    seen_ids: set[str] = set()

    for raw_case in raw_cases:
        cases.append(_parse_case(raw_case, seen_ids))

    if len(cases) < MIN_GOLDEN_CASES:
        raise ValueError(
            f"only {len(cases)} cases found; at least {MIN_GOLDEN_CASES} are "
            f"needed for the comparison against the previous run to mean anything"
        )
    if not any(case.catastrophic for case in cases):
        raise ValueError('no case sets "catastrophic": true, so a serious failure would be averaged away instead of stopping the release')

    return tuple(cases)


def _parse_case(raw_case: Any, seen_ids: set[str]) -> GoldenCase:
    if not isinstance(raw_case, dict):
        raise ValueError("every entry in \"cases\" must be a JSON object")

    required = ("case_id", "task", "expected", "check_type", "source")
    missing = [field for field in required if field not in raw_case]
    if missing:
        raise ValueError(
            "case is missing required field(s): " + ", ".join(missing)
        )

    case_id = raw_case["case_id"]
    check_type = raw_case["check_type"]
    if not isinstance(case_id, str) or not case_id:
        raise ValueError('"case_id" must be a non-empty string')
    if case_id in seen_ids:
        raise ValueError(f'two cases share the case_id "{case_id}"; each must be unique')
    if check_type not in _ALLOWED_CHECK_TYPES:
        allowed = ", ".join(sorted(_ALLOWED_CHECK_TYPES))
        raise ValueError(f'unsupported "check_type": {check_type!r}; use one of {allowed}')

    seen_ids.add(case_id)
    rubric = raw_case.get("rubric", [])
    if not isinstance(rubric, list) or not all(isinstance(item, str) for item in rubric):
        raise ValueError(f'the "rubric" for case "{case_id}" must be a list of strings')

    return GoldenCase(
        case_id=case_id,
        task=raw_case["task"],
        expected=raw_case["expected"],
        check_type=check_type,
        source=raw_case["source"],
        catastrophic=bool(raw_case.get("catastrophic", False)),
        rubric=tuple(rubric),
    )


def load_golden_cases(
    path: str | Path | None = None,
    *,
    promotion_store: GoldenCasePromotionStore | None = None,
) -> tuple[GoldenCase, ...]:
    """Load canonical golden-v1 cases plus explicitly promoted failures."""
    cases = list(load_golden_set(path))
    if promotion_store is None:
        return tuple(cases)

    existing_ids = {case.case_id for case in cases}
    for promotion in promotion_store.list():
        if promotion.case.case_id in existing_ids:
            raise ValueError(
                f'case_id "{promotion.case.case_id}" appears both in the case file '
                f"and among promoted cases; each must be unique"
            )
        cases.append(promotion.case)
        existing_ids.add(promotion.case.case_id)

    return tuple(cases)


def seed_golden_cases() -> tuple[GoldenCase, ...]:
    """Backward-compatible name for the canonical versioned golden set."""
    return load_golden_set()


def case_count() -> int:
    return len(load_golden_set())
