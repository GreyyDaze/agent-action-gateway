"""Judge calibration against a labelled set."""
from __future__ import annotations

import json
from pathlib import Path

from safety_layer.eval.models import CALIBRATION_SET_VERSION, CalibrationExample

CALIBRATION_SET_RESOURCE = "data/calibration/calibration-v1.json"


def default_calibration_set_path() -> Path:
    """Materialize the packaged calibration set and return its concrete path.

    The JSON ships as package data, so this works from a wheel, an editable
    install, and a source checkout without guessing a filesystem layout.
    """
    # The artifacts ship inside the installed package, one level above this
    # module. Resolving from __file__ works identically from a wheel, an
    # editable install and a source checkout, and needs no filesystem guessing.
    package_root = Path(__file__).resolve().parent.parent
    return package_root / CALIBRATION_SET_RESOURCE


def load_calibration_set(
    path: str | Path | None = None,
) -> tuple[CalibrationExample, ...]:
    artifact_path = Path(path) if path is not None else default_calibration_set_path()
    try:
        payload = json.loads(artifact_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"calibration set not found: {artifact_path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"calibration set is not valid JSON: {artifact_path}"
        ) from exc

    if not isinstance(payload, dict):
        raise ValueError("calibration set must be a JSON object")
    if payload.get("version") != CALIBRATION_SET_VERSION:
        raise ValueError(
            f"unsupported calibration set version: {payload.get('version')!r}; "
            f"expected {CALIBRATION_SET_VERSION!r}"
        )

    raw_examples = payload.get("examples")
    if not isinstance(raw_examples, list) or not raw_examples:
        raise ValueError("calibration set must contain a non-empty examples array")

    examples: list[CalibrationExample] = []
    seen_ids: set[str] = set()
    seen_pairs: set[tuple[str, str]] = set()

    for raw in raw_examples:
        if not isinstance(raw, dict):
            raise ValueError("each calibration example must be a JSON object")

        required = ("example_id", "case_id", "output", "label", "rationale")
        missing = [field for field in required if field not in raw]
        if missing:
            raise ValueError(
                f"calibration example missing fields: {', '.join(missing)}"
            )

        example_id = raw["example_id"]
        case_id = raw["case_id"]
        label = raw["label"]
        rationale = raw["rationale"]

        if not isinstance(example_id, str) or not example_id:
            raise ValueError("calibration example_id must be a non-empty string")
        if example_id in seen_ids:
            raise ValueError(f"duplicate calibration example_id: {example_id}")
        if not isinstance(case_id, str) or not case_id:
            raise ValueError("calibration case_id must be a non-empty string")
        if label not in {"pass", "fail"}:
            raise ValueError(
                f"calibration label must be 'pass' or 'fail': {example_id}"
            )
        if not isinstance(rationale, str) or not rationale:
            raise ValueError(
                f"calibration rationale must be a non-empty string: {example_id}"
            )

        pair = (case_id, label)
        if pair in seen_pairs:
            raise ValueError(
                f"duplicate calibration label for case: {case_id} ({label})"
            )

        seen_ids.add(example_id)
        seen_pairs.add(pair)
        examples.append(
            CalibrationExample(
                example_id=example_id,
                case_id=case_id,
                output=raw["output"],
                label=label,
                rationale=rationale,
            )
        )

    return tuple(examples)


def calibration_case_ids(
    path: str | Path | None = None,
) -> tuple[str, ...]:
    return tuple(dict.fromkeys(example.case_id for example in load_calibration_set(path)))


def run_calibration(cases, judge):
    """Compare the configured judge with human-labeled calibration examples."""
    from time import perf_counter

    from safety_layer.eval.judge import JudgeUnavailableError
    from safety_layer.eval.models import CalibrationResult

    by_id = {case.case_id: case for case in cases}
    examples = load_calibration_set()
    started = perf_counter()
    agreed = 0
    cost = 0.0

    for example in examples:
        case = by_id.get(example.case_id)
        if case is None:
            raise ValueError(f'unknown case_id "{example.case_id}"')
        try:
            decision = judge.evaluate(case, example.output)
        except JudgeUnavailableError:
            raise
        agreed += decision.label == example.label
        cost += decision.estimated_cost_usd

    return CalibrationResult(
        total=len(examples),
        agreed=agreed,
        agreement=agreed / len(examples),
        judge_version=judge.version,
        judge_prompt_version=judge.prompt_version,
        estimated_cost_usd=cost,
        runtime_seconds=perf_counter() - started,
    )
