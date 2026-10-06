from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .evaluation_models import Baseline, GoldenCase
from .evaluation_store import EvaluationStore
from .evaluator import evaluate_cases
from .gemini_judge import GeminiRubricJudgeProvider
from .golden import seed_golden_cases
from .calibration import run_calibration
from .gate import run_gate
from .judge import ProductControlledJudge, UnavailableRubricJudge


def _candidate_from_file(path: str):
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("candidate file must contain an object keyed by case_id")

    def candidate(case: GoldenCase) -> Any:
        if case.case_id not in payload:
            raise ValueError(
                "candidate file is missing case: {}".format(case.case_id)
            )
        return payload[case.case_id]

    return candidate


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="gate", description="Regression gate")
    subparsers = parser.add_subparsers(dest="command", required=True)
    check = subparsers.add_parser("check", help="run the regression gate")
    check.add_argument("--lane", choices=("push", "full"), default="push")
    check.add_argument("--candidate-version", required=True)
    check.add_argument("--candidate-file", required=True)
    check.add_argument("--db", default="data/evaluations.db")
    check.add_argument("--record-baseline", action="store_true")
    check.add_argument("--judge-model", default="gemini-3.5-flash-lite")
    calibrate = subparsers.add_parser("calibrate", help="run the human-labeled judge calibration set")
    calibrate.add_argument("--judge-model", default="gemini-3.5-flash-lite")
    check.add_argument(
        "--unchanged",
        action="store_true",
        help="treat this run as unchanged-code evidence for the false-alarm ledger",
    )
    return parser


def _build_judge(model: str):
    try:
        return ProductControlledJudge(GeminiRubricJudgeProvider(model=model))
    except Exception as exc:
        return UnavailableRubricJudge(str(exc))


def run_calibrate(args: argparse.Namespace) -> int:
    judge = _build_judge(args.judge_model)
    try:
        result = run_calibration(seed_golden_cases(), judge)
    except Exception as exc:
        print("UNCERTAIN | calibration unavailable: {}".format(exc))
        return 1
    status = "ACCEPTED" if result.accepted else "REJECTED"
    print("CALIBRATION | {} | agreed={}/{} | agreement={:.1%} | threshold={:.1%} | cost=$ {:.4f} | runtime={:.3f}s".format(status, result.agreed, result.total, result.agreement, 1.0, result.estimated_cost_usd, result.runtime_seconds))
    return 0 if result.accepted else 1


def run_check(args: argparse.Namespace) -> int:
    cases = seed_golden_cases()
    runs = 3 if args.lane == "push" else 10
    store = EvaluationStore(args.db)
    semantic_cases = tuple(case for case in cases if case.check_type == "rubric")
    judge = _build_judge(args.judge_model) if semantic_cases else None

    summary = evaluate_cases(
        cases, _candidate_from_file(args.candidate_file), runs=runs,
        judge=judge, candidate_version=args.candidate_version,
    )

    if args.record_baseline and not summary.judge_available:
        print("UNCERTAIN | baseline not saved because semantic judge is unavailable")
        return 1

    if args.record_baseline:
        store.save_baseline(
            Baseline(
                lane=args.lane,
                candidate_version=args.candidate_version,
                golden_set_version=summary.golden_set_version,
                judge_version=summary.judge_version,
                judge_prompt_version=summary.judge_prompt_version,
                score=summary.observed_score,
                cases_evaluated=summary.cases_evaluated,
                runs_per_case=summary.runs_per_case,
                estimated_cost_usd=summary.estimated_cost_usd,
                runtime_minutes=summary.runtime_minutes,
                created_at=summary.created_at,
            )
        )
        print(
            "baseline saved: lane={} score={:.4f}".format(
                args.lane, summary.observed_score
            )
        )
        return 0

    result = run_gate(
        summary,
        store.get_baseline(args.lane),
        lane=args.lane,
        store=store,
        unchanged=args.unchanged,
    )
    print(
        "{} | lane={} | score={:.4f} | baseline={:.4f} | noise={:.4f} | cost=$ {:.4f} | "
        "runtime={:.4f} min | reason={}".format(
            result.verdict,
            result.lane,
            result.observed_score,
            result.baseline_score,
            result.noise_estimate,
            result.estimated_cost_usd,
            result.runtime_minutes,
            result.reason,
        )
    )
    print("false-alarm-ledger={}".format(store.false_alarm_count()))
    return 0 if result.verdict == "PASS" else 1


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if args.command == "calibrate":
        raise SystemExit(run_calibrate(args))
    raise SystemExit(run_check(args))


if __name__ == "__main__":
    main()
