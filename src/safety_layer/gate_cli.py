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
    check.add_argument(
        "--repeat",
        type=int,
        default=1,
        help="repeat the gate evaluation this many times; useful for unchanged-code proof",
    )
    check.add_argument(
        "--wait-seconds",
        type=float,
        default=0.0,
        help="wait this many seconds between real judge requests; useful for provider rate limits",
    )
    check.add_argument(
        "--detail",
        action="store_true",
        help="show detailed run, judge request, wait, and result progress",
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


def _run_check_once(args: argparse.Namespace, cases: tuple[GoldenCase, ...], store: EvaluationStore):
    runs = 3 if args.lane == "push" else 10
    semantic_cases = tuple(case for case in cases if case.check_type == "rubric")
    judge = _build_judge(args.judge_model) if semantic_cases else None

    summary = evaluate_cases(
        cases, _candidate_from_file(args.candidate_file), runs=runs,
        judge=judge, candidate_version=args.candidate_version,
        judge_wait_seconds=args.wait_seconds,
        detail=args.detail,
    )

    if args.record_baseline and not summary.judge_available:
        print("UNCERTAIN | baseline not saved because semantic judge is unavailable")
        return None

    if args.record_baseline:
        store.save_baseline(
            Baseline(
                lane=args.lane,
                candidate_version=args.candidate_version,
                golden_set_version=summary.golden_set_version,
                judge_version=summary.judge_version,
                judge_prompt_version=summary.judge_prompt_version,
                judge_provider=summary.judge_provider,
                judge_model=summary.judge_model,
                score=summary.observed_score,
                cases_evaluated=summary.cases_evaluated,
                runs_per_case=summary.runs_per_case,
                estimated_cost_usd=summary.estimated_cost_usd,
                runtime_minutes=summary.runtime_minutes,
                created_at=summary.created_at,
            )
        )
        print("baseline saved: lane={} score={:.4f}".format(args.lane, summary.observed_score))
        return None

    result = run_gate(
        summary,
        store.get_baseline(args.lane),
        lane=args.lane,
        store=store,
        unchanged=args.unchanged,
    )
    print(
        "{} | lane={} | score={:.4f} | baseline={:.4f} | noise={:.4f} | "
        "judge={}/{} | cost=$ {:.4f} | runtime={:.4f} min | reason={}".format(
            result.verdict,
            result.lane,
            result.observed_score,
            result.baseline_score,
            result.noise_estimate,
            result.judge_provider,
            result.judge_model,
            result.estimated_cost_usd,
            result.runtime_minutes,
            result.reason,
        )
    )
    print("false-alarm-ledger={}".format(store.false_alarm_count()))
    return result


def run_check(args: argparse.Namespace) -> int:
    if args.repeat < 1:
        raise SystemExit("--repeat must be >= 1")
    if args.wait_seconds < 0:
        raise SystemExit("--wait-seconds must be >= 0")
    if args.record_baseline and args.repeat != 1:
        raise SystemExit("--record-baseline cannot be combined with --repeat > 1")

    cases = seed_golden_cases()
    store = EvaluationStore(args.db)
    results = []
    for _ in range(args.repeat):
        result = _run_check_once(args, cases, store)
        if result is not None:
            results.append(result)
            if result.verdict != "PASS":
                if args.repeat > 1:
                    print(
                        "UNCHANGED-PROOF | runs={}/{} | false-fails={} | status=FAIL".format(
                            len(results), args.repeat,
                            sum(item.verdict == "FAIL" for item in results),
                        )
                    )
                return 1

    if args.repeat > 1:
        false_fails = sum(result.verdict == "FAIL" for result in results)
        print(
            "UNCHANGED-PROOF | runs={}/{} | false-fails={} | status={}".format(
                len(results), args.repeat, false_fails,
                "PASS" if false_fails == 0 and len(results) == args.repeat else "FAIL",
            )
        )
        return 0 if false_fails == 0 and len(results) == args.repeat else 1

    return 0


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if args.command == "calibrate":
        raise SystemExit(run_calibrate(args))
    raise SystemExit(run_check(args))


if __name__ == "__main__":
    main()
