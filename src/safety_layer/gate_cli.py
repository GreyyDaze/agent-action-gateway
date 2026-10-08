from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .calibration import run_calibration
from .evaluation_models import Baseline, GoldenCase
from .evaluation_store import EvaluationStore
from .evaluator import evaluate_cases
from .gate import run_gate
from .gemini_judge import DEFAULT_GEMINI_MODEL, GeminiJudgeError, GeminiRubricJudgeProvider
from .golden import seed_golden_cases
from .judge import (
    JudgeUnavailableError,
    ProductControlledJudge,
    UnavailableRubricJudge,
)
from .verdict import LANE_RUNS

# Distinct exit codes so CI can tell three outcomes apart. argparse exits 2 on
# a usage error, so UNCERTAIN uses 3 to keep "the change regressed" (1),
# "the gate could not tell" (3), and "you typed it wrong" (2) distinguishable.
EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_USAGE = 2  # argparse's own code, listed for documentation
EXIT_UNCERTAIN = 3


def _candidate_from_file(path: str):
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("candidate file must contain an object keyed by case_id")

    def candidate(case: GoldenCase) -> Any:
        if case.case_id not in payload:
            raise ValueError(
                f"candidate file is missing case: {case.case_id}"
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
    check.add_argument("--judge-model", default=DEFAULT_GEMINI_MODEL)
    calibrate = subparsers.add_parser("calibrate", help="run the human-labeled judge calibration set")
    calibrate.add_argument("--judge-model", default=DEFAULT_GEMINI_MODEL)
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
    """Return a configured judge, or an explicitly unavailable one.

    Only judge-construction problems are absorbed here. A programming error such
    as a TypeError must not be laundered into an UNCERTAIN verdict, which would
    hide a broken deployment behind "we could not evaluate".
    """
    try:
        return ProductControlledJudge(GeminiRubricJudgeProvider(model=model))
    except GeminiJudgeError as exc:
        return UnavailableRubricJudge(str(exc))


def run_calibrate(args: argparse.Namespace) -> int:
    judge = _build_judge(args.judge_model)
    try:
        result = run_calibration(seed_golden_cases(), judge)
    except JudgeUnavailableError as exc:
        # Unavailability is not a calibration failure. Reporting it as exit 1
        # would contradict the gate contract documented in docs/sdk.md.
        print(f"UNCERTAIN | calibration unavailable: {exc}")
        return EXIT_UNCERTAIN
    status = "ACCEPTED" if result.accepted else "REJECTED"
    print(f"CALIBRATION | {status} | agreed={result.agreed}/{result.total} | agreement={result.agreement:.1%} | threshold={result.min_agreement:.1%} | cost=$ {result.estimated_cost_usd:.4f} | runtime={result.runtime_seconds:.3f}s")
    return EXIT_PASS if result.accepted else EXIT_FAIL


def _run_check_once(args: argparse.Namespace, cases: tuple[GoldenCase, ...], store: EvaluationStore):
    runs = LANE_RUNS[args.lane]
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
        print(f"baseline saved: lane={args.lane} score={summary.observed_score:.4f}")
        return None

    result = run_gate(
        summary,
        store.get_baseline(args.lane),
        lane=args.lane,
        store=store,
        unchanged=args.unchanged,
    )
    print(
        f"{result.verdict} | lane={result.lane} | score={result.observed_score:.4f} | baseline={result.baseline_score:.4f} | noise={result.noise_estimate:.4f} | "
        f"judge={result.judge_provider}/{result.judge_model} | cost=$ {result.estimated_cost_usd:.4f} | runtime={result.runtime_minutes:.4f} min | reason={result.reason}"
    )
    print(f"false-alarm-ledger={store.false_alarm_count()}")
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
        if result is None:
            continue
        results.append(result)
        if result.verdict == "PASS":
            continue
        if result.verdict == "UNCERTAIN":
            # Uncertain means the gate could not reach a trustworthy verdict,
            # typically an unavailable judge or an incompatible baseline. That
            # is not evidence of a regression and must never be reported as a
            # false alarm in the unchanged-code proof.
            if args.repeat > 1:
                _print_unchanged_proof(results, args.repeat, status="UNCERTAIN")
            return EXIT_UNCERTAIN
        if args.repeat > 1:
            _print_unchanged_proof(results, args.repeat, status="FAIL")
        return EXIT_FAIL

    if args.repeat > 1:
        false_fails = sum(result.verdict == "FAIL" for result in results)
        uncertain = any(result.verdict == "UNCERTAIN" for result in results)
        status = "UNCERTAIN" if uncertain else "PASS" if false_fails == 0 else "FAIL"
        _print_unchanged_proof(results, args.repeat, status=status)
        if uncertain:
            return EXIT_UNCERTAIN
        return EXIT_FAIL if false_fails else EXIT_PASS

    return EXIT_PASS


def _print_unchanged_proof(results, repeat: int, *, status: str) -> None:
    false_fails = sum(result.verdict == "FAIL" for result in results)
    print(
        "UNCHANGED-PROOF | runs={}/{} | false-fails={} | uncertain={} | status={}".format(
            len(results), repeat, false_fails, status == "UNCERTAIN", status,
        )
    )


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if args.command == "calibrate":
        raise SystemExit(run_calibrate(args))
    raise SystemExit(run_check(args))


if __name__ == "__main__":
    main()
