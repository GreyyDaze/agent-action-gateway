from __future__ import annotations

import argparse

from .evaluation_models import Baseline
from .evaluation_store import EvaluationStore
from .evaluator import evaluate_cases
from .golden import seed_golden_cases
from .gate import run_gate


def _reference_candidate():
    def candidate(case):
        if case.check_type == "regex":
            return "refunded successfully"
        return case.expected

    return candidate


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="gate", description="Regression gate")
    subparsers = parser.add_subparsers(dest="command", required=True)
    check = subparsers.add_parser("check", help="run the regression gate")
    check.add_argument("--lane", choices=("push", "full"), default="push")
    check.add_argument("--candidate-version", default="local")
    check.add_argument("--db", default="data/evaluations.db")
    check.add_argument("--record-baseline", action="store_true")
    return parser


def run_check(args: argparse.Namespace) -> int:
    cases = seed_golden_cases()
    runs = 3 if args.lane == "push" else 10
    store = EvaluationStore(args.db)
    summary = evaluate_cases(
        cases,
        _reference_candidate(),
        runs=runs,
        candidate_version=args.candidate_version,
    )

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
    )
    print(
        "{} | lane={} | score={:.4f} | baseline={:.4f} | noise={:.4f} | "
        "cost=$" + "{:.4f} | runtime={:.4f} min | reason={}".format(
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
    raise SystemExit(run_check(args))


if __name__ == "__main__":
    main()
