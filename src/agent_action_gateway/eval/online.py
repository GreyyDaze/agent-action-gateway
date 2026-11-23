"""Online evaluation: sample recorded runs and report on them.

The offline gate answers "did this change make the golden set worse". It cannot
answer "are the runs coming off production servers worse than the baseline",
because those runs were never evaluated.

This module samples completed runs from a live trace database and reports what
it finds. It is deliberately **report-only**:

- It never blocks by default. An online judge is stochastic and unproven
  against a human, and a gate that fires on noise gets switched off within a
  week -- which is worse than no gate.
- Promotion is an explicit flag, so turning it on is a visible decision someone
  made rather than a default nobody chose.
- Every judge/human disagreement is reported rather than averaged away. A judge
  that quietly disagrees with a human is a broken judge, and hiding that is how
  it stays broken.

Deterministic sampling: the same `--sample` and `--seed` select the same runs,
so a report can be reproduced instead of argued about.
"""

from __future__ import annotations

import random
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from agent_action_gateway.eval.trajectory import score as score_path

#: Sampling below this fraction of runs stops being informative: a 0.1% sample
#: of a thousand runs is one run, and one run is an anecdote.
MIN_MEANINGFUL_RUNS = 10


@dataclass
class RunAssessment:
    run_id: str
    steps: int
    penalty: int
    kinds: list[str] = field(default_factory=list)
    completed: bool = True

    def as_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "steps": self.steps,
            "penalty": self.penalty,
            "kinds": self.kinds,
            "completed": self.completed,
        }


@dataclass
class OnlineReport:
    sampled: int
    population: int
    assessments: list[RunAssessment] = field(default_factory=list)
    below_baseline: list[str] = field(default_factory=list)
    disagreements: list[str] = field(default_factory=list)

    @property
    def degraded(self) -> list[RunAssessment]:
        return [a for a in self.assessments if a.penalty > 0]

    def as_dict(self) -> dict[str, Any]:
        return {
            "sampled": self.sampled,
            "population": self.population,
            "degraded": len(self.degraded),
            "below_baseline": self.below_baseline,
            "disagreements": self.disagreements,
            "runs": [a.as_dict() for a in self.assessments],
        }


def group_runs(traces: Sequence[Mapping[str, Any]]) -> dict[str, list[dict]]:
    """Split a flat trace list into per-run sequences, preserving order."""
    runs: dict[str, list[dict]] = {}
    for trace in sorted(traces, key=lambda t: (str(t.get("run_id")), t.get("id") or 0)):
        runs.setdefault(str(trace.get("run_id")), []).append(dict(trace))
    return runs


def select(runs: Mapping[str, list[dict]], sample: float, seed: int) -> list[str]:
    """Choose which runs to assess, deterministically.

    `sample` is a fraction of runs, not of steps. Runs are the unit that matters:
    a run half-sampled is not half an observation.
    """
    run_ids = sorted(runs)
    if not run_ids:
        return []
    fraction = min(max(sample, 0.0), 1.0)
    count = max(1, round(len(run_ids) * fraction)) if fraction > 0 else 0
    if count >= len(run_ids):
        return run_ids
    return sorted(random.Random(seed).sample(run_ids, count))


def assess(
    runs: Mapping[str, list[dict]],
    *,
    sample: float = 0.1,
    seed: int = 0,
    blocked_run_ids: Sequence[str] = (),
) -> OnlineReport:
    """Sample runs and report on the paths they took.

    `blocked_run_ids` is the record of what a human already decided. A run held
    by policy is not a quality failure, so it is reported as held rather than
    counted as degraded -- but a human mark and an automated penalty that
    disagree are both listed, because that is the signal worth a person's time.
    """
    population = len(runs)
    chosen = select(runs, sample, seed)
    report = OnlineReport(sampled=len(chosen), population=population)
    human_marks = set(blocked_run_ids)

    for run_id in chosen:
        steps = runs[run_id]
        result = score_path(steps)
        held = run_id in human_marks
        report.assessments.append(
            RunAssessment(
                run_id=run_id,
                steps=len(steps),
                penalty=0 if held else result.penalty,
                kinds=[] if held else list(result.kinds()),
                completed=not held,
            )
        )
        # A human held it, the scorer found nothing wrong with it: the judge is
        # the thing under suspicion, not the run.
        if held and result.clean or not held and result.penalty > 0 and run_id in human_marks:
            report.disagreements.append(run_id)

    if population >= MIN_MEANINGFUL_RUNS and report.sampled < 2:
        report.below_baseline.append(
            f"sampled {report.sampled} of {population} runs; too few to draw a conclusion"
        )
    return report


def render(report: OnlineReport, *, promote: bool) -> str:
    lines = [
        f"sampled {report.sampled} of {report.population} runs",
        f"degraded: {len(report.degraded)}",
    ]
    for entry in report.assessments:
        if entry.completed and entry.penalty == 0:
            lines.append(f"  {entry.run_id}  clean path ({entry.steps} steps)")
        elif entry.completed:
            lines.append(f"  {entry.run_id}  penalty={entry.penalty}  {', '.join(entry.kinds)}")
        else:
            lines.append(f"  {entry.run_id}  held by policy (not counted as degraded)")

    if report.disagreements:
        lines.append("")
        lines.append("judge/human disagreements (worth a person's time):")
        lines.extend(f"  {run_id}" for run_id in report.disagreements)

    if report.below_baseline:
        lines.append("")
        lines.extend(report.below_baseline)

    lines.append("")
    if promote:
        lines.append("PROMOTED: this run can return a failing exit code.")
    else:
        lines.append(
            "report only. Nothing was blocked; promotion is an explicit flag "
            "because an online judge is stochastic and unproven."
        )
    return "\n".join(lines)


def gate_status(report: OnlineReport, *, promote: bool) -> bool:
    """Whether this report should fail. False unless promotion was asked for.

    Kept separate from `render` so the exit status and the printed words cannot
    drift apart, and so "report only" is the only thing that happens by default.
    """
    if not promote:
        return False
    if report.below_baseline:
        return False
    return bool(report.degraded)


__all__ = ["OnlineReport", "RunAssessment", "assess", "gate_status", "group_runs", "render", "select"]
