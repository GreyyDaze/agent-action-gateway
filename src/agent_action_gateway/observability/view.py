"""Turn a store snapshot into the shape the dashboard renders.

Kept separate from the HTTP handler for two reasons. The handler should not be
doing data shaping inline, because that is where a change to a column name
quietly breaks a panel. And the view model is testable on its own: a panel can
be checked against a populated snapshot and against an empty one without
starting a server.

The input is `TraceStore.dashboard_snapshot()`. The output is deliberately
plain -- dictionaries and lists, no objects -- so the handler stays a
formatter.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

#: Order matters: it is the order a reader works through a run.
RECEIPT_STATES = ("done", "pending", "failed", "resolved", "unknown")

_STATE_MEANING = {
    "done": "landed",
    "pending": "claimed, outcome unknown",
    "failed": "did not land",
    "resolved": "landed, confirmed by reconciliation",
    "unknown": "legacy row, no claim recorded",
}


def state_meaning(state: str) -> str:
    """One-line gloss for a receipt state, shown beside it.

    A bare status word is not readable evidence. "pending" in particular is the
    one state a human has to act on, and the word alone does not say why.
    """
    return _STATE_MEANING.get(state, "unrecognised state")


def _group_by_run(rows: Sequence[Mapping[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(str(row.get("run_id") or ""), []).append(dict(row))
    return grouped


def _spent(traces: Sequence[Mapping[str, Any]]) -> tuple[float, int, int]:
    """Total cost, tokens and the number of steps that called a model."""
    cost = 0.0
    tokens = 0
    calls = 0
    for trace in traces:
        if trace.get("cost_usd") is not None:
            cost += float(trace["cost_usd"])
        if trace.get("tokens_in") is not None:
            tokens += int(trace["tokens_in"])
        if trace.get("tokens_out") is not None:
            tokens += int(trace["tokens_out"])
        if trace.get("tokens_in") is not None:
            calls += 1
    return round(cost, 6), tokens, calls


def _enforcement_of(traces: Sequence[Mapping[str, Any]]) -> str:
    """Whether this run was protected or merely observed.

    The distinction is the difference between "recorded" and "protected", so it
    is worth naming rather than leaving the reader to infer it from a column.
    """
    modes = {str(t.get("enforcement")) for t in traces if t.get("enforcement")}
    if "enforced" in modes:
        return "enforced"
    if modes == {"observe"}:
        return "observe"
    return "unknown"


def _status_rank(status: str) -> int:
    return {"failed": 0, "blocked": 1, "completed": 2}.get(status, 3)


def build_run_view(snapshot: Mapping[str, Any], run_id: str | None) -> dict[str, Any]:
    """Everything the page shows for one run.

    Passing `run_id=None` with no runs recorded returns the same shape with
    empty collections, so an empty database renders an intentional page rather
    than a broken one.
    """
    all_traces = [dict(t) for t in snapshot.get("traces", [])]
    receipts = _group_by_run(snapshot.get("receipts", []))
    budgets = {str(b.get("run_id")): b for b in snapshot.get("budgets", [])}
    gates = [dict(g) for g in snapshot.get("gate_verdicts", [])]

    run_index: list[dict[str, Any]] = []
    for trace in all_traces:
        rid = str(trace.get("run_id") or "")
        if not any(r["run_id"] == rid for r in run_index):
            run_index.append({"run_id": rid, "status": str(trace.get("status") or "")})

    # A run's status is its worst step, not its last. A run that blocked an
    # action and then finished cleanly is a blocked run, and reporting it as
    # completed would be the sort of tidy lie this project exists to prevent.
    by_run: dict[str, list[dict[str, Any]]] = _group_by_run(all_traces)
    for entry in run_index:
        steps = by_run.get(entry["run_id"], [])
        entry["status"] = min(
            (str(s.get("status") or "") for s in steps),
            key=_status_rank,
            default="unknown",
        )
        entry["enforcement"] = _enforcement_of(steps)
        entry["steps"] = len(steps)
        entry["blocked"] = sum(1 for s in steps if s.get("status") == "blocked")

    run_index.sort(key=lambda r: (-r["steps"], r["run_id"]))

    selected = run_id or (run_index[0]["run_id"] if run_index else None)
    traces = sorted(by_run.get(selected or "", []), key=lambda t: int(t.get("id", 0)))
    run_receipts = sorted(
        receipts.get(selected or "", []), key=lambda r: int(r.get("id", 0))
    )
    budget = budgets.get(selected or "")

    cost, tokens, model_calls = _spent(traces)
    gated = [g for g in gates if str(g.get("run_id")) == selected]

    return {
        "run_id": selected,
        "runs": run_index,
        "has_run": selected is not None,
        "traces": traces,
        "receipts": [
            {
                **receipt,
                "state_meaning": state_meaning(str(receipt.get("state") or "")),
                "needs_review": str(receipt.get("state")) in {"pending", "unknown"},
            }
            for receipt in run_receipts
        ],
        "budget": budget,
        "gates": gated,
        "totals": {
            "runs": len(run_index),
            "steps": len(traces),
            "blocked": sum(1 for t in traces if t.get("status") == "blocked"),
            "receipts": len(run_receipts),
            "pending": sum(
                1 for r in run_receipts if str(r.get("state")) == "pending"
            ),
            "cost_usd": cost,
            "tokens": tokens,
            "model_calls": model_calls,
            "gates": len(gated),
        },
        "enforcement": _enforcement_of(traces),
        "pending_approvals": [],
    }
