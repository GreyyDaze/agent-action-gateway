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

_STATE_MEANING = {
    "done": "landed",
    "pending": "claimed, outcome unknown",
    "failed": "did not land",
    "resolved": "landed, confirmed by reconciliation",
    "unknown": "legacy row, no claim recorded",
}


#: Receipt states whose outcome is not known. A person settles them.
HELD_STATES = frozenset({"pending", "unknown"})


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


def _spent(traces: Sequence[Mapping[str, Any]]) -> tuple[float | None, int | None, int]:
    """Total cost, tokens and the number of reported model calls.

    Only the agent's own code sees its model calls, so these numbers exist only
    when it reports them (`record_model_exchange`, or the proxy's `/usage`).
    `None` means nothing was reported, which is not the same as zero.
    """
    cost: float | None = None
    tokens: int | None = None
    calls = 0
    for trace in traces:
        reported = False
        if trace.get("cost_usd") is not None:
            cost = (cost or 0.0) + float(trace["cost_usd"])
            reported = True
        for field in ("tokens_in", "tokens_out"):
            if trace.get(field) is not None:
                tokens = (tokens or 0) + int(trace[field])
                reported = True
        calls += reported
    return (None if cost is None else round(cost, 6)), tokens, calls


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
    last_id: dict[str, int] = {}
    for trace in all_traces:
        rid = str(trace.get("run_id") or "")
        last_id[rid] = max(last_id.get(rid, 0), int(trace.get("id", 0)))
        if not any(r["run_id"] == rid for r in run_index):
            run_index.append({"run_id": rid, "status": str(trace.get("status") or "")})

    # A run's status is its worst step, not its last. A run that blocked an
    # action and then finished cleanly is a blocked run.
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

    # Newest first: the run a person most likely came to look at.
    run_index.sort(key=lambda r: (-last_id.get(r["run_id"], 0), r["run_id"]))

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
                "needs_review": str(receipt.get("state")) in HELD_STATES,
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
        # Held actions from every run, not only this one: a held action blocks
        # its retries everywhere, so it has to be visible from any page.
        "held": [
            {**dict(receipt), "state_meaning": state_meaning(str(receipt.get("state") or ""))}
            for receipt in sorted(
                snapshot.get("receipts", []), key=lambda r: int(r.get("id", 0))
            )
            if str(receipt.get("state")) in HELD_STATES
        ],
    }
