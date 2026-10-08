"""The documented adoption path.

This file is executed by CI, so it cannot drift from the README. It shows the
thing that matters: an agent that tries to issue an unapproved refund is
stopped, and the refusal is recorded.

Tools the agent uses are obtained from a session. It never holds the raw
function, so there is nothing to bypass. See docs/feature-enforcement-integration.md.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from safety_layer import session
from safety_layer.storage.traces import TraceStore


def build_agent(tools: dict) -> str:
    """An agent that tries to issue a refund it was never approved for."""

    def agent(task: str) -> str:
        outcome = tools["refund"](order_id="ORD-100", amount=400)
        if outcome["status"] == "blocked":
            return f"refused: {outcome['error']}"
        return "refunded"

    return agent


def main() -> None:
    with tempfile.TemporaryDirectory() as directory:
        store = TraceStore(Path(directory) / "runtime.db")

        with session(store=store) as ctx:
            def refund_fn(
                order_id: str, amount: int = 0, intent_key: str = ""
            ) -> dict:
                # A real provider call would live here, keyed by intent_key so
                # a retry after a crash cannot double-charge.
                return {
                    "status": "refunded",
                    "order_id": order_id,
                    "amount": amount,
                    "key": intent_key,
                }

            refund = ctx.tool(
                refund_fn,
                action="refund",
                risk="destructive",
            )

            # No approval was requested, so this must be refused.
            result = ctx.run(build_agent({"refund": refund}), "refund Ava's order")

            print(f"agent said:  {result['output']}")
            print(f"run status:  {result['status']}")
            print(f"enforcement: {result['enforcement']}")

            assert result["output"].startswith("refused"), (
                "an unapproved destructive action must be refused"
            )
            assert result["status"] == "blocked", "a blocked run must not report clean"
            assert result["enforcement"] == "enforced"

            # Now approve the exact payload and try again.
            approval = ctx.request_approval(
                "refund", {"order_id": "ORD-100", "amount": 400}
            )
            ctx.approve(approval.approval_id, "operator")
            allowed = refund(order_id="ORD-100", amount=400, approval_id=approval.approval_id)
            print(f"after approval: {allowed['status']}")
            assert allowed["status"] == "allowed", "an approved action must be permitted"

        blocked_rows = [t for t in store.snapshot()["traces"] if t["status"] == "blocked"]
        print(f"blocked evidence rows: {len(blocked_rows)}")
        assert blocked_rows, "the refusal must leave evidence"


if __name__ == "__main__":
    main()
