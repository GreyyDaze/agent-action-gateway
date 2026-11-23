"""A Kubernetes incident agent, wrapped in the safety layer.

This file is executed in CI, so it cannot drift from the docs. It shows one
incident end to end: read the cluster, propose a fix, get refused because
nobody approved it, then succeed after an approval.

Nothing here holds the kubeconfig. `patch_deployment` talks to the gateway,
which holds the credential in a separate process.

Run:  python docs/examples/sre_agent.py
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from safety_layer import session
from safety_layer.eval.trajectory import score as score_path
from safety_layer.storage.traces import TraceStore

NAMESPACE = "prod"
APP = "shop-api"

#: Every patch that actually reached the cluster API, across every run. The
#: example asserts against this rather than against a return value, because a
#: duplicate patch returns a perfectly normal-looking success.
applied_patches: list[str] = []


def describe_fn(namespace: str, app: str) -> dict:
    """A read against the cluster API. Cheap, but still recorded."""
    return {
        "status": "ok",
        "app": app,
        "namespace": namespace,
        "restarts": 47,
        "exit_code": 137,
        "memory_limit": "256Mi",
        "working_set": "240Mi",
    }


def check_metrics_fn(namespace: str, app: str) -> dict:
    return {
        "status": "ok",
        "oom_killed": True,
        "restart_rate_per_hour": 9,
        "deployment_unchanged_days": 11,
    }


def patch_deployment_fn(
    namespace: str, app: str, memory_limit: str, intent_key: str = ""
) -> dict:
    """The write.

    The real call would go to the gateway, which holds the kubeconfig.
    ``intent_key`` is supplied by the layer, so a crash-recovery replay is
    recognisable as the same action rather than a second patch.
    """
    applied_patches.append(memory_limit)
    return {
        "status": "patched",
        "app": app,
        "namespace": namespace,
        "memory_limit": memory_limit,
        "key": intent_key,
    }


def build_agent(ctx) -> str:
    """Read the failure, then try to raise the memory limit.

    It has no approval, so the layer refuses and records the refusal.
    """

    def agent(task: str) -> str:
        ctx.describe(namespace=NAMESPACE, app=APP)
        ctx.check_metrics(namespace=NAMESPACE, app=APP)
        outcome = ctx.patch_deployment(
            namespace=NAMESPACE, app=APP, memory_limit="768Mi"
        )
        if outcome["status"] == "blocked":
            return f"refused: {outcome['error']}"
        return f"patched {APP} to {outcome.get('memory_limit')}"

    return agent


def main() -> None:
    with tempfile.TemporaryDirectory() as directory:
        store = TraceStore(Path(directory) / "runtime.db")

        with session(store=store, environment="prod") as ctx:
            ctx.describe = ctx.tool(  # type: ignore[attr-defined]
                describe_fn,
                action="read.deployment",
                risk="read",
                target=APP,
                target_environment=NAMESPACE,
            )
            ctx.check_metrics = ctx.tool(  # type: ignore[attr-defined]
                check_metrics_fn,
                action="read.metrics",
                risk="read",
                target=APP,
                target_environment=NAMESPACE,
            )
            ctx.patch_deployment = ctx.tool(  # type: ignore[attr-defined]
                patch_deployment_fn,
                action="patch.deployment",
                risk="destructive",
                target=APP,
                target_environment=NAMESPACE,
                required_fields=("namespace", "app", "memory_limit"),
            )

            # Every model call is recorded: tokens, cost, latency, redacted.
            ctx.record_model_exchange(
                prompt="shop-api is OOMKilled. Root cause: memory limit below working set.",
                completion="Raise limits.memory from 256Mi to 768Mi.",
                tokens_in=1420,
                tokens_out=96,
                cost_usd=0.0041,
                latency_ms=1840,
            )

            # --- Attempt 1: the agent acts with no approval. Must be refused. ---
            result = ctx.run(build_agent(ctx), "fix shop-api OOMKilled")

            print(f"agent said:     {result['output']}")
            print(f"run status:     {result['status']}")
            print(f"enforcement:    {result['enforcement']}")

            assert result["output"].startswith("refused"), (
                "an unapproved destructive action must be refused"
            )
            assert result["status"] == "blocked", "a blocked run must not report clean"
            assert result["enforcement"] == "enforced"

            # --- Approve the exact payload, then patch. ---
            approval = ctx.request_approval(
                "patch.deployment",
                {"namespace": NAMESPACE, "app": APP, "memory_limit": "768Mi"},
            )
            ctx.approve(approval.approval_id, "oncall-sre")
            allowed = ctx.patch_deployment(
                namespace=NAMESPACE,
                app=APP,
                memory_limit="768Mi",
                approval_id=approval.approval_id,
            )
            print(f"after approval: {allowed['status']}")
            assert allowed["status"] == "allowed", "an approved action must be permitted"

            # --- A different limit is a different effect, not a duplicate. ---
            other = ctx.request_approval(
                "patch.deployment",
                {"namespace": NAMESPACE, "app": APP, "memory_limit": "1536Mi"},
            )
            ctx.approve(other.approval_id, "oncall-sre")
            raised = ctx.patch_deployment(
                namespace=NAMESPACE,
                app=APP,
                memory_limit="1536Mi",
                approval_id=other.approval_id,
            )
            assert raised["status"] == "allowed", "a distinct change must be permitted"
            assert len(applied_patches) == 2, "a different limit was suppressed"

        # --- A new process, same database: the restart case. ---
        #
        # A retry after a crash arrives under a different run id, so nothing
        # about the attempt matches. The effect still does, which is why the
        # patch is not applied a second time.
        with session(store=TraceStore(Path(directory) / "runtime.db"), environment="prod") as ctx2:
            ctx2.patch_deployment = ctx2.tool(  # type: ignore[attr-defined]
                patch_deployment_fn,
                action="patch.deployment",
                risk="destructive",
                target=APP,
                target_environment=NAMESPACE,
                required_fields=("namespace", "app", "memory_limit"),
            )
            retry = ctx2.request_approval(
                "patch.deployment",
                {"namespace": NAMESPACE, "app": APP, "memory_limit": "768Mi"},
            )
            ctx2.approve(retry.approval_id, "oncall-sre")
            repeat = ctx2.patch_deployment(
                namespace=NAMESPACE,
                app=APP,
                memory_limit="768Mi",
                approval_id=retry.approval_id,
            )
            print(f"after restart: {repeat['status']} ({repeat['decision']})")
            assert repeat["decision"] == "DEDUPLICATED", (
                "the same effect in a new run must not execute twice"
            )
            assert len(applied_patches) == 2, "the patch was applied twice"

        rows = store.snapshot()
        blocked = [t for t in rows["traces"] if t["status"] == "blocked"]
        print(f"\nblocked evidence rows: {len(blocked)}")
        assert blocked, "the refusal must leave evidence"

        receipts = rows["receipts"]
        print(f"receipts: {len(receipts)} for {len(applied_patches)} distinct patches")
        assert len(receipts) == 2, "one effect produced more than one receipt"
        assert all(r["state"] == "done" for r in receipts)
        assert all(r["effect_key"] for r in receipts)

        # Score how the run got there, not just whether it finished.
        print("\n--- path score ---")
        print(json.dumps(score_path(rows["traces"]).as_dict(), indent=2, default=str))


if __name__ == "__main__":
    main()
