"""The effect key must make a duplicate detectable across runs.

These are the tests that the receipt's original per-run key could not pass. A
retry after a crash, a second worker, and the same action issued twice all
produce a new `run_id`, so nothing collided and every one of them would have
executed the action again.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from safety_layer import session
from safety_layer.policy.fingerprint import fingerprint
from safety_layer.storage.traces import TraceStore


class EffectClaimTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.db = Path(self.directory.name) / "runtime.db"
        self.calls: list[str] = []

    def _tool(self, ctx: session, **kwargs: object):
        def patch(namespace: str, app: str, memory_limit: str, intent_key: str = "") -> dict:
            self.calls.append(memory_limit)
            return {"status": "patched", "app": app, "namespace": namespace}

        return ctx.tool(patch, action="patch.deployment", risk="destructive", **kwargs)

    def _approved_patch(self, **kwargs: object) -> dict:
        """One approved patch in a brand new run."""
        store = TraceStore(self.db)
        with session(store=store, environment="prod") as ctx:
            tool = self._tool(ctx, **kwargs)
            payload = {"namespace": "prod", "app": "shop-api", "memory_limit": "768Mi"}
            approval = ctx.request_approval("patch.deployment", payload)
            ctx.approve(approval.approval_id, "oncall-sre")
            return tool(
                namespace="prod",
                app="shop-api",
                memory_limit="768Mi",
                approval_id=approval.approval_id,
            )

    def test_the_same_effect_in_two_runs_executes_once(self) -> None:
        """A retry after a restart is not a new intent.

        The two runs have different `run_id`s, so the per-attempt key could
        never have detected this.
        """
        first = self._approved_patch()
        second = self._approved_patch()

        self.assertEqual(first["status"], "allowed")
        self.assertEqual(second["decision"], "DEDUPLICATED")
        self.assertEqual(len(self.calls), 1, "the action ran twice")

    def test_a_crash_mid_action_blocks_the_retry_instead_of_repeating_it(self) -> None:
        """The outcome is unknown, so neither repeating nor claiming success is right."""
        self._approved_patch()
        # The crash window: dispatched, but the local record never advanced.
        store = TraceStore(self.db)
        with store.connection() as connection:
            connection.execute(
                "UPDATE receipts SET state='pending', provider_ref=NULL"
            )

        second = self._approved_patch()
        self.assertEqual(second["status"], "blocked")
        self.assertEqual(second["decision"], "DEDUPLICATED")
        self.assertEqual(len(self.calls), 1, "an uncertain effect was repeated")

    def test_dedup_needs_no_provider(self) -> None:
        """A tool with no provider still gets a receipt and still dedupes.

        This is the adoption path. Requiring a per-API provider just to be safe
        against duplicates made the guarantee unreachable for most callers.
        """
        self._approved_patch()
        self._approved_patch()

        receipts = TraceStore(self.db).snapshot()["receipts"]
        self.assertEqual(len(receipts), 1)
        self.assertEqual(receipts[0]["state"], "done")
        self.assertTrue(receipts[0]["effect_key"])
        self.assertEqual(len(self.calls), 1)

    def test_a_read_is_not_claimed(self) -> None:
        """Reads have no side effect, so they should not pay for a claim."""
        store = TraceStore(self.db)
        with session(store=store, environment="prod") as ctx:
            lookup = ctx.tool(
                lambda app: {"replicas": 3},
                action="read.deployment",
                risk="read",
            )
            lookup(app="shop-api")
            lookup(app="shop-api")

        self.assertEqual(TraceStore(self.db).snapshot()["receipts"], [])

    def test_different_arguments_are_different_effects(self) -> None:
        """Raising to a different limit is not a duplicate of raising to this one."""
        store = TraceStore(self.db)
        with session(store=store, environment="prod") as ctx:
            tool = self._tool(ctx)
            for limit in ("768Mi", "1536Mi"):
                payload = {
                    "namespace": "prod",
                    "app": "shop-api",
                    "memory_limit": limit,
                }
                approval = ctx.request_approval("patch.deployment", payload)
                ctx.approve(approval.approval_id, "oncall-sre")
                tool(
                    namespace="prod",
                    app="shop-api",
                    memory_limit=limit,
                    approval_id=approval.approval_id,
                )

        self.assertEqual(len(self.calls), 2)

    def test_identity_fields_keeps_a_changing_body_out_of_the_key(self) -> None:
        """Same issue, edited draft: one effect, not two."""
        db = Path(self.directory.name) / "issues.db"
        calls: list[str] = []

        def create_issue(owner: str, title: str, body: str, intent_key: str = "") -> dict:
            calls.append(body)
            return {"status": "created"}

        def attempt(body: str) -> dict:
            with session(store=TraceStore(db)) as ctx:
                tool = ctx.tool(
                    create_issue,
                    action="create_issue",
                    risk="destructive",
                    identity_fields=("owner", "title"),
                )
                payload = {"owner": "acme", "title": "Bug", "body": body}
                approval = ctx.request_approval("create_issue", payload)
                ctx.approve(approval.approval_id, "oncall-sre")
                return tool(
                    owner="acme",
                    title="Bug",
                    body=body,
                    approval_id=approval.approval_id,
                )

        attempt("draft one")
        second = attempt("draft two")

        self.assertEqual(second["decision"], "DEDUPLICATED")
        self.assertEqual(len(calls), 1)

    def test_scope_stops_two_tenants_suppressing_each_other(self) -> None:
        """Without a scope the second tenant's action is silently dropped.

        That is a wrong answer rather than a slow one, so a shared deployment
        must separate tenants explicitly.
        """
        calls: list[str] = []

        def create_issue(owner: str, title: str, intent_key: str = "") -> dict:
            calls.append(owner)
            return {"status": "created"}

        def attempt(db: Path, tenant: str) -> None:
            with session(store=TraceStore(db)) as ctx:
                tool = ctx.tool(
                    create_issue,
                    action="create_issue",
                    risk="destructive",
                    effect_scope=tenant,
                )
                payload = {"owner": "acme", "title": "Bug"}
                approval = ctx.request_approval("create_issue", payload)
                ctx.approve(approval.approval_id, "oncall-sre")
                tool(owner="acme", title="Bug", approval_id=approval.approval_id)

        db = Path(self.directory.name) / "tenants.db"
        attempt(db, "tenant-a")
        attempt(db, "tenant-b")
        self.assertEqual(len(calls), 2)

        # The same action with no scope at all collapses to one.
        shared = Path(self.directory.name) / "shared.db"
        attempt(shared, "")
        attempt(shared, "")
        self.assertEqual(len(calls), 3, "tenants shared a namespace")

    def test_a_raising_tool_releases_its_claim(self) -> None:
        """A call that raises did not land, so the next attempt must be allowed."""
        calls: list[str] = []

        def flaky(app: str, intent_key: str = "") -> dict:
            calls.append(app)
            raise RuntimeError("upstream refused")

        with session(store=TraceStore(self.db)) as ctx:
            tool = ctx.tool(flaky, action="write.config", risk="destructive")
            payload = {"app": "shop-api"}
            approval = ctx.request_approval("write.config", payload)
            ctx.approve(approval.approval_id, "oncall-sre")
            with self.assertRaises(RuntimeError):
                tool(app="shop-api", approval_id=approval.approval_id)

        states = [r["state"] for r in TraceStore(self.db).snapshot()["receipts"]]
        self.assertEqual(states, ["failed"], "a failed effect kept a pending claim")

    def test_a_changed_argument_is_a_different_effect(self) -> None:
        """Raising to a different limit is not a duplicate of raising to this one."""
        args = {"app": "shop-api", "memory_limit": "768Mi"}
        self.assertEqual(
            fingerprint("patch.deployment", args),
            fingerprint("patch.deployment", args),
        )
        self.assertNotEqual(
            fingerprint("patch.deployment", args),
            fingerprint("patch.deployment", {**args, "memory_limit": "1Gi"}),
        )


if __name__ == "__main__":
    unittest.main()
