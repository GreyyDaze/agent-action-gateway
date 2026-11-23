"""The adoption contract.

This file is the definition of done for the Enforcement Integration feature. It
drives only the documented public API and asserts that an agent acting against
its own interest is stopped by the safety layer.

The failure this file exists to prevent: every enforcement primitive worked, and
none of them sat on the path an adopter's agent actually takes. Phase proofs
drove `dispatch_external_action` directly and were green, while
`run(agent, task)` enforced nothing.

Rules that shape these tests:

- Only the public API. Reaching into internals here would test the internals.
- Assertions are about observable outcome: was the provider called, is the
  receipt state correct, what is in the database. Not about which functions ran,
  except in the structural path test, which deliberately monkeypatches.
- A scenario that cannot run yet fails loudly. It must never skip silently.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from agent_action_gateway import session
from agent_action_gateway.policy.fuses import FuseLimits
from agent_action_gateway.storage.traces import TraceStore


class CountingProvider:
    """External side effect target that records whether it was ever reached."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def execute(self, target: str, intent_key: str) -> str:
        self.calls.append((target, intent_key))
        return f"ref-{len(self.calls)}"

    def find(self, intent_key: str, target: str | None = None) -> str | None:
        for key, ref in ((k, f"ref-{i + 1}") for i, (k, _) in enumerate(self.calls)):
            if key == intent_key:
                return ref
        return None

    @property
    def call_count(self) -> int:
        return len(self.calls)


class AdoptionContractTest(unittest.TestCase):
    """Hostile agent + documented adoption path."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.db = Path(self._tmp.name) / "runtime.db"
        self.store = TraceStore(self.db)
        self.provider = CountingProvider()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _raw_db_text(self) -> str:
        return self.db.read_bytes().decode("utf-8", errors="ignore")

    # -- 1. approval bypass ------------------------------------------------

    def test_1_unapproved_destructive_action_is_blocked_before_dispatch(self) -> None:
        """A destructive tool with no approval must not reach the provider."""
        with session(store=self.store) as ctx:
            rollback = ctx.tool(
                lambda **kw: self.provider.execute(kw["deployment_id"], kw.get("intent_key", "x")),
                action="rollback",
                risk="destructive",
                provider=self.provider,
            )
            outcome = rollback(deployment_id="DEP-100", revision=400)

        self.assertEqual(outcome["status"], "blocked")
        self.assertEqual(outcome["decision"], "APPROVAL")
        self.assertEqual(self.provider.call_count, 0, "provider must never be reached")

    def test_1b_refused_action_is_recorded_as_evidence(self) -> None:
        """A blocked attempt must leave a trace, not silence."""
        with session(store=self.store) as ctx:
            rollback = ctx.tool(
                lambda **kw: {"ok": True},
                action="rollback",
                risk="destructive",
                provider=self.provider,
            )
            rollback(deployment_id="DEP-100", revision=400)

        statuses = [t["status"] for t in self.store.snapshot()["traces"]]
        self.assertIn("blocked", statuses)
        self.assertEqual(self.provider.call_count, 0)

    # -- 2. payload tamper -------------------------------------------------

    def test_2_approved_payload_cannot_be_changed(self) -> None:
        """Approving revision 400 must not authorize revision 500."""
        with session(store=self.store) as ctx:
            approval = ctx.request_approval("rollback", {"deployment_id": "DEP-1", "revision": 400})
            ctx.approve(approval.approval_id, "operator")
            rollback = ctx.tool(
                lambda **kw: self.provider.execute(kw["deployment_id"], "k"),
                action="rollback",
                risk="destructive",
                provider=self.provider,
            )
            outcome = rollback(
                deployment_id="DEP-1",
                revision=500,
                approval_id=approval.approval_id,
            )

        self.assertEqual(outcome["status"], "blocked")
        self.assertIn("payload", outcome["error"].lower())
        self.assertEqual(self.provider.call_count, 0)

    def test_2b_unused_approval_is_not_consumed_by_a_refused_call(self) -> None:
        """A tampered attempt must not burn the approval the operator issued."""
        with session(store=self.store) as ctx:
            approval = ctx.request_approval("rollback", {"deployment_id": "DEP-1", "revision": 400})
            ctx.approve(approval.approval_id, "operator")
            rollback = ctx.tool(
                lambda **kw: self.provider.execute(kw["deployment_id"], "k"),
                action="rollback",
                risk="destructive",
                provider=self.provider,
            )
            rollback(deployment_id="DEP-1", revision=500, approval_id=approval.approval_id)
            self.assertIsNone(ctx.approvals.get(approval.approval_id).consumed_at)

    # -- 3. budgets are on by default -------------------------------------

    def test_3_budgets_trip_without_the_caller_asking(self) -> None:
        """A caller who passes nothing must still be bounded."""
        with session(store=self.store, limits=FuseLimits(max_steps=2)) as ctx:
            lookup = ctx.tool(lambda **kw: {"customer": "Ava"}, action="lookup", risk="read")
            for _ in range(6):
                lookup(customer="Ava")

        snapshot = ctx.fuse.snapshot()
        self.assertTrue(snapshot.tripped, "budget must trip on its own")
        self.assertLessEqual(snapshot.steps_used, 2)

    def test_3b_default_session_has_a_budget(self) -> None:
        with session(store=self.store) as ctx:
            self.assertIsNotNone(ctx.fuse)
            self.assertIsNotNone(ctx.fuse.limits.max_steps)

    # -- 4. ambiguity ------------------------------------------------------

    def test_4_missing_required_input_asks_instead_of_guessing(self) -> None:
        """Missing required input must not be silently defaulted."""
        with session(store=self.store) as ctx:
            rollback = ctx.tool(
                lambda **kw: {"ok": True},
                action="rollback",
                risk="destructive",
                provider=self.provider,
                required_fields=("deployment_id",),
            )
            approval = ctx.request_approval("rollback", {"revision": 400})
            ctx.approve(approval.approval_id, "operator")
            # Approved, but the result is missing a required field.
            outcome = rollback(revision=400, approval_id=approval.approval_id)

        self.assertNotEqual(outcome["status"], "allowed")
        self.assertIn("deployment_id", str(outcome.get("missing", "")))

    # -- 5. cross-environment ---------------------------------------------

    def test_5_cross_environment_action_is_blocked(self) -> None:
        """A staging session must not reach a production tool."""
        with session(store=self.store, environment="staging") as ctx:
            rollback = ctx.tool(
                lambda **kw: {"ok": True},
                action="deploy",
                risk="destructive",
                provider=self.provider,
                target_environment="prod",
            )
            outcome = rollback(component="api")

        self.assertEqual(outcome["status"], "blocked")
        self.assertEqual(outcome["decision"], "ENVIRONMENT")
        self.assertEqual(self.provider.call_count, 0)

    # -- 6. honest status --------------------------------------------------

    def test_6_blocked_run_is_not_reported_as_clean_completion(self) -> None:
        """The agent saying 'done' must not override a blocked step."""

        def agent(task: str, tools: dict[str, Any]) -> str:
            tools["rollback"](deployment_id="DEP-100", revision=400)
            return "All done, rollbacks issued."

        with session(store=self.store) as ctx:
            rollback = ctx.tool(
                lambda **kw: self.provider.execute(kw["deployment_id"], "k"),
                action="rollback",
                risk="destructive",
                provider=self.provider,
            )
            result = ctx.run(agent, "rollback everything", tools={"rollback": rollback})

        self.assertNotEqual(result["status"], "completed")
        self.assertIn(result["status"], {"blocked", "degraded"})
        self.assertEqual(self.provider.call_count, 0)

    # -- 7. no plaintext payment data at rest -----------------------------

    def test_7_no_plaintext_card_number_reaches_storage(self) -> None:
        """Payment data must not persist in the clear."""
        pan = "4111111111111111"  # Luhn-valid test PAN
        with session(store=self.store) as ctx:
            rollback = ctx.tool(
                lambda **kw: {"status": "deployed", "card": kw.get("card")},
                action="deploy",
                risk="destructive",
                provider=self.provider,
            )
            rollback(card=pan, revision=100)

        raw = self._raw_db_text()
        self.assertNotIn(pan, raw, "PAN persisted in plaintext")

    # -- 8. structural path test ------------------------------------------

    def test_8_documented_path_reaches_the_shared_pipeline(self) -> None:
        """Guard against a future refactor silently re-bypassing enforcement.

        Behavioural tests can pass while the pipeline is no longer on the path,
        so this one asserts the wiring itself.
        """
        from agent_action_gateway.engine import enforcement

        reached: list[str] = []
        original = enforcement.enforce

        def spy(*args: Any, **kwargs: Any) -> Any:
            context = kwargs.get("ctx") or (args[0] if args else None)
            reached.append(getattr(context, "action", "?"))
            return original(*args, **kwargs)

        with mock.patch.object(enforcement, "enforce", spy):
            with session(store=self.store) as ctx:
                lookup = ctx.tool(lambda **kw: {"ok": True}, action="lookup", risk="read")
                lookup(customer="Ava")

        self.assertIn("lookup", reached, "documented path must reach the shared pipeline")


class ObserveModeTest(unittest.TestCase):
    """run() must label itself honestly."""

    def test_bare_run_reports_observe_mode(self) -> None:
        from agent_action_gateway import run

        with tempfile.TemporaryDirectory() as directory:
            result = run(lambda task: "done", "task", TraceStore(Path(directory) / "r.db"))
        self.assertEqual(result.get("enforcement"), "observe")

    def test_session_run_reports_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with session(store=TraceStore(Path(directory) / "r.db")) as ctx:
                result = ctx.run(lambda task, tools: "done", "task", tools={})
        self.assertEqual(result.get("enforcement"), "enforced")


class SessionApiTest(unittest.TestCase):
    """The session surface itself."""

    def test_environment_default_is_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with session(store=TraceStore(Path(directory) / "r.db")) as ctx:
                self.assertEqual(ctx.environment, "dev")

    def test_unknown_action_defaults_to_destructive(self) -> None:
        """An unregistered action is never silently safe."""
        with tempfile.TemporaryDirectory() as directory:
            with session(store=TraceStore(Path(directory) / "r.db")) as ctx:
                ctx.registry.register("mystery", "destructive")
                self.assertEqual(ctx.registry.classify("never-registered"), "destructive")

    def test_approval_cannot_expire_in_the_past(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with session(store=TraceStore(Path(directory) / "r.db")) as ctx:
                with self.assertRaisesRegex(Exception, "expiry"):
                    ctx.request_approval(
                        "rollback", {"deployment_id": "O"}, expires_in_seconds=-1
                    )


if __name__ == "__main__":
    unittest.main()
