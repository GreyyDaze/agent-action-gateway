"""The dashboard is the human trust boundary's evidence surface.

Two things are tested here. That every panel renders from a populated
snapshot, and that every panel renders something intentional when there is
nothing to show -- an empty database must look like an empty dashboard, not a
broken one.

The security properties are pinned in tests/test_safety_invariants.py and are
not duplicated here.
"""

from __future__ import annotations

import json
import tempfile
import threading
import unittest
import urllib.request
from pathlib import Path

from agent_action_gateway import session
from agent_action_gateway.observability.dashboard import build_server
from agent_action_gateway.observability.view import build_run_view, state_meaning
from agent_action_gateway.storage.traces import TraceStore


def _soup(html: str) -> str:
    """Strip tags so a text probe does not depend on markup structure."""
    import re

    return re.sub(r"<[^>]+>", " ", html).lower()


class DashboardRenderTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.db = Path(self.directory.name) / "runtime.db"

    def _populate(self) -> None:
        store = TraceStore(self.db)
        with session(store=store, environment="prod") as ctx:
            ctx.record_model_exchange(
                prompt="shop-api is OOMKilled. Raise limits.memory 256Mi -> 768Mi.",
                completion="Patch deployment default/shop-api.",
                tokens_in=1420,
                tokens_out=96,
                cost_usd=0.0041,
                latency_ms=1840,
            )

            def describe(namespace: str, app: str) -> dict:
                return {"status": "ok", "restarts": 47, "exit_code": 137}

            def patch(namespace: str, app: str, memory_limit: str, intent_key: str = "") -> dict:
                # Echoes every required field back, or the result check
                # rejects it as partial and the action never counts as landed.
                return {
                    "status": "patched",
                    "app": app,
                    "namespace": namespace,
                    "memory_limit": memory_limit,
                }

            lookup = ctx.tool(describe, action="read.deployment", risk="read")
            patcher = ctx.tool(
                patch,
                action="patch.deployment",
                risk="destructive",
                target="shop-api",
                target_environment="prod",
                required_fields=("namespace", "app", "memory_limit"),
            )
            lookup(namespace="prod", app="shop-api")

            # An unapproved patch: refused, and the refusal is evidence.
            refused = patcher(namespace="prod", app="shop-api", memory_limit="768Mi")
            self.assertEqual(refused["status"], "blocked")

            # Leave this one pending so the approval panel has something to show.
            approval = ctx.request_approval(
                "patch.deployment",
                {"namespace": "prod", "app": "shop-api", "memory_limit": "768Mi"},
            )
            self.assertTrue(approval.approval_id)

            # A second, separately-approved patch so the receipts panel has a
            # completed effect to render alongside the pending one.
            settled = ctx.request_approval(
                "patch.deployment",
                {"namespace": "prod", "app": "shop-api", "memory_limit": "512Mi"},
            )
            ctx.approve(settled.approval_id, "oncall-sre")
            allowed = patcher(
                namespace="prod",
                app="shop-api",
                memory_limit="512Mi",
                approval_id=settled.approval_id,
            )
            self.assertEqual(allowed["status"], "allowed")

    def _get(self) -> str:
        server, handler = build_server(str(self.db), "127.0.0.1", 0, "test-token")
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_port}/"
            request = urllib.request.Request(
                url, headers={"Authorization": "Bearer test-token"}
            )
            return urllib.request.urlopen(request, timeout=10).read().decode()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    # -- populated ---------------------------------------------------------

    def test_every_section_renders(self) -> None:
        self._populate()
        html = self._get()
        text = _soup(html)
        for heading in (
            "this run",
            "timeline",
            "side-effect receipts",
            "approvals waiting",
            "budget",
            "gate history",
            "runs",
        ):
            self.assertIn(heading, text, f"missing section: {heading}")

    def test_a_refused_action_is_visible_with_its_reason(self) -> None:
        """The whole point of the page: what was refused, and why."""
        self._populate()
        text = _soup(self._get())
        self.assertIn("patch.deployment", text)
        self.assertIn("blocked", text)

    def test_the_pending_approval_is_offered_for_review(self) -> None:
        self._populate()
        html = self._get()
        self.assertIn("action='/approvals/approve'", html)
        self.assertIn("action='/approvals/deny'", html)
        self.assertIn("csrf_token", html)

    def test_model_exchange_cost_and_tokens_are_shown(self) -> None:
        """Spend is one of the three things the operator has to see."""
        self._populate()
        text = _soup(self._get())
        self.assertIn("1420", text)
        self.assertIn("0.0041", text)

    def test_a_run_is_labelled_by_whether_it_was_protected(self) -> None:
        """"recorded" and "protected" are not the same claim."""
        self._populate()
        text = _soup(self._get())
        self.assertIn("enforced", text)

    # -- empty -------------------------------------------------------------

    def test_an_empty_database_renders_intentional_empty_states(self) -> None:
        html = self._get()
        text = _soup(html)
        self.assertIn("no runs recorded", text)
        self.assertIn("no approvals are waiting", text)
        self.assertIn("no gate verdicts", text)
        # A blank page is indistinguishable from a crash. Every panel must say
        # something.
        for panel in ("timeline", "side-effect receipts", "budget"):
            self.assertIn(panel, text)

    def test_unreported_model_usage_says_so_instead_of_zero(self) -> None:
        from agent_action_gateway.observability.view import _spent

        self.assertEqual(_spent([{"event": "tool"}]), (None, None, 0))
        self.assertEqual(
            _spent([{"tokens_in": 10, "tokens_out": 5}, {"cost_usd": 0.25}]), (0.25, 15, 2)
        )
        db = Path(self.db)
        db.unlink(missing_ok=True)
        with session(store=TraceStore(db)) as ctx:
            ctx.tool(lambda: {"ok": True}, action="t.read", risk="read")()
        html = self._get()
        self.assertIn("not reported", html)
        self.assertNotIn("$0.0000", html)

    def test_the_only_script_is_the_refresh_and_the_policy_allows_only_it(self) -> None:
        """One inline script, allowed by its hash; no file, no other script."""
        import base64
        import hashlib
        import re

        server, _ = build_server(str(self.db), "127.0.0.1", 0, "test-token")
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{server.server_port}/",
                headers={"Authorization": "Bearer test-token"},
            )
            with urllib.request.urlopen(request, timeout=10) as response:
                policy = response.headers["Content-Security-Policy"]
                html = response.read().decode()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

        scripts = re.findall(r"<script>(.*?)</script>", html, re.S)
        self.assertEqual(len(scripts), 1)
        self.assertEqual(html.lower().count("<script"), 1)
        self.assertNotIn("javascript:", html.lower())
        digest = base64.b64encode(hashlib.sha256(scripts[0].encode()).digest()).decode()
        self.assertIn(f"script-src 'sha256-{digest}'", policy)
        self.assertNotIn("unsafe-inline';", policy.split("script-src", 1)[1].split(";", 1)[0])
        self.assertIn("default-src 'none'", policy)
        # It waits while a person is busy, and reloads only this page.
        self.assertIn("document.activeElement", scripts[0])
        self.assertIn("details[open]", scripts[0])
        self.assertIn("location.reload()", scripts[0])
        self.assertNotIn("fetch(", scripts[0])

    def test_the_page_is_responsive(self) -> None:
        html = self._get()
        self.assertIn('name="viewport"', html)
        self.assertIn("@media (max-width:860px)", html)

    def test_blue_is_kept_for_the_logo_and_links(self) -> None:
        """The style guide: blue only for the logo mark and links."""
        html = self._get()
        self.assertEqual(html.count("#005DFF"), 2)  # the token, and the logo mark


class ViewModelTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.db = Path(self.directory.name) / "runtime.db"

    def test_an_empty_snapshot_still_produces_a_view(self) -> None:
        """Every collection is present and empty, so the renderer cannot KeyError."""
        view = build_run_view(TraceStore(self.db).dashboard_snapshot(), None)
        self.assertFalse(view["has_run"])
        self.assertIsNone(view["run_id"])
        for key in ("runs", "traces", "receipts", "gates"):
            self.assertEqual(view[key], [], key)
        self.assertEqual(view["totals"]["steps"], 0)
        self.assertEqual(view["enforcement"], "unknown")

    def test_a_run_reports_its_worst_step_not_its_last(self) -> None:
        """A run that blocked something and then finished is not 'completed'.

        Reporting it as completed is the sort of tidy lie this project exists
        to prevent, and it is the one most likely to be introduced by a
        well-meaning refactor of the status logic.
        """
        store = TraceStore(self.db)
        with session(store=store) as ctx:
            lookup = ctx.tool(lambda app: {"ok": True}, action="read.deployment", risk="read")
            lookup(app="shop-api")
            refused = ctx.tool(
                lambda app: {"ok": True},
                action="delete.namespace",
                risk="destructive",
            )
            refused(app="shop-api")
            lookup(app="shop-api")

        view = build_run_view(store.dashboard_snapshot(), None)
        self.assertEqual(view["totals"]["blocked"], 1)
        self.assertEqual(view["runs"][0]["status"], "blocked")

    def test_receipts_are_grouped_under_their_run(self) -> None:
        store = TraceStore(self.db)
        with session(store=store) as ctx:
            def write(app: str, intent_key: str = "") -> dict:
                return {"status": "written"}

            tool = ctx.tool(write, action="write.config", risk="destructive")
            approval = ctx.request_approval("write.config", {"app": "shop-api"})
            ctx.approve(approval.approval_id, "operator")
            tool(app="shop-api", approval_id=approval.approval_id)

        view = build_run_view(store.dashboard_snapshot(), None)
        self.assertEqual(len(view["receipts"]), 1)
        receipt = view["receipts"][0]
        self.assertEqual(receipt["state"], "done")
        self.assertTrue(receipt["effect_key"])
        self.assertEqual(receipt["state_meaning"], "landed")
        self.assertFalse(receipt["needs_review"])

    def test_a_pending_receipt_is_flagged_for_review(self) -> None:
        """`pending` is the state a human has to act on."""
        store = TraceStore(self.db)
        with session(store=store) as ctx:
            tool = ctx.tool(
                lambda app, intent_key="": {"ok": True},
                action="write.config",
                risk="destructive",
            )
            approval = ctx.request_approval("write.config", {"app": "shop-api"})
            ctx.approve(approval.approval_id, "operator")
            tool(app="shop-api", approval_id=approval.approval_id)
        # Simulate the crash window: dispatched, outcome never recorded.
        with store.connection() as connection:
            connection.execute("UPDATE receipts SET state='pending'")

        view = build_run_view(store.dashboard_snapshot(), None)
        self.assertEqual(view["totals"]["pending"], 1)
        self.assertTrue(view["receipts"][0]["needs_review"])

    def test_the_api_state_route_returns_the_raw_snapshot(self) -> None:
        server, _ = build_server(str(self.db), "127.0.0.1", 0, "test-token")
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_port}/api/state"
            request = urllib.request.Request(
                url, headers={"Authorization": "Bearer test-token"}
            )
            payload = json.loads(urllib.request.urlopen(request, timeout=10).read())
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        for key in ("traces", "receipts", "runs", "budgets", "gate_verdicts"):
            self.assertIn(key, payload)


class ReceiptStateTest(unittest.TestCase):
    def test_every_state_has_a_plain_meaning(self) -> None:
        """A bare status word is not readable evidence."""
        for state in ("done", "pending", "failed", "resolved", "unknown"):
            self.assertTrue(state_meaning(state))
        self.assertEqual(state_meaning("nonsense"), "unrecognised state")


if __name__ == "__main__":
    unittest.main()
