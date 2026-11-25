"""The three moments a person is in the loop, done the way a browser does them.

A browser opens `/?token=...` once, then sends a cookie and plain form posts
with its own Origin. The older tests sent the token in a header on every
request, which a browser form cannot do, so Approve never worked in a real
browser while they passed. These tests use only what a browser sends.
"""

from __future__ import annotations

import http.client
import re
import tempfile
import threading
import unittest
import urllib.parse
from datetime import UTC, datetime, timedelta
from pathlib import Path

from agent_action_gateway import OutcomeUnknown, session
from agent_action_gateway.integrations.mcp_proxy import PinStore
from agent_action_gateway.observability.dashboard import build_server
from agent_action_gateway.observability.view import build_run_view
from agent_action_gateway.policy.locks import ApprovalStore
from agent_action_gateway.storage.traces import TraceStore

TOKEN = "dashboard-test-token"


class Browser:
    """Just enough of a browser: a cookie jar, an Origin, no auth header."""

    def __init__(self, port: int) -> None:
        self.port = port
        self.origin = f"http://127.0.0.1:{port}"
        self.cookie = ""

    def request(self, method: str, path: str, body: str = "") -> http.client.HTTPResponse:
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        headers = {"Cookie": self.cookie} if self.cookie else {}
        if method == "POST":
            headers["Origin"] = self.origin
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        connection.request(method, path, body=body.encode(), headers=headers)
        response = connection.getresponse()
        cookie = response.getheader("Set-Cookie")
        if cookie:
            self.cookie = cookie.split(";", 1)[0]
        response.body = response.read().decode()  # type: ignore[attr-defined]
        connection.close()
        return response

    def open(self) -> str:
        first = self.request("GET", f"/?token={TOKEN}")
        assert first.status == 303, first.status
        page = self.request("GET", "/")
        assert page.status == 200, page.status
        return page.body  # type: ignore[attr-defined,no-any-return]

    def submit(self, page: str, action: str, **fields: str) -> http.client.HTTPResponse:
        csrf = re.search(r"name='csrf_token' value='([^']+)'", page).group(1)  # type: ignore[union-attr]
        body = urllib.parse.urlencode({"csrf_token": csrf, **fields})
        return self.request("POST", action, body)


class DashboardActionsTest(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.db = Path(tmp.name) / "runtime.db"

    def serve(self) -> Browser:
        server, _ = build_server(str(self.db), "127.0.0.1", 0, TOKEN)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return Browser(server.server_address[1])

    def pending_approval(self) -> str:
        with session(store=TraceStore(self.db), environment="staging") as ctx:
            ctx.tool(lambda table, intent_key="": {"ok": True},
                     action="db.drop_table", risk="destructive")
            return ctx.request_approval("db.drop_table", {"table": "users"}).approval_id

    # -- signing in ---------------------------------------------------------

    def test_the_token_becomes_a_strict_cookie_and_leaves_the_address(self) -> None:
        browser = self.serve()
        first = browser.request("GET", f"/?token={TOKEN}")
        self.assertEqual(first.status, 303)
        self.assertEqual(first.getheader("Location"), "/")
        cookie = first.getheader("Set-Cookie") or ""
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)

    def test_without_the_cookie_or_token_the_page_is_locked(self) -> None:
        browser = self.serve()
        self.assertEqual(browser.request("GET", "/").status, 401)

    def test_the_referrer_policy_keeps_our_own_origin(self) -> None:
        """With `no-referrer`, a browser sends `Origin: null` and every post fails."""
        browser = self.serve()
        response = browser.request("GET", f"/?token={TOKEN}")
        self.assertEqual(response.getheader("Referrer-Policy"), "same-origin")

    # -- approve ------------------------------------------------------------

    def test_a_browser_can_approve(self) -> None:
        approval_id = self.pending_approval()
        browser = self.serve()
        page = browser.open()
        response = browser.submit(
            page, "/approvals/approve", approval_id=approval_id, approver="reviewer"
        )
        self.assertEqual(response.status, 303)
        approval = ApprovalStore(TraceStore(self.db)).get(approval_id)
        self.assertEqual((approval.decision, approval.approver), ("approved", "reviewer"))

    def test_a_post_from_another_site_is_refused(self) -> None:
        approval_id = self.pending_approval()
        browser = self.serve()
        page = browser.open()
        browser.origin = "http://evil.example"
        response = browser.submit(
            page, "/approvals/approve", approval_id=approval_id, approver="x"
        )
        self.assertEqual(response.status, 403)
        self.assertEqual(ApprovalStore(TraceStore(self.db)).get(approval_id).decision, "pending")

    def test_the_card_shows_risk_environment_and_run(self) -> None:
        self.pending_approval()
        page = self.serve().open()
        self.assertIn("destructive", page)
        self.assertIn("staging", page)
        self.assertIn("run ", page)

    def test_an_expired_approval_is_not_offered(self) -> None:
        store = ApprovalStore(TraceStore(self.db))
        approval = store.request(
            "db.drop_table", {"table": "old"}, datetime.now(UTC) + timedelta(seconds=1)
        )
        with store.connection() as connection:
            connection.execute(
                "UPDATE approvals SET expires_at=? WHERE approval_id=?",
                ((datetime.now(UTC) - timedelta(minutes=1)).isoformat(), approval.approval_id),
            )
        page = self.serve().open()
        self.assertNotIn(approval.approval_id, page)
        self.assertIn("No approvals are waiting", page)

    def test_given_and_denied_approvals_are_listed_with_who(self) -> None:
        approval_id = self.pending_approval()
        ApprovalStore(TraceStore(self.db)).deny(approval_id, "reviewer")
        page = self.serve().open()
        history = page.split("Approval history</h1>", 1)[1]
        self.assertIn("denied", history)
        self.assertIn("reviewer", history)

    # -- settle -------------------------------------------------------------

    def held_action(self, evidence: list | None = None) -> str:
        def restart(service: str, intent_key: str = "") -> dict:
            raise OutcomeUnknown("no answer")

        with session(store=TraceStore(self.db), environment="prod") as ctx:
            tool = ctx.tool(restart, action="service.restart", risk="write")
            approval = ctx.request_approval(
                "service.restart", {"service": "api"}, evidence=evidence
            )
            ctx.approve(approval.approval_id, "reviewer")
            with self.assertRaises(OutcomeUnknown):
                tool(service="api", approval_id=approval.approval_id)
        (held,) = TraceStore(self.db).unknown_receipts()
        return held.intent_key

    def test_a_browser_can_settle_a_held_action_and_it_is_recorded(self) -> None:
        key = self.held_action()
        browser = self.serve()
        page = browser.open()
        self.assertIn("Held actions", page)
        response = browser.submit(
            page, "/receipts/settle", intent_key=key, outcome="done",
            approver="reviewer", ref="ticket-7",
        )
        self.assertEqual(response.status, 303)
        store = TraceStore(self.db)
        self.assertEqual(store.unknown_receipts(), [])
        settled = [t for t in store.snapshot()["traces"] if t["event"] == "receipt.settled"]
        self.assertEqual(settled[0]["input"]["by"], "reviewer")
        self.assertEqual(settled[0]["input"]["ref"], "ticket-7")

    def test_settling_something_not_held_is_refused(self) -> None:
        self.held_action()
        browser = self.serve()
        page = browser.open()
        response = browser.submit(
            page, "/receipts/settle", intent_key="nope", outcome="done", approver="r"
        )
        self.assertEqual(response.status, 400)

    def test_held_actions_from_every_run_are_shown(self) -> None:
        self.held_action()
        with session(store=TraceStore(self.db), environment="prod") as ctx:
            ctx.tool(lambda: {"ok": True}, action="later.read", risk="read")()
        view = build_run_view(TraceStore(self.db).dashboard_snapshot(), None)
        self.assertEqual(len(view["held"]), 1)
        self.assertNotEqual(view["held"][0]["run_id"], view["run_id"])

    # -- evidence ------------------------------------------------------------

    def test_a_waiting_approval_shows_its_evidence_links(self) -> None:
        with session(store=TraceStore(self.db), environment="staging") as ctx:
            ctx.request_approval(
                "db.drop_table",
                {"table": "users"},
                evidence=[
                    {"label": "Migration 0042 diff", "url": "https://example.com/diff/42"},
                    "Checked on staging first",
                ],
            )
        page = self.serve().open()
        self.assertIn("Evidence:", page)
        self.assertIn("href='https://example.com/diff/42'", page)
        self.assertIn("rel='noopener noreferrer'", page)
        self.assertIn("Checked on staging first", page)

    def test_a_held_action_shows_who_approved_it_and_what_they_saw(self) -> None:
        self.held_action(evidence=[{"label": "Replay", "url": "https://example.com/replay/9"}])
        page = self.serve().open()
        self.assertIn("Approved by reviewer", page)
        self.assertIn("href='https://example.com/replay/9'", page)

    def test_approval_history_lists_the_evidence(self) -> None:
        self.held_action(evidence=["https://example.com/diff/7"])
        page = self.serve().open()
        self.assertIn("<th>Evidence</th>", page)
        self.assertEqual(page.count("href='https://example.com/diff/7'"), 2)

    def test_a_script_link_in_stored_evidence_is_never_made_clickable(self) -> None:
        approval_id = self.pending_approval()
        store = ApprovalStore(TraceStore(self.db))
        with store.connection() as connection:
            connection.execute(
                "UPDATE approvals SET context_json=? WHERE approval_id=?",
                (
                    '{"risk": "destructive", "evidence": [{"label": "<b>x</b>", '
                    '"url": "javascript:alert(1)"}]}',
                    approval_id,
                ),
            )
        page = self.serve().open()
        self.assertNotIn("javascript:", page)
        self.assertNotIn("<b>x</b>", page)
        self.assertIn("&lt;b&gt;x&lt;/b&gt;", page)

    # -- accept a tool ------------------------------------------------------

    def test_a_browser_can_accept_a_waiting_tool(self) -> None:
        pins = PinStore(self.db)
        pins.pin("db__run_sql", "db", "h0", "first use")
        pins.hold("db__run_sql", "db", "h1")
        browser = self.serve()
        page = browser.open()
        self.assertIn("db__run_sql", page)
        response = browser.submit(page, "/tools/accept", tool="db__run_sql", approver="reviewer")
        self.assertEqual(response.status, 303)
        self.assertEqual(pins.waiting(), [])
        self.assertEqual(pins.pinned("db__run_sql"), "h1")

    def test_without_proxy_data_there_is_nothing_to_accept(self) -> None:
        page = self.serve().open()
        self.assertIn("No MCP proxy data in this database", page)

    # -- the run shown ------------------------------------------------------

    def test_the_newest_run_is_shown_first(self) -> None:
        with session(store=TraceStore(self.db), environment="prod") as ctx:
            tool = ctx.tool(lambda n: {"ok": True}, action="big.read", risk="read")
            for n in range(5):
                tool(n=n)
            older = ctx.run_id
        with session(store=TraceStore(self.db), environment="prod") as ctx:
            ctx.tool(lambda: {"ok": True}, action="small.read", risk="read")()
            newer = ctx.run_id
        view = build_run_view(TraceStore(self.db).dashboard_snapshot(), None)
        self.assertEqual(view["run_id"], newer)
        self.assertNotEqual(view["run_id"], older)


if __name__ == "__main__":
    unittest.main()
