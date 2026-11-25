"""Checks every scene of the demo without an LLM, before recording.

This is a test harness, not the agent: it plays the agent (MCP calls to the
proxy) and the person (dashboard forms), so a failing setup is found before a
real agent run. Run with ./run.sh check. Exit 0 only if every check passes.
"""

from __future__ import annotations

import http.cookiejar
import json
import os
import re
import socket
import sys
import urllib.parse
import urllib.request

PROXY = "http://proxy:8090/mcp"
DASH = "http://dashboard:8765"
TOKEN = os.environ["AGENT_GATEWAY_PROXY_TOKEN"]
DASH_TOKEN = os.environ["AGENT_GATEWAY_DASHBOARD_TOKEN"]
RESULTS: list[tuple[bool, str]] = []


def check(ok: bool, what: str, detail: object = "") -> None:
    RESULTS.append((ok, what))
    print(("PASS " if ok else "FAIL ") + what + (f"\n     {detail}" if not ok and detail else ""))


class Mcp:
    def __init__(self) -> None:
        self.session = None
        self.n = 0
        self.rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                "clientInfo": {"name": "demo-check", "version": "1"}})
        self.notify("notifications/initialized")

    def _post(self, body: dict) -> dict | None:
        headers = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json",
                   "Accept": "application/json, text/event-stream"}
        if self.session:
            headers["Mcp-Session-Id"] = self.session
        req = urllib.request.Request(PROXY, json.dumps(body).encode(), headers)
        with urllib.request.urlopen(req, timeout=60) as resp:
            self.session = resp.headers.get("Mcp-Session-Id") or self.session
            raw = resp.read().decode()
        return json.loads(raw) if raw.strip() else None

    def notify(self, method: str) -> None:
        self._post({"jsonrpc": "2.0", "method": method})

    def rpc(self, method: str, params: dict) -> dict:
        self.n += 1
        reply = self._post({"jsonrpc": "2.0", "id": self.n, "method": method, "params": params})
        assert reply is not None
        return reply

    def call(self, tool: str, args: dict) -> tuple[bool, str]:
        result = self.rpc("tools/call", {"name": tool, "arguments": args}).get("result", {})
        text = " ".join(c.get("text", "") for c in result.get("content", []))
        return bool(result.get("isError")), text


class Person:
    """Uses the dashboard the way a browser does: token once, then cookie + CSRF."""

    def __init__(self) -> None:
        jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
        self.page = self.get(f"/?token={DASH_TOKEN}")

    def get(self, path: str) -> str:
        with self.opener.open(DASH + path, timeout=10) as resp:
            return resp.read().decode()

    def post(self, path: str, fields: dict) -> int:
        page = self.get("/")
        csrf = re.search(r"name='csrf_token' value='([^']+)'", page).group(1)
        data = urllib.parse.urlencode({**fields, "csrf_token": csrf}).encode()
        req = urllib.request.Request(DASH + path, data, {
            "Origin": "http://127.0.0.1:8765", "Content-Type": "application/x-www-form-urlencoded"})
        # The dashboard checks Origin against --allow-origin; the Host header
        # here is dashboard:8765, so send the address a person opens.
        req.add_header("Host", "127.0.0.1:8765")
        with self.opener.open(req, timeout=10) as resp:
            return resp.status

    def approve(self, approval_id: str) -> int:
        return self.post("/approvals/approve", {"approval_id": approval_id, "approver": "demo-reviewer"})


def approval_id(text: str) -> str | None:
    found = re.search(r"Approval id: ([\w-]+)", text)
    return found.group(1) if found else None


def reachable(host: str, port: int) -> bool:
    try:
        socket.create_connection((host, port), timeout=3).close()
        return True
    except OSError:
        return False


def main() -> int:
    agent = Mcp()
    person = Person()
    tools = [t["name"] for t in agent.rpc("tools/list", {})["result"]["tools"]]
    check("staging__execute_sql" in tools and "ops__staging-api/restart" in tools,
          "the agent sees the database and ops tools through the proxy", tools)

    # Scene: no way around the checks.
    check(not reachable("postgres", 5432), "the agent side cannot reach Postgres directly")
    check(not reachable("gateway", 8080), "the agent side cannot reach the gateway directly")

    # Scene: reads run freely.
    err, text = agent.call("staging__execute_sql", {"sql": "SELECT version, dirty FROM schema_migrations ORDER BY version"})
    check(not err and "42" in text, "a read on staging runs without approval", text[:200])

    # Scene: environment.
    err, text = agent.call("prod__execute_sql", {"sql": "SELECT count(*) FROM ticket_comments"})
    check(err and "prod" in text.lower(), "a call to prod from the staging session is refused", text[:200])

    # Scene: exact approval.
    fix = "TRUNCATE ticket_comments"
    err, text = agent.call("staging__execute_sql", {"sql": fix})
    aid = approval_id(text)
    check(err and aid is not None, "a destructive statement is held for approval", text[:200])
    check(person.approve(aid) in (200, 303), "a person approves it in the dashboard")
    err, text = agent.call("staging__execute_sql", {"sql": "DROP TABLE ticket_comments"})
    check(err, "a different statement is not covered by that approval", text[:200])
    err, text = agent.call("staging__execute_sql", {"sql": fix})
    check(not err, "the approved statement runs", text[:200])

    # Scene: once only.
    err, text = agent.call("staging__execute_sql", {"sql": fix})
    aid2 = approval_id(text)
    check(err and aid2 is not None, "repeating it asks for a new approval (each approval works once)", text[:200])
    person.approve(aid2)
    err, text = agent.call("staging__execute_sql", {"sql": fix})
    check("already" in text.lower() or "earlier" in text.lower() or "first result" in text.lower(),
          "approved again, it answers with the earlier result and does not run again", text[:300])

    # Scene: key held by the gateway.
    err, text = agent.call("ops__staging-api/status", {})
    check(not err and "staging-api" in text, "the status read goes through the gateway", text[:200])
    err, text = agent.call("ops__staging-api/restart", {})
    aid3 = approval_id(text)
    check(err and aid3 is not None, "a restart needs approval", text[:200])
    person.approve(aid3)
    err, text = agent.call("ops__staging-api/restart", {})
    check(not err and '"restarted"' in text and "restarts_so_far" in text,
          "after approval the restart runs, with the key added by the gateway", text[:300])
    check(os.environ.get("OPS_API_KEY", "") == "", "the agent side has no ops key in its environment")

    # Proof.
    page = person.get("/")
    check("demo-reviewer" in page, "the dashboard shows who approved", "")

    failed = [w for ok, w in RESULTS if not ok]
    print(f"\n{len(RESULTS) - len(failed)} of {len(RESULTS)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
