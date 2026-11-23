"""The MCP proxy in front of the real `agent-gateway gateway` process, from a route file on disk.

The in-process test (test_proxy_gateway.py) sets the gateway's policy flag in code.
This one starts the gateway the way an operator does and proves the same thing from
the file: a `credentials` block means the gateway does not ask for its own approval.
The gateway refuses loopback destinations, so the upstream is reached as
`e2e.localhost`, which resolves to loopback; the test is skipped where it does not.
"""

from __future__ import annotations

import json
import os
import queue
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from agent_action_gateway.integrations.mcp_proxy import ProxyConfig, ServerConfig, build_proxy

ROOT = Path(__file__).resolve().parents[1]
HOST = "e2e.localhost"
REAL_KEY = "real-upstream-key-456"


def resolves_to_loopback() -> bool:
    try:
        return socket.gethostbyname(HOST) == "127.0.0.1"
    except OSError:
        return False


class Upstream(BaseHTTPRequestHandler):
    received: list[dict] = []

    def log_message(self, *args: object) -> None:
        return

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length) or b"{}")
        type(self).received.append({
            "path": self.path,
            "authorization": self.headers.get("Authorization", ""),
            "idempotency_key": self.headers.get("Idempotency-Key", ""),
            "payload": payload,
        })
        body = json.dumps({"ok": True}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@unittest.skipUnless(resolves_to_loopback(), f"{HOST} does not resolve to loopback here")
class ProxyToGatewayProcessTest(unittest.TestCase):
    def setUp(self) -> None:
        Upstream.received = []
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        tmp = Path(self._tmp.name)

        self.upstream = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        threading.Thread(target=self.upstream.serve_forever, daemon=True).start()
        self.addCleanup(self.upstream.server_close)
        self.addCleanup(self.upstream.shutdown)
        base = f"http://{HOST}:{self.upstream.server_address[1]}"

        routes = tmp / "routes.json"
        routes.write_text(json.dumps({
            "master_key_env": "AAG_E2E_MASTER",
            "session_environment": "prod",
            "credentials": [{
                "secret_name": "UPSTREAM",
                "secret_env": "AAG_E2E_UPSTREAM_KEY",
                "allowed_hosts": [HOST],
                "header": "Authorization",
            }],
            "allowed_hosts": [HOST],
            "routes": [
                {"path": "/status", "upstream": base + "/status", "action": "status",
                 "risk": "read", "host": HOST, "environment": "prod"},
                {"path": "/deploy", "upstream": base + "/deploy", "action": "deploy",
                 "risk": "destructive", "host": HOST, "environment": "prod"},
            ],
        }))
        env = {
            **os.environ,
            "PYTHONPATH": str(ROOT / "src"),
            "AAG_E2E_MASTER": "master-value",
            "AAG_E2E_UPSTREAM_KEY": REAL_KEY,
        }
        self.gateway_db = str(tmp / "gateway.db")
        issued = subprocess.run(
            [sys.executable, "-m", "agent_action_gateway.cli", "gateway",
             "--config", str(routes), "--db", self.gateway_db,
             "issue-key", "--name", "agent", "--routes", "/status,/deploy"],
            env=env, capture_output=True, text=True, check=True,
        )
        self.virtual_key = issued.stdout.split("Virtual key issued:")[1].split()[0]

        self.process = subprocess.Popen(
            [sys.executable, "-u", "-m", "agent_action_gateway.cli", "gateway",
             "--config", str(routes), "--db", self.gateway_db, "--port", "0"],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        self.addCleanup(self._stop_gateway)
        self.port = self._wait_for_port()

    def _stop_gateway(self) -> None:
        self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
        if self.process.stdout:
            self.process.stdout.close()

    def _wait_for_port(self) -> int:
        found: queue.Queue[str] = queue.Queue()

        def read() -> None:
            assert self.process.stdout is not None
            for line in self.process.stdout:
                found.put(line)

        threading.Thread(target=read, daemon=True).start()
        lines = []
        for _ in range(50):
            try:
                line = found.get(timeout=0.2)
            except queue.Empty:
                continue
            lines.append(line)
            if "Safety gateway on" in line:
                return int(line.rsplit(":", 1)[1].strip().strip("/"))
        raise AssertionError("the gateway did not start: " + "".join(lines))

    def proxy(self):
        config = ServerConfig(
            name="gw",
            url=f"http://127.0.0.1:{self.port}/mcp",
            headers={"Authorization": f"Bearer {self.virtual_key}"},
        )
        proxy = build_proxy(
            ProxyConfig((config,), environment="prod"), Path(self._tmp.name) / "proxy.db"
        )
        self.addCleanup(proxy.close)
        return proxy

    @staticmethod
    def text(result: dict) -> str:
        return result["content"][0]["text"]

    def test_tools_and_risk_come_from_the_route_file(self) -> None:
        risks = {name: risk for name, risk, _ in self.proxy().describe()}
        self.assertEqual(risks, {"gw__status": "read", "gw__deploy": "destructive"})

    def test_a_read_reaches_the_upstream_with_the_real_key_added_by_the_gateway(self) -> None:
        result = self.proxy().call_tool("gw__status", {})
        self.assertFalse(result["isError"], self.text(result))
        self.assertIn(REAL_KEY, Upstream.received[0]["authorization"])

    def test_a_destructive_call_needs_one_approval_in_the_proxy_and_none_in_the_gateway(self) -> None:
        proxy = self.proxy()
        held = proxy.call_tool("gw__deploy", {"ref": "v2"})
        self.assertIn("needs a person's approval", self.text(held))
        self.assertEqual(Upstream.received, [])
        proxy.session.approvals.approve(proxy.session.approvals.pending()[0].approval_id, "alice")
        done = proxy.call_tool("gw__deploy", {"ref": "v2"})
        # If the gateway had asked for its own approval this would be an error.
        self.assertFalse(done["isError"], self.text(done))
        self.assertEqual(len(Upstream.received), 1)
        self.assertIn(REAL_KEY, Upstream.received[0]["authorization"])
        self.assertEqual(
            Upstream.received[0]["idempotency_key"], proxy.session.decisions[-1].intent_key
        )

    def test_the_real_key_is_nowhere_the_proxy_or_agent_can_see(self) -> None:
        proxy = self.proxy()
        result = proxy.call_tool("gw__status", {})
        self.assertNotIn(REAL_KEY, json.dumps(result))
        self.assertNotIn(REAL_KEY, json.dumps(proxy.list_tools()))
        self.assertNotIn(REAL_KEY, repr(proxy.configs))


if __name__ == "__main__":
    unittest.main()
