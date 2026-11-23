"""The MCP proxy forwarding to a real gateway: checks in the proxy, key in the gateway."""

from __future__ import annotations

import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from agent_action_gateway.integrations import mcp_proxy, mcp_server
from agent_action_gateway.integrations.gateway import (
    MCP_PATH,
    GatewayError,
    GatewayPolicy,
    Route,
    build_gateway_server,
)
from agent_action_gateway.integrations.mcp_proxy import (
    DownstreamError,
    ProxyConfig,
    ServerConfig,
    build_proxy,
)
from agent_action_gateway.storage.traces import TraceStore

REAL_KEY = "real-upstream-key-123"


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
        body = json.dumps({"ok": True, "path": self.path}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class ProxyToGatewayTest(unittest.TestCase):
    def setUp(self) -> None:
        Upstream.received = []
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        for name, value in (("AGENT_GATEWAY", "1"), ("AAG_TEST_UPSTREAM_KEY", REAL_KEY)):
            os.environ[name] = value
            self.addCleanup(os.environ.pop, name, None)

        self.upstream = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        threading.Thread(target=self.upstream.serve_forever, daemon=True).start()
        self.addCleanup(self.upstream.server_close)
        self.addCleanup(self.upstream.shutdown)
        base = f"http://127.0.0.1:{self.upstream.server_address[1]}"

        policy = GatewayPolicy(session_environment="prod")
        for path, risk in (("/status", "read"), ("/deploy", "destructive")):
            policy.register(Route(
                path=path, upstream=base + path, action=path.lstrip("/"), risk=risk,
                secret_env="AAG_TEST_UPSTREAM_KEY", environment="prod",
            ))
        # The proxy runs the checks; the gateway only holds the key.
        policy.enforcement_enabled = False
        gateway_store = TraceStore(Path(self._tmp.name) / "gateway.db")
        gateway_store.save_virtual_key("vk-all", "agent", ["/status", "/deploy"], expires_at=None)
        gateway_store.save_virtual_key("vk-read", "reader", ["/status"], expires_at=None)
        self.server, _ = build_gateway_server(gateway_store, policy, port=0, token="bootstrap-token")
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.mcp_url = f"http://127.0.0.1:{self.server.server_address[1]}{MCP_PATH}"

    def proxy(self, key: str = "vk-all"):
        config = ServerConfig(
            name="gw", url=self.mcp_url, headers={"Authorization": f"Bearer {key}"}
        )
        proxy = build_proxy(
            ProxyConfig((config,), environment="prod"), Path(self._tmp.name) / "proxy.db"
        )
        self.addCleanup(proxy.close)
        return proxy

    @staticmethod
    def text(result: dict) -> str:
        return result["content"][0]["text"]

    def test_routes_become_tools_and_the_gateway_says_which_are_read_only(self) -> None:
        proxy = self.proxy()
        risks = {name: risk for name, risk, _ in proxy.describe()}
        self.assertEqual(risks, {"gw__status": "read", "gw__deploy": "destructive"})

    def test_a_read_goes_through_and_the_gateway_adds_the_key(self) -> None:
        proxy = self.proxy()
        result = proxy.call_tool("gw__status", {})
        self.assertFalse(result["isError"], self.text(result))
        self.assertEqual(Upstream.received[0]["authorization"], f"Bearer {REAL_KEY}")

    def test_the_key_never_reaches_the_proxy_or_the_agent(self) -> None:
        proxy = self.proxy()
        result = proxy.call_tool("gw__status", {})
        self.assertNotIn(REAL_KEY, json.dumps(result))
        self.assertNotIn(REAL_KEY, json.dumps(proxy.list_tools()))
        self.assertNotIn(REAL_KEY, repr(proxy.configs))

    def test_a_destructive_route_is_held_by_the_proxy_before_the_gateway_sees_it(self) -> None:
        proxy = self.proxy()
        result = proxy.call_tool("gw__deploy", {"ref": "v2"})
        self.assertIn("needs a person's approval", self.text(result))
        self.assertEqual(Upstream.received, [])

    def test_after_approval_it_runs_once_and_the_idempotency_key_reaches_the_upstream(self) -> None:
        proxy = self.proxy()
        proxy.call_tool("gw__deploy", {"ref": "v2"})
        proxy.session.approvals.approve(proxy.session.approvals.pending()[0].approval_id, "alice")
        result = proxy.call_tool("gw__deploy", {"ref": "v2"})
        self.assertFalse(result["isError"], self.text(result))
        self.assertEqual(len(Upstream.received), 1)
        sent = Upstream.received[0]
        self.assertEqual(sent["authorization"], f"Bearer {REAL_KEY}")
        self.assertEqual(sent["payload"], {"ref": "v2"})
        # the proxy's own intent key, so a retry is recognised by the upstream too
        self.assertEqual(sent["idempotency_key"], proxy.session.decisions[-1].intent_key)

    def test_a_scoped_virtual_key_sees_only_its_routes(self) -> None:
        proxy = self.proxy("vk-read")
        self.assertEqual([t["name"] for t in proxy.list_tools()], ["gw__status"])

    def test_the_bootstrap_token_sees_every_route(self) -> None:
        proxy = self.proxy("bootstrap-token")
        self.assertEqual(len(proxy.list_tools()), 2)

    def test_an_unknown_key_is_refused_at_start_up(self) -> None:
        with self.assertRaises(DownstreamError):
            self.proxy("not-a-key")

    def test_a_route_cannot_take_the_mcp_path(self) -> None:
        with self.assertRaises(GatewayError):
            GatewayPolicy().register(
                Route(path=MCP_PATH, upstream="http://x.invalid/", action="x", risk="read")
            )

    def test_the_two_sides_agree_on_the_idempotency_meta_key(self) -> None:
        self.assertEqual(mcp_proxy.INTENT_META_KEY, mcp_server.INTENT_META_KEY)


if __name__ == "__main__":
    unittest.main()
