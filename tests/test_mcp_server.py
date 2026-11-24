"""The gateway's MCP handler holds no policy; every call goes through the bridge."""

from __future__ import annotations

import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from agent_action_gateway.integrations.gateway import GatewayPolicy, Route, SafetyGateway
from agent_action_gateway.integrations.mcp import MCPToolBridge
from agent_action_gateway.integrations.mcp_server import MCPServer
from agent_action_gateway.storage.traces import TraceStore


class MCPServerTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.store = TraceStore(Path(self._tmp.name) / "runtime.db")
        self.calls: list[dict] = []

        def transport(upstream, payload, headers):
            self.calls.append({"payload": dict(payload)})
            return 200, {"id": "ch_1"}

        self.policy = GatewayPolicy(session_environment="prod")
        self.policy.register(
            Route(path="/deploy", upstream="https://x.invalid/deploy", action="deploy", risk="destructive")
        )
        self.gateway = SafetyGateway(self.store, self.policy, transport=transport)
        self.server = MCPServer(MCPToolBridge(self.gateway))

    def test_initialize_advertises_tools(self) -> None:
        result = self.server.handle({"method": "initialize", "id": 1, "params": {}})
        assert result is not None
        self.assertEqual(result["result"]["capabilities"], {"tools": {}})

    def test_tools_list_includes_registered_route(self) -> None:
        result = self.server.handle({"method": "tools/list", "id": 2, "params": {}})
        assert result is not None
        names = [t["name"] for t in result["result"]["tools"]]
        self.assertIn("deploy", names)

    def test_destructive_call_blocked(self) -> None:
        result = self.server.handle({
            "method": "tools/call", "id": 3,
            "params": {"name": "deploy", "arguments": {"revision": 100}},
        })
        assert result is not None
        self.assertTrue(result["result"]["isError"])
        self.assertEqual(self.calls, [])

    def test_approved_call_forwards_once(self) -> None:
        approval = self.gateway.approvals.request(
            "deploy", {"revision": 100, "_idempotency_key": "k"}, datetime.now(UTC) + timedelta(minutes=5)
        )
        self.gateway.approvals.approve(approval.approval_id, "op")
        result = self.server.handle({
            "method": "tools/call", "id": 4,
            "params": {"name": "deploy", "arguments": {
                "revision": 100,
                "_idempotency_key": "k",
                "_approval_id": approval.approval_id,
            }},
        })
        assert result is not None
        self.assertFalse(result["result"]["isError"])
        self.assertEqual(len(self.calls), 1)

    def test_unknown_method_is_json_rpc_error(self) -> None:
        result = self.server.handle({"method": "nope", "id": 5})
        assert result is not None
        self.assertEqual(result["error"]["code"], -32601)


if __name__ == "__main__":
    unittest.main()
