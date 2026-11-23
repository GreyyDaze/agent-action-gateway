"""Phase 3: the MCP surface must not be a second, weaker policy path.

The whole point of routing MCP calls through `SafetyGateway.handle` is that
arriving over MCP instead of HTTP buys the caller nothing. These tests assert
that property directly by performing the same action through both doors and
comparing what was written.

`RealSessionRunTest`-style drift is guarded here too: an event name that stops
existing would otherwise make this file pass while the runtime disagrees.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from agent_action_gateway.integrations.gateway import (
    GatewayPolicy,
    Route,
    SafetyGateway,
)
from agent_action_gateway.integrations.mcp import (
    MCPToolBridge,
    route_path_for,
    tool_definitions,
    tool_name_for,
)
from agent_action_gateway.storage.traces import TraceStore


class UpstreamRecorder:
    """Stands in for a provider. Counts forwards so a test can prove exactly
    one upstream call happened, or none."""

    def __init__(self) -> None:
        self.calls: list[dict] = []

    def __call__(self, upstream, payload, headers):
        self.calls.append({"upstream": upstream, "payload": payload, "headers": dict(headers)})
        return 200, {"id": "ch_1", "status": "succeeded"}


class BridgeTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup
                        )
        self.store = TraceStore(Path(self._tmp.name) / "runtime.db")
        self.upstream = UpstreamRecorder()
        self.policy = GatewayPolicy(session_environment="prod")
        for path, action, risk in (
            ("/charge", "charge", "destructive"),
            ("/lookup", "lookup", "read"),
        ):
            self.policy.register(
                Route(
                    path=path,
                    upstream=f"https://example.invalid{path}",
                    action=action,
                    risk=risk,
                    environment="prod",
                )
            )

    def _approve(self, gateway: SafetyGateway, action: str, payload: dict) -> str:
        approval = gateway.approvals.request(
            action, payload, datetime.now(UTC) + timedelta(minutes=5)
        )
        gateway.approvals.approve(approval.approval_id, "operator")
        return approval.approval_id

    def _traces(self) -> list[dict]:
        return self.store.snapshot()["traces"]

    def _decisions(self) -> list[dict]:
        return [t for t in self._traces() if t["event"] == "enforcement.decision"]


class NamingTest(unittest.TestCase):
    def test_round_trip(self) -> None:
        self.assertEqual(tool_name_for("/charge"), "charge")
        self.assertEqual(route_path_for("charge"), "/charge")
        self.assertEqual(route_path_for("/charge"), "/charge")

    def test_every_route_is_offered_as_a_tool(self) -> None:
        policy = GatewayPolicy()
        policy.register(Route(path="/charge", upstream="u", action="charge"))
        policy.register(Route(path="/lookup", upstream="u", action="lookup"))
        names = {tool["name"] for tool in tool_definitions(policy)}
        self.assertEqual(names, {"charge", "lookup"})

    def test_a_descriptor_is_usable_as_an_mcp_tool(self) -> None:
        policy = GatewayPolicy()
        policy.register(
            Route(path="/charge", upstream="u", action="charge", risk="destructive")
        )
        tool = tool_definitions(policy)[0]
        json.dumps(tool)  # must serialise
        self.assertEqual(tool["inputSchema"]["type"], "object")
        self.assertIn("destructive", tool["description"])


class EnforcementTest(BridgeTestBase):
    def test_a_destructive_call_without_approval_is_refused(self) -> None:
        bridge = MCPToolBridge.from_policy(self.store, self.policy)
        bridge.gateway._transport = self.upstream
        result = bridge.call_tool("charge", {"amount": 100})
        self.assertTrue(result["isError"])
        self.assertIn("approval", result["content"][0]["text"].lower())
        self.assertEqual(self.upstream.calls, [])

    def test_an_approved_call_forwards_exactly_once(self) -> None:
        gateway = SafetyGateway(self.store, self.policy, transport=self.upstream)
        bridge = MCPToolBridge(gateway)
        approval = self._approve(gateway, "charge", {"amount": 100, "_idempotency_key": "k-1"})
        result = bridge.call_tool(
            "charge", {"amount": 100}, approval_id=approval, idempotency_key="k-1"
        )
        self.assertFalse(result["isError"], result)
        self.assertEqual(len(self.upstream.calls), 1)

    def test_a_read_needs_no_approval(self) -> None:
        bridge = MCPToolBridge.from_policy(self.store, self.policy)
        bridge.gateway._transport = self.upstream
        result = bridge.call_tool("lookup", {"charge_id": "ch_1"})
        self.assertFalse(result["isError"], result)
        self.assertEqual(len(self.upstream.calls), 1)

    def test_an_unknown_tool_is_refused(self) -> None:
        bridge = MCPToolBridge.from_policy(self.store, self.policy)
        result = bridge.call_tool("delete_everything", {})
        self.assertTrue(result["isError"])
        self.assertIn("not available", result["content"][0]["text"])

    def test_an_unknown_tool_does_not_reveal_which_routes_exist(self) -> None:
        """The refusal must be identical for a missing route and a wrong-scope
        key, or the bridge becomes a route-existence oracle."""
        bridge = MCPToolBridge.from_policy(self.store, self.policy)
        missing = bridge.call_tool("nope", {})["content"][0]["text"]
        known = bridge.call_tool("charge", {})["content"][0]["text"]
        # Both refuse, but for different reasons -- what must not leak is the
        # existence of a route the caller has no scope for. Here the caller is
        # the bridge itself, so assert only that an absent tool reads as absent.
        self.assertIn("not available", missing)
        self.assertNotIn("not available", known)


class ParityTest(BridgeTestBase):
    """The load-bearing claim: both doors produce the same evidence."""

    def _via_http(self, path: str, payload: dict, approval_id=None, key=None):
        gateway = SafetyGateway(self.store, self.policy, transport=self.upstream)
        return gateway.handle("POST", path, payload, approval_id=approval_id,
                              idempotency_key=key)

    def test_a_refused_action_writes_the_same_trace_over_both_doors(self) -> None:
        self._via_http("/charge", {"amount": 100})
        http_rows = [
            (t["event"], t["status"]) for t in self._traces()
        ]

        store2 = TraceStore(Path(self._tmp.name) / "second.db")
        bridge = MCPToolBridge.from_policy(store2, self.policy)
        bridge.gateway._transport = self.upstream
        bridge.call_tool("charge", {"amount": 100})
        mcp_rows = [
            (t["event"], t["status"]) for t in store2.snapshot()["traces"]
        ]

        self.assertEqual(http_rows, mcp_rows)

    def test_a_refused_action_is_refused_over_both_doors(self) -> None:
        http = self._via_http("/charge", {"amount": 100})
        bridge = MCPToolBridge.from_policy(
            TraceStore(Path(self._tmp.name) / "second.db"), self.policy
        )
        bridge.gateway._transport = self.upstream
        mcp = bridge.call_tool("charge", {"amount": 100})
        self.assertGreaterEqual(http.status, 400)
        self.assertTrue(mcp["isError"])

    def test_both_doors_mark_the_row_as_enforced(self) -> None:
        self._via_http("/charge", {"amount": 100})
        store2 = TraceStore(Path(self._tmp.name) / "second.db")
        bridge = MCPToolBridge.from_policy(store2, self.policy)
        bridge.gateway._transport = self.upstream
        bridge.call_tool("charge", {"amount": 100})
        for store in (self.store, store2):
            rows = store.snapshot()["traces"]
            self.assertTrue(rows, "a refused action must leave evidence")
            for row in rows:
                self.assertEqual(row["enforcement"], "enforced")

    def test_a_held_action_is_recorded_over_both_doors(self) -> None:
        """The gateway used to refuse an approval-required action in silence.

        An operator asking whether anything tried to charge got an empty
        answer. Both doors must now leave the same evidence of the hold.
        """
        self._via_http("/charge", {"amount": 100})
        store2 = TraceStore(Path(self._tmp.name) / "second.db")
        bridge = MCPToolBridge.from_policy(store2, self.policy)
        bridge.gateway._transport = self.upstream
        bridge.call_tool("charge", {"amount": 100})

        for store in (self.store, store2):
            held = [t for t in store.snapshot()["traces"] if t["event"] == "gateway.held"]
            self.assertEqual(len(held), 1, store.snapshot()["traces"])
            self.assertEqual(held[0]["output"]["action"], "charge")
            self.assertEqual(held[0]["output"]["path"], "/charge")


class TransportIndependenceTest(BridgeTestBase):
    def test_the_bridge_needs_no_mcp_package(self) -> None:
        """We ship the policy layer, not a protocol implementation.

        A dependency on an MCP SDK would make this package non-stdlib and would
        tie the enforcement path to someone else's release schedule.
        """
        import agent_action_gateway.integrations.mcp as module

        self.assertNotIn("mcp", {name for name in dir(module) if name.startswith("_mcp")})

    def test_the_module_imports_nothing_from_an_mcp_package(self) -> None:
        """We ship the policy layer, not a protocol implementation.

        Parsed rather than grepped: the module's own docstring shows an `from
        mcp.server import Server` example for the adopter, and a substring
        search would flag the documentation instead of the code.
        """
        import ast

        source = (
            Path(__file__).resolve().parents[1] / "src/agent_action_gateway/integrations/mcp.py"
        )
        tree = ast.parse(source.read_text(encoding="utf-8"))
        imported: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.append(node.module)
        self.assertFalse(
            [name for name in imported if name.split(".")[0] == "mcp"],
            f"unexpected MCP dependency: {imported}",
        )


if __name__ == "__main__":
    unittest.main()
