"""The MCP message handler behind the gateway's `/mcp` endpoint.

MCP is JSON-RPC 2.0. `MCPServer.handle` answers one message: `initialize`,
`tools/list` and `tools/call`. It holds no policy of its own. Every `tools/call`
goes through :class:`~agent_action_gateway.integrations.mcp.MCPToolBridge`, so
arriving over MCP skips no rule the HTTP routes enforce.

The MCP proxy points at this endpoint, so the proxy runs the full checks and the
gateway holds the key. No MCP SDK is needed, keeping the package stdlib-only.
"""

from __future__ import annotations

from collections.abc import Collection, Mapping
from typing import Any

from agent_action_gateway.integrations.mcp import (
    MCPToolBridge,
    route_path_for,
    tool_definitions,
)

#: Where an MCP client (the proxy) puts the idempotency key of the action it
#: forwards. It becomes the `Idempotency-Key` the gateway sends upstream. Keep
#: in step with `INTENT_META_KEY` in mcp_proxy.py.
INTENT_META_KEY = "agent-action-gateway/intent_key"


class MCPServer:
    """JSON-RPC dispatcher. Transport-agnostic: feed it lines, get lines back.

    `allowed_routes` limits the tools to those routes (a virtual key's scope). A
    tool outside it is refused exactly like one that does not exist.
    """

    def __init__(
        self, bridge: MCPToolBridge, allowed_routes: Collection[str] | None = None
    ) -> None:
        self.bridge = bridge
        self.tools = {
            t["name"]: t
            for t in tool_definitions(bridge.gateway.policy)
            if allowed_routes is None or route_path_for(t["name"]) in allowed_routes
        }

    def handle(self, message: Mapping[str, Any]) -> dict[str, Any] | None:
        """Handle one JSON-RPC message. Returns None for notifications."""
        method = message.get("method")
        request_id = message.get("id")
        params = message.get("params") or {}

        if method == "initialize":
            return self._result(request_id, {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "agent-action-gateway", "version": "0.2.0"},
            })
        if method == "notifications/initialized":
            return None
        if method == "tools/list":
            return self._result(request_id, {"tools": list(self.tools.values())})
        if method == "tools/call":
            name = str(params.get("name", ""))
            arguments = dict(params.get("arguments") or {})
            # These two are transport concerns, not tool inputs. The agent's tool
            # wrapper supplies them; pass them through to the bridge so an
            # approval bound to an idempotency key still verifies. They are
            # removed from the arguments the tool itself sees.
            idempotency_key = arguments.pop("_idempotency_key", None)
            approval_id = arguments.pop("_approval_id", None)
            meta = params.get("_meta") or {}
            if idempotency_key is None and isinstance(meta, Mapping):
                idempotency_key = meta.get(INTENT_META_KEY)
            if name not in self.tools:
                return self._result(request_id, {
                    "content": [{"type": "text", "text": f"tool not available: {name}"}],
                    "isError": True,
                })
            result = self.bridge.call_tool(
                name,
                arguments,
                approval_id=approval_id,
                idempotency_key=idempotency_key,
            )
            # MCP errors are reported in the result body, not as JSON-RPC errors,
            # so the agent sees the refusal reason and can request approval.
            return self._result(request_id, result)
        if request_id is None:
            return None
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": -32601, "message": f"method not found: {method}"},
        }

    @staticmethod
    def _result(request_id: Any, result: Any) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": request_id, "result": result}


__all__ = ["MCPServer"]
