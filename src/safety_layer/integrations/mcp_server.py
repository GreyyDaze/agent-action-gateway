"""A minimal, stdlib-only MCP server over the guarded tool bridge.

MCP is JSON-RPC 2.0. The stdio transport is newline-delimited JSON: one request
per line, one response per line on stdout. This module is deliberately small —
it is a transport, not policy. Every ``tools/call`` is dispatched through
:class:`~safety_layer.integrations.mcp.MCPToolBridge`, so an MCP client cannot skip
a rule the HTTP door enforces.

No MCP SDK is needed, keeping the package stdlib-only. Adopters who already use
an MCP library can register the same bridge's tools with it instead.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Iterable, Mapping
from typing import Any, TextIO

from safety_layer.integrations.mcp import MCPToolBridge, tool_definitions


class MCPServer:
    """JSON-RPC dispatcher. Transport-agnostic: feed it lines, get lines back."""

    def __init__(self, bridge: MCPToolBridge) -> None:
        self.bridge = bridge
        self.tools = {t["name"]: t for t in tool_definitions(bridge.gateway.policy)}

    def handle(self, message: Mapping[str, Any]) -> dict[str, Any] | None:
        """Handle one JSON-RPC message. Returns None for notifications."""
        method = message.get("method")
        request_id = message.get("id")
        params = message.get("params") or {}

        if method == "initialize":
            return self._result(request_id, {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "safety", "version": "0.2.0"},
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

    def serve(self, lines: Iterable[str], out: TextIO | None = None) -> None:
        out = out or sys.stdout
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                out.write(json.dumps({
                    "jsonrpc": "2.0", "id": None,
                    "error": {"code": -32700, "message": "parse error"},
                }) + "\n")
                out.flush()
                continue
            response = self.handle(message)
            if response is not None:
                out.write(json.dumps(response) + "\n")
                out.flush()


def serve_stdio(bridge: MCPToolBridge) -> None:
    """Run the newline-delimited stdio transport until stdin closes."""
    MCPServer(bridge).serve(sys.stdin)


__all__ = ["MCPServer", "serve_stdio"]
