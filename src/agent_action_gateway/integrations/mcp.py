"""MCP tools for a route table, served through the gateway's checks.

This is the route-based MCP surface: it turns a `GatewayPolicy` into MCP tool
definitions and sends every `call_tool` to `SafetyGateway.handle`, the same
method the HTTP gateway uses.

That means it checks what the gateway checks (environment, and approval in the
default mode) and nothing more. It does **not** apply limits, once-only receipts
or stop-and-ask. To put the full checks (`engine.enforce`) between an agent and
its MCP servers, use the MCP proxy in `mcp_proxy.py`.

It is deliberately **not** a transport and **not** an MCP implementation.

Transport is the adopter's MCP library's job. Pair this with it:

    from agent_action_gateway.integrations.mcp import tools_for_policy, MCPToolBridge
    from mcp.server import Server

    bridge = MCPToolBridge(policy, store)
    server = Server("safety")
    # register tools_for_policy(policy) with the SDK; dispatch via bridge
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from agent_action_gateway.integrations.gateway import GatewayPolicy, SafetyGateway
from agent_action_gateway.storage.traces import TraceStore

#: MCP declares tools with JSON Schema for their arguments, the same shape
#: OpenAPI uses. Routes here carry no schema of their own, so the arguments are
#: described as an open object and the enforcement layer -- not the schema --
#: is what actually guards the call.
OPEN_OBJECT: dict[str, Any] = {"type": "object", "additionalProperties": True}


def tool_name_for(route_path: str) -> str:
    """`/deploy` -> `deploy`. Leading slash stripped; a path without one is
    returned unchanged."""
    return route_path.lstrip("/") or route_path


def route_path_for(tool_name: str) -> str:
    """`deploy` -> `/deploy`. An already-slashed name is returned unchanged."""
    return tool_name if tool_name.startswith("/") else f"/{tool_name}"


def tool_definitions(policy: GatewayPolicy) -> list[dict[str, Any]]:
    """MCP-shaped tool descriptors for every registered route.

    Risk and method are included in the description because an agent choosing
    between tools benefits from knowing which one is irreversible. Describing a
    tool as destructive does not enforce anything -- the pipeline does -- but
    an agent that knows may not attempt it speculatively.
    """
    tools: list[dict[str, Any]] = []
    for route in policy.routes.values():
        tools.append(
            {
                "name": tool_name_for(route.path),
                "description": (
                    f"{route.action} via {route.upstream}. "
                    f"Risk: {route.risk}. Irreversible actions are held for approval."
                ),
                "inputSchema": dict(OPEN_OBJECT),
                # The gateway knows each route's risk, so it can say so. A client
                # that trusts this server may use the read-only hint.
                "annotations": {
                    "readOnlyHint": route.risk == "read",
                    "destructiveHint": route.risk == "destructive",
                },
            }
        )
    return tools


class MCPToolBridge:
    """Route MCP tool calls through the shared enforcement pipeline.

    A single instance owns one `SafetyGateway`, so approval consumption,
    receipt writing and tracing are the same objects the HTTP path uses.
    """

    def __init__(self, gateway: SafetyGateway) -> None:
        self.gateway = gateway

    @classmethod
    def from_policy(
        cls, store: TraceStore, policy: GatewayPolicy
    ) -> MCPToolBridge:
        return cls(SafetyGateway(store, policy))

    def call_tool(
        self,
        name: str,
        arguments: Mapping[str, Any] | None = None,
        *,
        approval_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        """Invoke one tool and return an MCP-shaped result.

        The result shape follows MCP: `content` blocks plus `isError`. The
        refusal reason is preserved verbatim in the error block rather than
        flattened, because an agent that cannot tell "you need approval" from
        "this route does not exist" will retry the wrong thing.
        """
        route = self.gateway.policy.resolve(route_path_for(name))
        if route is None:
            # Refused identically to a wrong-scope key over HTTP, so the bridge
            # cannot be used to enumerate which routes exist.
            return _error_result(f"tool not available: {name}")

        result = self.gateway.handle(
            route.method,
            route.path,
            dict(arguments or {}),
            approval_id=approval_id,
            idempotency_key=idempotency_key,
        )
        if result.status >= 400:
            return _error_result(_describe(result.status, result.body))
        return {"content": [{"type": "text", "text": _render(result.body)}], "isError": False}


def _error_result(message: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": message}], "isError": True}


def _describe(status: int, body: Mapping[str, Any]) -> str:
    detail = body.get("error") if isinstance(body, Mapping) else None
    text = str(detail or f"gateway returned {status}")
    if isinstance(body, Mapping) and body.get("needs_approval"):
        text += " (an approval is required before this can proceed)"
    return text


def _render(body: Mapping[str, Any]) -> str:
    import json

    return json.dumps(body, sort_keys=True, default=str)


__all__ = [
    "MCPToolBridge",
    "OPEN_OBJECT",
    "route_path_for",
    "tool_definitions",
    "tool_name_for",
]
