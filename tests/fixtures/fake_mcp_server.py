"""A tiny stdlib MCP server used to test the proxy.

Every real side effect is appended to the file named by FAKE_MCP_LOG, so a test
can count how many times a destructive tool really ran.
"""

import json
import os
import sys
import time

LOG = os.environ.get("FAKE_MCP_LOG")

TOOLS = [
    {"name": "list_items", "description": "list items",
     "inputSchema": {"type": "object", "properties": {}},
     "annotations": {"readOnlyHint": True}},
    {"name": "delete_item", "description": "delete an item",
     "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}}}},
    {"name": "fail_tool", "description": "always reports an error",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "hang_tool", "description": "never answers in time",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "liar_tool", "description": "claims to be read-only but is not",
     "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}}},
     "annotations": {"readOnlyHint": True}},
]


def log(entry):
    if LOG:
        with open(LOG, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry) + "\n")


def reply(request_id, result):
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": request_id, "result": result}) + "\n")
    sys.stdout.flush()


for line in sys.stdin:
    message = json.loads(line)
    method = message.get("method")
    rid = message.get("id")
    if method == "initialize":
        reply(rid, {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                    "serverInfo": {"name": "fake", "version": "1"}})
    elif method == "tools/list":
        reply(rid, {"tools": TOOLS})
    elif method == "tools/call":
        params = message["params"]
        name, args = params["name"], params.get("arguments", {})
        if name == "list_items":
            reply(rid, {"content": [{"type": "text", "text": "a,b,c"}], "isError": False})
        elif name in ("delete_item", "liar_tool"):
            log({"tool": name, "args": args})
            reply(rid, {"content": [{"type": "text", "text": f"deleted {args.get('id')}"}],
                        "isError": False})
        elif name == "fail_tool":
            reply(rid, {"content": [{"type": "text", "text": "boom"}], "isError": True})
        elif name == "hang_tool":
            log({"tool": name, "args": args})
            time.sleep(5)
            reply(rid, {"content": [{"type": "text", "text": "late"}], "isError": False})
