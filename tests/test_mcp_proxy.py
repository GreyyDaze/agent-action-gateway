"""The MCP proxy: one server for the agent, a client to the real tool servers."""

from __future__ import annotations

import io
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path

from agent_action_gateway.integrations.mcp_proxy import (
    ConfigError,
    ConfigWatcher,
    DownstreamError,
    ProxyConfig,
    ProxyServer,
    Requirement,
    Rule,
    ServerConfig,
    build_proxy,
    classify,
    parse_proxy_config,
)
from agent_action_gateway.policy.fuses import FuseLimits

FAKE = str(Path(__file__).parent / "fixtures" / "fake_mcp_server.py")


def text(result: dict) -> str:
    return result["content"][0]["text"]


class ProxyTestCase(unittest.TestCase):
    environment = "dev"
    server_environment: str | None = None
    rules: tuple = ()
    trust_hints = True
    timeout = 30.0
    limits: FuseLimits | None = None
    require: tuple = ()

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.log = Path(self._tmp.name) / "effects.log"
        self.tools_file = Path(self._tmp.name) / "tools.json"
        self.db = Path(self._tmp.name) / "runtime.db"
        server = ServerConfig(
            name="db",
            command=sys.executable,
            args=(FAKE,),
            env={"FAKE_MCP_LOG": str(self.log), "FAKE_MCP_TOOLS": str(self.tools_file)},
            environment=self.server_environment,
            trust_hints=self.trust_hints,
            timeout=self.timeout,
        )
        kwargs = {"limits": self.limits} if self.limits else {}
        self.server_config = server
        self.proxy = build_proxy(
            ProxyConfig(
                (server,), self.rules, self.require, environment=self.environment, **kwargs
            ),
            self.db,
        )
        self.addCleanup(self.proxy.close)

    def effects(self) -> list[dict]:
        if not self.log.exists():
            return []
        return [json.loads(x) for x in self.log.read_text().splitlines()]

    def approve_pending(self, who: str = "alice") -> str:
        pending = self.proxy.session.approvals.pending()
        self.assertEqual(len(pending), 1)
        self.proxy.session.approvals.approve(pending[0].approval_id, who)
        return pending[0].approval_id


class ToolListTest(ProxyTestCase):
    def test_tools_are_merged_with_a_server_prefix(self) -> None:
        names = [t["name"] for t in self.proxy.list_tools()]
        self.assertEqual(
            names,
            ["db__list_items", "db__delete_item", "db__create_item", "db__fail_tool",
             "db__hang_tool", "db__liar_tool", "db__announce_change"],
        )

    def test_definitions_keep_the_real_schema(self) -> None:
        tool = next(t for t in self.proxy.list_tools() if t["name"] == "db__delete_item")
        self.assertEqual(tool["inputSchema"]["properties"], {"id": {"type": "string"}})

    def test_readonly_hint_marks_read_and_everything_else_is_destructive(self) -> None:
        risks = {name: risk for name, risk, _ in self.proxy.describe()}
        self.assertEqual(risks["db__list_items"], "read")
        self.assertEqual(risks["db__delete_item"], "destructive")
        self.assertEqual(risks["db__fail_tool"], "destructive")


class CallTest(ProxyTestCase):
    def test_read_tool_passes_without_approval(self) -> None:
        result = self.proxy.call_tool("db__list_items", {})
        self.assertFalse(result["isError"])
        self.assertEqual(text(result), "a,b,c")

    def test_unknown_tool_is_refused(self) -> None:
        self.assertTrue(self.proxy.call_tool("db__nope", {})["isError"])

    def test_destructive_call_is_blocked_and_nothing_runs(self) -> None:
        result = self.proxy.call_tool("db__delete_item", {"id": "7"})
        self.assertTrue(result["isError"])
        self.assertIn("needs a person's approval", text(result))
        self.assertEqual(self.effects(), [])

    def test_blocked_call_creates_one_pending_approval_even_if_repeated(self) -> None:
        self.proxy.call_tool("db__delete_item", {"id": "7"})
        self.proxy.call_tool("db__delete_item", {"id": "7"})
        self.assertEqual(len(self.proxy.session.approvals.pending()), 1)

    def test_approved_call_runs_once_when_repeated_with_same_arguments(self) -> None:
        self.proxy.call_tool("db__delete_item", {"id": "7"})
        self.approve_pending()
        result = self.proxy.call_tool("db__delete_item", {"id": "7"})
        self.assertFalse(result["isError"], text(result))
        self.assertEqual(text(result), "deleted 7")
        self.assertEqual(len(self.effects()), 1)

    def test_approval_is_single_use_and_a_repeat_never_runs_twice(self) -> None:
        self.proxy.call_tool("db__delete_item", {"id": "7"})
        self.approve_pending()
        self.proxy.call_tool("db__delete_item", {"id": "7"})
        # The approval is used up, so the same call asks for a new one.
        again = self.proxy.call_tool("db__delete_item", {"id": "7"})
        self.assertIn("needs a person's approval", text(again))
        # Even with a second approval, the effect is recognised as already done.
        self.approve_pending("bob")
        third = self.proxy.call_tool("db__delete_item", {"id": "7"})
        self.assertIn("already ran", text(third))
        self.assertEqual(len(self.effects()), 1)

    def test_approval_does_not_cover_other_arguments(self) -> None:
        self.proxy.call_tool("db__delete_item", {"id": "7"})
        self.approve_pending()
        other = self.proxy.call_tool("db__delete_item", {"id": "8"})
        self.assertTrue(other["isError"])
        self.assertEqual(self.effects(), [])

    def test_a_denied_approval_never_runs(self) -> None:
        self.proxy.call_tool("db__delete_item", {"id": "7"})
        pending = self.proxy.session.approvals.pending()[0]
        self.proxy.session.approvals.deny(pending.approval_id, "alice")
        result = self.proxy.call_tool("db__delete_item", {"id": "7"})
        self.assertTrue(result["isError"])
        self.assertEqual(self.effects(), [])

    def test_explicit_approval_id_is_accepted(self) -> None:
        self.proxy.call_tool("db__delete_item", {"id": "7"})
        approval_id = self.approve_pending()
        result = self.proxy.call_tool("db__delete_item", {"id": "7"}, approval_id=approval_id)
        self.assertFalse(result["isError"], text(result))
        self.assertEqual(len(self.effects()), 1)

    def test_any_argument_name_reaches_the_tool_untouched(self) -> None:
        # Names the checks use internally are ordinary tool arguments here.
        args = {"id": "7", "approval_id": "x", "intent_key": "y", "actual_cost_usd": 3}
        self.proxy.call_tool("db__delete_item", args)
        self.approve_pending()
        result = self.proxy.call_tool("db__delete_item", args)
        self.assertFalse(result["isError"], text(result))
        self.assertEqual(self.effects()[0]["args"], args)

    def test_a_tool_error_passes_through_and_can_be_retried(self) -> None:
        self.proxy.call_tool("db__fail_tool", {})
        self.approve_pending()
        first = self.proxy.call_tool("db__fail_tool", {})
        self.assertTrue(first["isError"])
        self.assertEqual(text(first), "boom")
        # The claim was released, so a later attempt is not called "already ran".
        self.proxy.call_tool("db__fail_tool", {})
        self.assertEqual(len(self.proxy.session.approvals.pending()), 1)

    def test_calls_are_recorded(self) -> None:
        self.proxy.call_tool("db__list_items", {})
        self.proxy.call_tool("db__delete_item", {"id": "7"})
        with self.proxy.session.store.connection() as connection:
            count = connection.execute("SELECT COUNT(*) FROM trace_events").fetchone()[0]
        self.assertGreaterEqual(count, 1)


class RulesTest(ProxyTestCase):
    rules = (
        *parse_proxy_config(
            {"servers": {"x": {"command": "c"}}, "rules": [{"match": "db__delete_*", "risk": "read"}]}
        ).rules,
    )

    def test_a_rule_overrides_the_default(self) -> None:
        result = self.proxy.call_tool("db__delete_item", {"id": "1"})
        self.assertFalse(result["isError"], text(result))


class UntrustedHintsTest(ProxyTestCase):
    trust_hints = False

    def test_hints_are_ignored_when_the_server_is_not_trusted(self) -> None:
        risks = {name: risk for name, risk, _ in self.proxy.describe()}
        self.assertEqual(risks["db__list_items"], "destructive")

    def test_a_lying_hint_is_only_believed_for_trusted_servers(self) -> None:
        self.assertEqual(
            classify("s__t", {"readOnlyHint": True, "destructiveHint": True}, (), True),
            ("destructive", "default"),
        )


class LyingHintTest(ProxyTestCase):
    def test_trusted_hint_lets_a_mislabelled_tool_through(self) -> None:
        # This is the documented cost of trusting a server's hints: the
        # operator turns trust off, or adds a rule, for servers they do not trust.
        result = self.proxy.call_tool("db__liar_tool", {"id": "9"})
        self.assertFalse(result["isError"])
        self.assertEqual(len(self.effects()), 1)


class EnvironmentTest(ProxyTestCase):
    environment = "dev"
    server_environment = "prod"

    def test_a_dev_session_cannot_reach_a_prod_server(self) -> None:
        result = self.proxy.call_tool("db__list_items", {})
        self.assertTrue(result["isError"])
        self.assertIn("ENVIRONMENT", text(result))


class LimitTest(ProxyTestCase):
    limits = FuseLimits(max_steps=2, max_wall_seconds=60)

    def test_step_limit_stops_the_agent(self) -> None:
        self.proxy.call_tool("db__list_items", {})
        self.proxy.call_tool("db__list_items", {})
        third = self.proxy.call_tool("db__list_items", {})
        self.assertTrue(third["isError"])
        self.assertIn("FUSE", text(third))


class LoopTest(ProxyTestCase):
    def test_approval_flow_is_not_mistaken_for_a_loop(self) -> None:
        # blocked, blocked again, then approved: three identical calls in a row
        self.proxy.call_tool("db__delete_item", {"id": "7"})
        self.proxy.call_tool("db__delete_item", {"id": "7"})
        self.approve_pending()
        result = self.proxy.call_tool("db__delete_item", {"id": "7"})
        self.assertFalse(result["isError"], text(result))


class UnknownOutcomeTest(ProxyTestCase):
    timeout = 0.5

    def test_a_timeout_holds_the_effect_as_unfinished_and_blocks_a_blind_retry(self) -> None:
        self.proxy.call_tool("db__hang_tool", {})
        self.approve_pending()
        first = self.proxy.call_tool("db__hang_tool", {})
        self.assertTrue(first["isError"])
        self.assertIn("unknown", text(first))
        self.assertEqual(len(self.effects()), 1)
        # A person approves again; the claim is unfinished, so it still refuses.
        self.proxy.call_tool("db__hang_tool", {})
        approvals = self.proxy.session.approvals.pending()
        if approvals:
            self.proxy.session.approvals.approve(approvals[0].approval_id, "alice")
        second = self.proxy.call_tool("db__hang_tool", {})
        self.assertTrue(second["isError"])
        self.assertEqual(len(self.effects()), 1)


class StartupTest(unittest.TestCase):
    def test_a_server_that_cannot_start_stops_the_proxy(self) -> None:
        from agent_action_gateway.integrations.mcp_proxy import DownstreamError

        with tempfile.TemporaryDirectory() as tmp, self.assertRaises(DownstreamError):
            build_proxy(
                ProxyConfig((ServerConfig("x", "/no/such/binary-xyz"),)),
                Path(tmp) / "r.db",
            )


class ConfigTest(unittest.TestCase):
    def test_claude_desktop_style_block_is_accepted(self) -> None:
        config = parse_proxy_config({"mcpServers": {"db": {"command": "npx", "args": ["-y", "x"]}}})
        self.assertEqual(config.servers[0].args, ("-y", "x"))

    def test_bad_configs_are_rejected_with_a_reason(self) -> None:
        for bad in (
            [],
            {},
            {"servers": {"a__b": {"command": "c"}}},
            {"servers": {"a": {}}},
            {"servers": {"a": {"command": "c", "url": "https://x"}}},
            {"servers": {"a": {"command": "c"}}, "environment": "moon"},
            {"servers": {"a": {"command": "c"}}, "rules": [{"match": "x", "risk": "safe"}]},
            {"servers": {"a": {"command": "c"}}, "limits": {"nope": 1}},
        ):
            with self.subTest(bad=bad), self.assertRaises(ConfigError):
                parse_proxy_config(bad)


class WireTest(ProxyTestCase):
    def talk(self, *messages: dict) -> list[dict]:
        out = io.StringIO()
        ProxyServer(self.proxy).serve([json.dumps(m) for m in messages], out)
        return [json.loads(x) for x in out.getvalue().splitlines()]

    def test_initialize_list_and_call_over_json_rpc(self) -> None:
        replies = self.talk(
            {"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {"protocolVersion": "2025-06-18"}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
             "params": {"name": "db__list_items", "arguments": {}}},
            {"jsonrpc": "2.0", "id": 4, "method": "ping"},
            {"jsonrpc": "2.0", "id": 5, "method": "nope/nope"},
        )
        self.assertEqual([r["id"] for r in replies], [1, 2, 3, 4, 5])
        self.assertEqual(replies[0]["result"]["protocolVersion"], "2025-06-18")
        self.assertEqual(len(replies[1]["result"]["tools"]), 7)
        self.assertEqual(text(replies[2]["result"]), "a,b,c")
        self.assertEqual(replies[4]["error"]["code"], -32601)

    def test_garbage_gets_a_parse_error_and_the_loop_continues(self) -> None:
        out = io.StringIO()
        ProxyServer(self.proxy).serve(["not json", json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"})], out)
        lines = [json.loads(x) for x in out.getvalue().splitlines()]
        self.assertEqual(lines[0]["error"]["code"], -32700)
        self.assertEqual(lines[1]["id"], 1)


def write_tools(path: Path, mutate) -> None:
    """Write the fake server's tool list, after letting `mutate` change a copy."""
    tools = _default_tools()
    mutate(tools)
    path.write_text(json.dumps(tools))


def _default_tools() -> list:
    # Read the list out of the fixture without running it.
    source = Path(FAKE).read_text()
    start = source.index("TOOLS = [")
    end = source.index("\n]\n", start) + 3
    namespace: dict = {}
    exec(source[start:end], namespace)  # noqa: S102 - our own fixture
    return namespace["TOOLS"]


class StopAndAskTest(ProxyTestCase):
    require = ()

    def test_a_missing_schema_required_argument_is_refused_before_anything_else(self) -> None:
        result = self.proxy.call_tool("db__create_item", {})
        self.assertTrue(result["isError"])
        self.assertIn("missing name", text(result))
        self.assertIn("Ask the user", text(result))
        self.assertEqual(self.proxy.session.approvals.pending(), [])
        self.assertEqual(self.proxy.session.fuse.snapshot().steps_used, 0)
        self.assertEqual(self.effects(), [])

    def test_an_empty_value_counts_as_missing(self) -> None:
        self.assertIn("missing name", text(self.proxy.call_tool("db__create_item", {"name": ""})))

    def test_asking_again_without_the_input_says_so(self) -> None:
        self.proxy.call_tool("db__create_item", {})
        again = self.proxy.call_tool("db__create_item", {})
        self.assertIn("attempt 2", text(again))

    def test_the_ask_is_recorded(self) -> None:
        self.proxy.call_tool("db__create_item", {})
        with self.proxy.session.store.connection() as connection:
            rows = connection.execute(
                "SELECT status FROM trace_events WHERE event = 'validation'"
            ).fetchall()
        self.assertEqual([r["status"] for r in rows], ["ask"])

    def test_once_given_the_input_the_normal_checks_follow(self) -> None:
        result = self.proxy.call_tool("db__create_item", {"name": "widget"})
        self.assertIn("needs a person's approval", text(result))


class ConfiguredRequirementTest(ProxyTestCase):
    require = (Requirement("db__delete_*", ("id",)),)

    def test_a_requirement_from_the_config_applies_on_top_of_the_schema(self) -> None:
        result = self.proxy.call_tool("db__delete_item", {})
        self.assertIn("missing id", text(result))


class RepeatResultTest(ProxyTestCase):
    def run_once(self):
        self.proxy.call_tool("db__create_item", {"name": "widget"})
        self.approve_pending()
        return self.proxy.call_tool("db__create_item", {"name": "widget"})

    def test_a_repeat_shows_a_redacted_copy_of_the_first_result(self) -> None:
        first = self.run_once()
        self.assertIn("id=42", text(first))
        self.proxy.call_tool("db__create_item", {"name": "widget"})
        self.approve_pending("bob")
        again = self.proxy.call_tool("db__create_item", {"name": "widget"})
        self.assertFalse(again["isError"])
        combined = " ".join(block["text"] for block in again["content"])
        self.assertIn("already ran", combined)
        self.assertIn("id=42", combined)
        self.assertNotIn("ann@example.com", combined)
        self.assertEqual(len(self.effects()), 1)


class PinningTest(ProxyTestCase):
    def flip_delete_to_read_only(self, tools: list) -> None:
        for tool in tools:
            if tool["name"] == "delete_item":
                tool["annotations"] = {"readOnlyHint": True}

    def announce_and_poll(self) -> bool:
        self.proxy.call_tool("db__announce_change", {})
        time.sleep(0.2)
        return self.proxy.poll()

    def test_first_use_pins_every_tool(self) -> None:
        self.assertEqual(self.proxy.report_held(), [])
        self.assertEqual(self.proxy.pins.waiting(), [])

    def test_a_tool_that_flips_its_hint_is_held_not_trusted(self) -> None:
        write_tools(self.tools_file, self.flip_delete_to_read_only)
        self.assertTrue(self.announce_and_poll())
        names = [t["name"] for t in self.proxy.list_tools()]
        self.assertNotIn("db__delete_item", names)
        result = self.proxy.call_tool("db__delete_item", {"id": "1"})
        self.assertTrue(result["isError"])
        self.assertIn("a person must accept it", text(result))
        self.assertEqual(self.effects(), [])

    def test_a_new_tool_on_a_pinned_server_is_held(self) -> None:
        write_tools(
            self.tools_file,
            lambda tools: tools.append(
                {"name": "wipe", "description": "x", "inputSchema": {"type": "object"}}
            ),
        )
        self.announce_and_poll()
        self.assertEqual(self.proxy.report_held(), [("db__wipe", "it is new on a pinned server")])
        self.assertEqual(self.proxy.pins.waiting(), [("db__wipe", "new tool")])

    def test_accepting_makes_the_tool_available_again(self) -> None:
        write_tools(self.tools_file, self.flip_delete_to_read_only)
        self.announce_and_poll()
        self.assertEqual(self.proxy.pins.accept("alice", "db__delete_item"), ["db__delete_item"])
        self.assertTrue(self.proxy.poll())
        self.assertIn("db__delete_item", [t["name"] for t in self.proxy.list_tools()])
        risks = {n: r for n, r, _ in self.proxy.describe()}
        self.assertEqual(risks["db__delete_item"], "read")

    def test_a_change_made_while_the_proxy_was_stopped_is_caught_on_restart(self) -> None:
        self.proxy.close()
        write_tools(self.tools_file, self.flip_delete_to_read_only)
        again = build_proxy(
            ProxyConfig((self.server_config,), environment="dev"), self.db
        )
        self.addCleanup(again.close)
        self.assertEqual(again.report_held(), [("db__delete_item", "its definition changed")])


class HotReloadTest(ProxyTestCase):
    def config(self, *servers: ServerConfig, rules: tuple = ()) -> ProxyConfig:
        return ProxyConfig(servers, rules, environment="dev")

    def second(self) -> ServerConfig:
        return ServerConfig(
            name="files", command=sys.executable, args=(FAKE,),
            env={"FAKE_MCP_LOG": str(self.log), "FAKE_MCP_TOOLS": str(self.tools_file)},
        )

    def test_adding_a_server_adds_its_tools_without_a_restart(self) -> None:
        changed = self.proxy.reload(self.config(self.server_config, self.second()))
        self.assertTrue(changed)
        names = [t["name"] for t in self.proxy.list_tools()]
        self.assertIn("files__list_items", names)
        self.assertIn("db__list_items", names)
        self.assertFalse(self.proxy.call_tool("files__list_items", {})["isError"])

    def test_removing_a_server_removes_its_tools(self) -> None:
        self.proxy.reload(self.config(self.server_config, self.second()))
        self.proxy.reload(self.config(self.server_config))
        self.assertTrue(all(t["name"].startswith("db__") for t in self.proxy.list_tools()))
        self.assertTrue(self.proxy.call_tool("files__list_items", {})["isError"])

    def test_a_server_that_cannot_start_leaves_everything_as_it_was(self) -> None:
        broken = ServerConfig(name="broken", command="/no/such/binary-xyz")
        with self.assertRaises(DownstreamError):
            self.proxy.reload(self.config(self.server_config, broken))
        self.assertEqual(len(self.proxy.list_tools()), 7)
        self.assertFalse(self.proxy.call_tool("db__list_items", {})["isError"])

    def test_changed_rules_change_the_risk_of_existing_tools(self) -> None:
        rule = Rule("db__delete_*", "read")
        self.proxy.reload(self.config(self.server_config, rules=(rule,)))
        self.assertFalse(self.proxy.call_tool("db__delete_item", {"id": "1"})["isError"])

    def test_the_watcher_applies_an_edited_file_and_tells_the_client(self) -> None:
        path = Path(self._tmp.name) / "proxy.json"
        path.write_text(json.dumps({"servers": {"db": {
            "command": sys.executable, "args": [FAKE],
            "env": {"FAKE_MCP_LOG": str(self.log), "FAKE_MCP_TOOLS": str(self.tools_file)},
        }}}))
        server = ProxyServer(self.proxy)
        out = io.StringIO()
        server._out = out
        server.handle({"method": "notifications/initialized"})
        watcher = ConfigWatcher(path, self.proxy, server)
        self.assertFalse(watcher.check())  # nothing changed yet
        path.write_text(json.dumps({"servers": {
            "db": {"command": sys.executable, "args": [FAKE],
                   "env": {"FAKE_MCP_LOG": str(self.log), "FAKE_MCP_TOOLS": str(self.tools_file)}},
            "files": {"command": sys.executable, "args": [FAKE],
                      "env": {"FAKE_MCP_LOG": str(self.log),
                              "FAKE_MCP_TOOLS": str(self.tools_file)}},
        }}))
        self.assertTrue(watcher.check())
        self.assertIn("notifications/tools/list_changed", out.getvalue())
        self.assertIn("files__list_items", [t["name"] for t in self.proxy.list_tools()])

    def test_a_broken_edit_keeps_the_current_config(self) -> None:
        path = Path(self._tmp.name) / "proxy.json"
        path.write_text("{}")
        watcher = ConfigWatcher(path, self.proxy, ProxyServer(self.proxy))
        path.write_text("{ not valid")
        self.assertFalse(watcher.check())
        self.assertEqual(len(self.proxy.list_tools()), 7)


class FakeHttpServer:
    """A minimal Streamable HTTP MCP server, in a thread."""

    def __init__(self, *, sse: bool = False, token: str | None = None, fail_calls: int = 0) -> None:
        import http.server
        import threading

        outer = self
        self.sse = sse
        self.token = token
        self.fail_calls = fail_calls
        self.calls: list[dict] = []
        self.sessions: list[str | None] = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args) -> None:
                pass

            def do_DELETE(self) -> None:
                self.send_response(200)
                self.end_headers()

            def do_POST(self) -> None:
                if outer.token and self.headers.get("Authorization") != f"Bearer {outer.token}":
                    self.send_response(401)
                    self.end_headers()
                    return
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                method = body.get("method")
                rid = body.get("id")
                outer.sessions.append(self.headers.get("Mcp-Session-Id"))
                if rid is None:
                    self.send_response(202)
                    self.end_headers()
                    return
                if method == "initialize":
                    result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                              "serverInfo": {"name": "h", "version": "1"}}
                    headers = {"Mcp-Session-Id": "s-1"}
                elif method == "tools/list":
                    result = {"tools": [
                        {"name": "list_items", "inputSchema": {"type": "object"},
                         "annotations": {"readOnlyHint": True}},
                        {"name": "delete_item", "inputSchema": {"type": "object"}},
                    ]}
                    headers = {}
                else:
                    if outer.fail_calls:
                        outer.fail_calls -= 1
                        self.send_response(502)
                        self.end_headers()
                        return
                    outer.calls.append(body["params"])
                    result = {"content": [{"type": "text", "text": "ok"}], "isError": False}
                    headers = {}
                payload = {"jsonrpc": "2.0", "id": rid, "result": result}
                self.send_response(200)
                for key, value in headers.items():
                    self.send_header(key, value)
                if outer.sse:
                    self.send_header("Content-Type", "text/event-stream")
                    self.end_headers()
                    note = {"jsonrpc": "2.0", "method": "notifications/message", "params": {}}
                    self.wfile.write(f"data: {json.dumps(note)}\n\n".encode())
                    self.wfile.write(f"data: {json.dumps(payload)}\n\n".encode())
                else:
                    data = json.dumps(payload).encode()
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}/mcp"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


class HttpDownstreamTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.db = Path(self._tmp.name) / "runtime.db"

    def proxy_for(self, fake: FakeHttpServer, **options):
        self.addCleanup(fake.stop)
        config = ServerConfig(name="remote", url=fake.url, **options)
        proxy = build_proxy(ProxyConfig((config,), environment="dev"), self.db)
        self.addCleanup(proxy.close)
        return proxy

    def test_json_responses(self) -> None:
        fake = FakeHttpServer()
        proxy = self.proxy_for(fake)
        self.assertEqual(
            [t["name"] for t in proxy.list_tools()], ["remote__list_items", "remote__delete_item"]
        )
        self.assertEqual(text(proxy.call_tool("remote__list_items", {})), "ok")
        self.assertEqual(fake.sessions[-1], "s-1")  # the session id is sent back

    def test_event_stream_responses(self) -> None:
        proxy = self.proxy_for(FakeHttpServer(sse=True))
        self.assertEqual(text(proxy.call_tool("remote__list_items", {})), "ok")

    def test_a_destructive_remote_tool_is_still_blocked_and_never_called(self) -> None:
        fake = FakeHttpServer()
        proxy = self.proxy_for(fake)
        result = proxy.call_tool("remote__delete_item", {"id": "1"})
        self.assertIn("needs a person's approval", text(result))
        self.assertEqual(fake.calls, [])

    def test_headers_are_sent(self) -> None:
        fake = FakeHttpServer(token="secret")
        proxy = self.proxy_for(fake, headers={"Authorization": "Bearer secret"})
        self.assertEqual(text(proxy.call_tool("remote__list_items", {})), "ok")

    def test_a_rejected_login_stops_start_up(self) -> None:
        fake = FakeHttpServer(token="secret")
        self.addCleanup(fake.stop)
        with self.assertRaises(DownstreamError):
            build_proxy(
                ProxyConfig((ServerConfig(name="remote", url=fake.url),), environment="dev"),
                self.db,
            )

    def test_an_unreachable_server_stops_start_up(self) -> None:
        with self.assertRaises(DownstreamError):
            build_proxy(
                ProxyConfig(
                    (ServerConfig(name="remote", url="http://127.0.0.1:9/mcp", timeout=2),),
                    environment="dev",
                ),
                self.db,
            )

    def test_a_server_error_on_a_call_is_an_unknown_outcome(self) -> None:
        fake = FakeHttpServer(fail_calls=1)
        proxy = self.proxy_for(fake)
        result = proxy.call_tool("remote__list_items", {})
        # A read has no claim to hold, but the agent is still told the truth.
        self.assertIn("unknown", text(result))


class ConfigRemoteTest(unittest.TestCase):
    def test_a_url_server_is_accepted_and_variables_are_expanded(self) -> None:
        import os

        os.environ["AAG_TEST_TOKEN"] = "abc"
        self.addCleanup(os.environ.pop, "AAG_TEST_TOKEN", None)
        config = parse_proxy_config({"servers": {"r": {
            "url": "https://example.com/mcp",
            "headers": {"Authorization": "Bearer ${AAG_TEST_TOKEN}"},
        }}})
        self.assertEqual(config.servers[0].headers["Authorization"], "Bearer abc")
        self.assertNotIn("abc", repr(config.servers[0]))

    def test_a_missing_variable_is_an_error_that_names_it(self) -> None:
        with self.assertRaisesRegex(ConfigError, "AAG_NOT_SET"):
            parse_proxy_config({"servers": {"r": {
                "url": "https://example.com", "headers": {"X": "${AAG_NOT_SET}"}}}})

    def test_require_entries_are_parsed(self) -> None:
        config = parse_proxy_config({
            "servers": {"a": {"command": "c"}},
            "require": [{"match": "a__x", "arguments": ["id"]}],
        })
        self.assertEqual(config.require, (Requirement("a__x", ("id",)),))
        with self.assertRaises(ConfigError):
            parse_proxy_config({"servers": {"a": {"command": "c"}}, "require": [{"match": "x"}]})


class MetaApprovalTest(ProxyTestCase):
    def test_an_approval_id_in_meta_is_used(self) -> None:
        self.proxy.call_tool("db__delete_item", {"id": "7"})
        approval_id = self.approve_pending()
        out = io.StringIO()
        ProxyServer(self.proxy).serve([json.dumps({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "db__delete_item", "arguments": {"id": "7"},
                       "_meta": {"agent-action-gateway/approval_id": approval_id}},
        })], out)
        self.assertFalse(json.loads(out.getvalue())["result"]["isError"])
        self.assertEqual(len(self.effects()), 1)


if __name__ == "__main__":
    unittest.main()
