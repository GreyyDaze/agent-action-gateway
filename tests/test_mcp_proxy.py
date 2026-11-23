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
    SignInError,
    build_proxy,
    classify,
    parse_proxy_config,
    sign_in,
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
             "db__hang_tool", "db__liar_tool", "db__crash_tool", "db__announce_change"],
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
        self.assertEqual(len(replies[1]["result"]["tools"]), 8)
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
        self.assertEqual(len(self.proxy.list_tools()), 8)
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
        self.assertEqual(len(self.proxy.list_tools()), 8)


class RestartTest(ProxyTestCase):
    def kill_server(self) -> None:
        process = self.proxy.downstreams["db"]._proc
        process.kill()
        process.wait()

    def test_a_dead_server_is_restarted_before_the_next_call(self) -> None:
        before = self.proxy.downstreams["db"]._proc.pid
        self.kill_server()
        result = self.proxy.call_tool("db__list_items", {})
        self.assertEqual(text(result), "a,b,c")
        self.assertNotEqual(self.proxy.downstreams["db"]._proc.pid, before)

    def test_a_crash_in_the_middle_of_a_destructive_call_is_held_and_the_server_returns(self) -> None:
        self.proxy.call_tool("db__crash_tool", {})
        self.approve_pending()
        crashed = self.proxy.call_tool("db__crash_tool", {})
        self.assertIn("unknown", text(crashed))
        # the proxy is still usable: the server is restarted for the next call
        self.assertEqual(text(self.proxy.call_tool("db__list_items", {})), "a,b,c")
        # the crashed attempt stays unfinished, so a second approval cannot repeat it
        self.proxy.call_tool("db__crash_tool", {})
        self.approve_pending("bob")
        again = self.proxy.call_tool("db__crash_tool", {})
        self.assertTrue(again["isError"])
        self.assertEqual(len(self.effects()), 1)

    def test_a_server_that_keeps_dying_is_not_restarted_forever(self) -> None:
        for n in range(3):
            self.kill_server()
            self.assertFalse(self.proxy.call_tool("db__list_items", {"n": n})["isError"])
        self.kill_server()
        result = self.proxy.call_tool("db__list_items", {"n": 99})
        self.assertTrue(result["isError"])
        self.assertIn("keeps stopping", text(result))

    def test_a_server_that_comes_back_different_is_checked_against_its_pins(self) -> None:
        self.kill_server()
        write_tools(
            self.tools_file,
            lambda tools: [
                t.update(annotations={"readOnlyHint": True}) for t in tools if t["name"] == "delete_item"
            ],
        )
        self.proxy.call_tool("db__list_items", {})
        self.assertEqual(self.proxy.report_held(), [("db__delete_item", "its definition changed")])


class FakeHttpServer:
    """A minimal Streamable HTTP MCP server, in a thread."""

    def __init__(
        self,
        *,
        sse: bool = False,
        token: str | None = None,
        fail_calls: int = 0,
        oauth: bool = False,
        stream: bool = False,
    ) -> None:
        import http.server
        import queue
        import threading

        outer = self
        self.sse = sse
        self.token = token
        self.fail_calls = fail_calls
        self.calls: list[dict] = []
        self.sessions: list[str | None] = []
        self.oauth = oauth
        self.issued = 0
        self.valid_token: str | None = None
        self.token_forms: list[dict] = []
        self.epoch = 1
        self.initializations = 0
        self.stream = stream
        self.refresh_token = "rt-1"
        self.token_lifetime = 3600
        self.codes: dict[str, dict] = {}
        self.events: queue.Queue = queue.Queue()
        self.stream_open = threading.Event()
        self.stopping = threading.Event()
        self.extra_tools: list[dict] = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args) -> None:
                pass

            def do_GET(self) -> None:
                import urllib.parse

                if self.path.startswith("/authorize"):
                    query = {k: v[0] for k, v in urllib.parse.parse_qs(
                        urllib.parse.urlparse(self.path).query).items()}
                    code = f"code-{len(outer.codes) + 1}"
                    outer.codes[code] = query
                    target = urllib.parse.urlparse(query["redirect_uri"])
                    back = urllib.parse.urlencode({"code": code, "state": query["state"]})
                    self.send_response(302)
                    self.send_header("Location", f"{query['redirect_uri']}?{back}")
                    self.end_headers()
                    del target
                    return
                if not outer.stream:
                    self.send_response(405)
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()
                outer.stream_open.set()
                try:
                    while not outer.stopping.is_set():
                        try:
                            item = outer.events.get(timeout=0.1)
                        except queue.Empty:
                            continue
                        self.wfile.write(f"data: {json.dumps(item)}\n\n".encode())
                        self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def do_DELETE(self) -> None:
                self.send_response(200)
                self.end_headers()

            def do_POST(self) -> None:
                import urllib.parse

                if self.path.endswith("/token"):
                    raw = self.rfile.read(int(self.headers["Content-Length"])).decode()
                    form = {k: v[0] for k, v in urllib.parse.parse_qs(raw).items()}
                    outer.token_forms.append(form)
                    grant = form.get("grant_type")
                    reply: dict = {}
                    if grant == "authorization_code":
                        import base64
                        import hashlib

                        saved = outer.codes.get(form.get("code", ""))
                        digest = base64.urlsafe_b64encode(
                            hashlib.sha256(form.get("code_verifier", "").encode()).digest()
                        ).rstrip(b"=").decode()
                        if (
                            saved is None
                            or saved["code_challenge"] != digest
                            or saved["redirect_uri"] != form.get("redirect_uri")
                        ):
                            self.send_response(400)
                            self.end_headers()
                            return
                        reply["refresh_token"] = outer.refresh_token
                    elif grant == "refresh_token" and form.get("refresh_token") != outer.refresh_token:
                        self.send_response(400)
                        self.end_headers()
                        return
                    outer.issued += 1
                    outer.valid_token = f"tok-{outer.issued}"
                    data = json.dumps(
                        {"access_token": outer.valid_token, "expires_in": outer.token_lifetime,
                         **reply}
                    ).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                    return
                if outer.token and self.headers.get("Authorization") != f"Bearer {outer.token}":
                    self.send_response(401)
                    self.end_headers()
                    return
                if outer.oauth and self.headers.get("Authorization") != f"Bearer {outer.valid_token}":
                    self.send_response(401)
                    self.end_headers()
                    return
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                if (
                    body.get("method") != "initialize"
                    and self.headers.get("Mcp-Session-Id") not in (None, f"s-{outer.epoch}")
                ):
                    self.send_response(404)
                    self.end_headers()
                    return
                method = body.get("method")
                rid = body.get("id")
                outer.sessions.append(self.headers.get("Mcp-Session-Id"))
                if rid is None:
                    self.send_response(202)
                    self.end_headers()
                    return
                if method == "initialize":
                    outer.initializations += 1
                    result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                              "serverInfo": {"name": "h", "version": "1"}}
                    headers = {"Mcp-Session-Id": f"s-{outer.epoch}"}
                elif method == "tools/list":
                    result = {"tools": [
                        {"name": "list_items", "inputSchema": {"type": "object"},
                         "annotations": {"readOnlyHint": True}},
                        {"name": "delete_item", "inputSchema": {"type": "object"}},
                        *outer.extra_tools,
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

    def push_list_changed(self) -> None:
        self.events.put({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"})

    def expire_session(self) -> None:
        self.epoch += 1

    def revoke_token(self) -> None:
        self.valid_token = "revoked"

    def stop(self) -> None:
        self.stopping.set()
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

    def test_an_expired_session_is_replaced_and_the_call_goes_through(self) -> None:
        fake = FakeHttpServer()
        proxy = self.proxy_for(fake)
        self.assertEqual(fake.initializations, 1)
        fake.expire_session()
        self.assertEqual(text(proxy.call_tool("remote__list_items", {})), "ok")
        self.assertEqual(fake.initializations, 2)
        self.assertEqual(fake.sessions[-1], "s-2")

    def test_a_destructive_call_after_session_expiry_runs_exactly_once(self) -> None:
        fake = FakeHttpServer()
        proxy = self.proxy_for(fake)
        proxy.call_tool("remote__delete_item", {"id": "1"})
        proxy.session.approvals.approve(proxy.session.approvals.pending()[0].approval_id, "alice")
        fake.expire_session()
        result = proxy.call_tool("remote__delete_item", {"id": "1"})
        self.assertFalse(result["isError"], text(result))
        self.assertEqual(len(fake.calls), 1)

    def test_the_idempotency_key_of_a_destructive_call_is_sent_in_meta(self) -> None:
        fake = FakeHttpServer()
        proxy = self.proxy_for(fake)
        proxy.call_tool("remote__delete_item", {"id": "1"})
        proxy.session.approvals.approve(proxy.session.approvals.pending()[0].approval_id, "alice")
        proxy.call_tool("remote__delete_item", {"id": "1"})
        meta = fake.calls[0]["_meta"]
        self.assertTrue(meta["agent-action-gateway/intent_key"])

    def test_oauth_gets_a_token_and_sends_it(self) -> None:
        fake = FakeHttpServer(oauth=True)
        proxy = self.proxy_for(
            fake,
            oauth={
                "token_url": fake.url.replace("/mcp", "/token"),
                "client_id": "cid",
                "client_secret": "csecret",
                "scope": "tools",
            },
        )
        self.assertEqual(text(proxy.call_tool("remote__list_items", {})), "ok")
        self.assertEqual(fake.token_forms[0]["grant_type"], "client_credentials")
        self.assertEqual(fake.token_forms[0]["client_id"], "cid")
        self.assertEqual(fake.token_forms[0]["scope"], "tools")
        self.assertEqual(fake.issued, 1)  # one token serves every request

    def test_a_revoked_token_is_replaced_once(self) -> None:
        fake = FakeHttpServer(oauth=True)
        proxy = self.proxy_for(
            fake,
            oauth={"token_url": fake.url.replace("/mcp", "/token"),
                   "client_id": "cid", "client_secret": "csecret"},
        )
        fake.revoke_token()
        self.assertEqual(text(proxy.call_tool("remote__list_items", {})), "ok")
        self.assertEqual(fake.issued, 2)

    def test_a_token_endpoint_that_fails_stops_start_up_without_leaking_the_secret(self) -> None:
        fake = FakeHttpServer(oauth=True)
        self.addCleanup(fake.stop)
        config = ServerConfig(
            name="remote", url=fake.url,
            oauth={"token_url": "http://127.0.0.1:9/token", "client_id": "cid",
                   "client_secret": "super-secret-value"},
            timeout=2,
        )
        with self.assertRaises(DownstreamError) as raised:
            build_proxy(ProxyConfig((config,), environment="dev"), self.db)
        self.assertNotIn("super-secret-value", str(raised.exception))

    def test_a_tool_list_change_sent_on_the_separate_stream_is_heard(self) -> None:
        fake = FakeHttpServer(stream=True)
        proxy = self.proxy_for(fake)
        self.assertTrue(fake.stream_open.wait(5))
        fake.extra_tools.append({"name": "wipe", "inputSchema": {"type": "object"}})
        fake.push_list_changed()
        deadline = time.monotonic() + 5
        while not proxy.downstreams["remote"].tools_changed and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertTrue(proxy.downstreams["remote"].tools_changed)
        proxy.poll()
        self.assertEqual(
            proxy.report_held(), [("remote__wipe", "it is new on a pinned server")]
        )

    def test_a_server_without_a_stream_is_left_alone(self) -> None:
        fake = FakeHttpServer(stream=False)
        proxy = self.proxy_for(fake)
        listener = proxy.downstreams["remote"]._listener
        listener.join(5)
        self.assertFalse(listener.is_alive())
        self.assertEqual(text(proxy.call_tool("remote__list_items", {})), "ok")

    def test_closing_stops_the_listener(self) -> None:
        fake = FakeHttpServer(stream=True)
        proxy = self.proxy_for(fake)
        self.assertTrue(fake.stream_open.wait(5))
        listener = proxy.downstreams["remote"]._listener
        proxy.close()
        listener.join(5)
        self.assertFalse(listener.is_alive())

    def test_a_server_error_on_a_call_is_an_unknown_outcome(self) -> None:
        fake = FakeHttpServer(fail_calls=1)
        proxy = self.proxy_for(fake)
        result = proxy.call_tool("remote__list_items", {})
        # A read has no claim to hold, but the agent is still told the truth.
        self.assertIn("unknown", text(result))


class BrowserSignInTest(unittest.TestCase):
    """OAuth authorization code with PKCE: a person signs in once, the proxy keeps it fresh."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.db = Path(self._tmp.name) / "runtime.db"
        self.token_file = Path(self._tmp.name) / "tokens" / "remote.json"
        self.fake = FakeHttpServer(oauth=True)
        self.addCleanup(self.fake.stop)
        base = self.fake.url.replace("/mcp", "")
        self.server = ServerConfig(
            name="remote",
            url=self.fake.url,
            oauth={
                "flow": "authorization_code",
                "authorization_url": base + "/authorize",
                "token_url": base + "/token",
                "client_id": "cid",
                "token_file": str(self.token_file),
            },
        )

    def browser(self, url: str) -> None:
        """Stands in for the person: opens the sign-in link and follows the redirect back."""
        import urllib.request

        urllib.request.urlopen(url, timeout=5).read()

    def sign_in(self):
        return sign_in(self.server, open_browser=self.browser, timeout=10)

    def proxy(self):
        proxy = build_proxy(ProxyConfig((self.server,), environment="dev"), self.db)
        self.addCleanup(proxy.close)
        return proxy

    def test_signing_in_saves_the_tokens_readable_by_the_owner_only(self) -> None:
        import os

        path = self.sign_in()
        saved = json.loads(path.read_text())
        self.assertEqual(saved["refresh_token"], "rt-1")
        self.assertTrue(saved["access_token"].startswith("tok-"))
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)

    def test_the_sign_in_link_carries_a_pkce_challenge_and_a_state(self) -> None:
        self.sign_in()
        query = next(iter(self.fake.codes.values()))
        self.assertEqual(query["code_challenge_method"], "S256")
        self.assertEqual(query["response_type"], "code")
        self.assertTrue(query["state"])
        self.assertTrue(query["redirect_uri"].startswith("http://127.0.0.1:"))

    def test_the_proxy_uses_the_saved_sign_in(self) -> None:
        self.sign_in()
        self.assertEqual(text(self.proxy().call_tool("remote__list_items", {})), "ok")

    def test_an_expired_token_is_refreshed_and_saved(self) -> None:
        self.sign_in()
        saved = json.loads(self.token_file.read_text())
        saved["expires_at"] = 0
        self.token_file.write_text(json.dumps(saved))
        self.token_file.chmod(0o600)
        proxy = self.proxy()
        self.assertEqual(text(proxy.call_tool("remote__list_items", {})), "ok")
        refreshed = json.loads(self.token_file.read_text())
        self.assertNotEqual(refreshed["access_token"], saved["access_token"])
        self.assertEqual(refreshed["refresh_token"], "rt-1")  # kept when the server sends none
        self.assertEqual(self.fake.token_forms[-1]["grant_type"], "refresh_token")

    def test_a_revoked_token_is_refreshed_once(self) -> None:
        self.sign_in()
        proxy = self.proxy()
        self.fake.revoke_token()
        self.assertEqual(text(proxy.call_tool("remote__list_items", {})), "ok")

    def test_without_a_sign_in_the_proxy_says_how_to_sign_in(self) -> None:
        with self.assertRaises(DownstreamError) as raised:
            self.proxy()
        self.assertIn("mcp-login", str(raised.exception))

    def test_a_sign_in_file_other_users_can_read_is_refused(self) -> None:
        self.sign_in()
        self.token_file.chmod(0o644)
        with self.assertRaises(DownstreamError) as raised:
            self.proxy()
        self.assertIn("chmod 600", str(raised.exception))

    def test_a_wrong_state_in_the_answer_is_refused_and_nothing_is_saved(self) -> None:
        import urllib.parse
        import urllib.request

        def tampering_browser(url: str) -> None:
            query = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
            back = query["redirect_uri"][0] + "?code=x&state=not-the-state"
            urllib.request.urlopen(back, timeout=5).read()

        with self.assertRaises(SignInError):
            sign_in(self.server, open_browser=tampering_browser, timeout=10)
        self.assertFalse(self.token_file.exists())

    def test_a_server_refusing_the_sign_in_is_reported(self) -> None:
        import urllib.parse
        import urllib.request

        def refusing_browser(url: str) -> None:
            query = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
            back = f"{query['redirect_uri'][0]}?error=access_denied&state={query['state'][0]}"
            urllib.request.urlopen(back, timeout=5).read()

        with self.assertRaisesRegex(SignInError, "access_denied"):
            sign_in(self.server, open_browser=refusing_browser, timeout=10)

    def test_no_answer_in_time_is_reported(self) -> None:
        with self.assertRaisesRegex(SignInError, "no sign-in answer"):
            sign_in(self.server, open_browser=lambda _url: None, timeout=0.3)

    def test_a_failed_token_exchange_is_reported_without_secrets(self) -> None:
        server = ServerConfig(
            name="remote", url=self.fake.url,
            oauth={**self.server.oauth, "client_secret": "super-secret-value"},
        )

        def sign_in_then_lose_the_code(url: str) -> None:
            self.browser(url)
            self.fake.codes.clear()  # the server no longer knows the code

        with self.assertRaises(SignInError) as raised:
            sign_in(server, open_browser=sign_in_then_lose_the_code, timeout=10)
        self.assertNotIn("super-secret-value", str(raised.exception))
        self.assertFalse(self.token_file.exists())

    def test_signing_in_with_the_wrong_kind_of_server_is_refused(self) -> None:
        plain = ServerConfig(name="plain", url=self.fake.url)
        with self.assertRaises(SignInError):
            sign_in(plain, open_browser=lambda _url: None, timeout=1)


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

    def test_oauth_settings_are_parsed_and_checked(self) -> None:
        import os

        os.environ["AAG_TEST_SECRET"] = "s3"
        self.addCleanup(os.environ.pop, "AAG_TEST_SECRET", None)
        good = {"url": "https://x.example/mcp", "oauth": {
            "token_url": "https://auth.example/token", "client_id": "c",
            "client_secret": "${AAG_TEST_SECRET}"}}
        config = parse_proxy_config({"servers": {"r": good}})
        self.assertEqual(config.servers[0].oauth["client_secret"], "s3")
        self.assertNotIn("s3", repr(config.servers[0]))
        for bad in (
            {"command": "c", "oauth": good["oauth"]},
            {**good, "oauth": {"token_url": "https://a/t", "client_id": "c"}},
            {**good, "headers": {"Authorization": "Bearer x"}},
            {**good, "oauth": {**good["oauth"], "token_url": "ftp://a/t"}},
        ):
            with self.subTest(bad=bad), self.assertRaises(ConfigError):
                parse_proxy_config({"servers": {"r": bad}})

    def test_browser_sign_in_settings_are_checked(self) -> None:
        good = {"url": "https://x.example/mcp", "oauth": {
            "flow": "authorization_code",
            "authorization_url": "https://auth.example/authorize",
            "token_url": "https://auth.example/token",
            "client_id": "c", "token_file": "~/tokens/x.json"}}
        config = parse_proxy_config({"servers": {"r": good}})
        oauth = config.servers[0].oauth
        self.assertEqual(oauth["flow"], "authorization_code")
        self.assertNotIn("~", oauth["token_file"])  # expanded
        for drop in ("authorization_url", "token_file", "client_id"):
            bad = {**good, "oauth": {k: v for k, v in good["oauth"].items() if k != drop}}
            with self.subTest(missing=drop), self.assertRaises(ConfigError):
                parse_proxy_config({"servers": {"r": bad}})
        with self.assertRaises(ConfigError):
            parse_proxy_config({"servers": {"r": {**good, "oauth": {**good["oauth"], "flow": "x"}}}})
        with self.assertRaises(ConfigError):
            parse_proxy_config({"servers": {"r": {
                **good, "oauth": {**good["oauth"], "redirect_port": "abc"}}}})

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
