"""The MCP proxy: one server for the agent, a client to the real tool servers."""

from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

from agent_action_gateway.integrations.mcp_proxy import (
    ConfigError,
    ProxyConfig,
    ProxyServer,
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

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.log = Path(self._tmp.name) / "effects.log"
        server = ServerConfig(
            name="db",
            command=sys.executable,
            args=(FAKE,),
            env={"FAKE_MCP_LOG": str(self.log)},
            environment=self.server_environment,
            trust_hints=self.trust_hints,
            timeout=self.timeout,
        )
        kwargs = {"limits": self.limits} if self.limits else {}
        self.proxy = build_proxy(
            ProxyConfig((server,), self.rules, self.environment, **kwargs),
            Path(self._tmp.name) / "runtime.db",
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
            ["db__list_items", "db__delete_item", "db__fail_tool", "db__hang_tool", "db__liar_tool"],
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
        result = self.proxy.call_tool("db__delete_item", {"id": "7", "_approval_id": approval_id})
        self.assertFalse(result["isError"], text(result))
        self.assertEqual(len(self.effects()), 1)

    def test_reserved_argument_names_are_refused(self) -> None:
        result = self.proxy.call_tool("db__delete_item", {"id": "7", "intent_key": "x"})
        self.assertTrue(result["isError"])
        self.assertIn("intent_key", text(result))

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
            {"servers": {"a": {"url": "https://x"}}},
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
        self.assertEqual(len(replies[1]["result"]["tools"]), 5)
        self.assertEqual(text(replies[2]["result"]), "a,b,c")
        self.assertEqual(replies[4]["error"]["code"], -32601)

    def test_garbage_gets_a_parse_error_and_the_loop_continues(self) -> None:
        out = io.StringIO()
        ProxyServer(self.proxy).serve(["not json", json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"})], out)
        lines = [json.loads(x) for x in out.getvalue().splitlines()]
        self.assertEqual(lines[0]["error"]["code"], -32700)
        self.assertEqual(lines[1]["id"], 1)


if __name__ == "__main__":
    unittest.main()
