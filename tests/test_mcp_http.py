"""The MCP proxy over HTTP, and the stdio connector that forwards to it."""

from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

from agent_action_gateway.cli import main
from agent_action_gateway.integrations.mcp_http import (
    Connector,
    TokenError,
    build_proxy_http_server,
    check_connect_url,
    parse_tokens,
)
from agent_action_gateway.integrations.mcp_proxy import ProxyConfig, ServerConfig, build_proxy

FAKE = str(Path(__file__).parent / "fixtures" / "fake_mcp_server.py")
TOKEN = "agent-token-0123456789"
OTHER = "other-token-0123456789"


class HttpProxyCase(unittest.TestCase):
    origins: tuple[str, ...] = ()

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.log = Path(tmp.name) / "effects.log"
        server = ServerConfig(
            name="db", command=sys.executable, args=(FAKE,),
            env={"FAKE_MCP_LOG": str(self.log)},
        )
        self.proxy = build_proxy(ProxyConfig((server,)), Path(tmp.name) / "runtime.db")
        self.addCleanup(self.proxy.close)
        self.http = build_proxy_http_server(
            self.proxy, (TOKEN, OTHER), "127.0.0.1", 0, self.origins
        )
        self.addCleanup(self.http.server_close)
        threading.Thread(target=self.http.serve_forever, daemon=True).start()
        self.addCleanup(self.http.shutdown)
        self.url = f"http://127.0.0.1:{self.http.server_address[1]}/mcp"

    def effects(self) -> list[dict]:
        if not self.log.exists():
            return []
        return [json.loads(x) for x in self.log.read_text().splitlines()]

    def post(
        self,
        message: object,
        *,
        token: str | None = TOKEN,
        session: str | None = None,
        headers: dict | None = None,
        url: str | None = None,
        method: str = "POST",
    ) -> tuple[int, dict, dict]:
        data = None if method in ("GET", "DELETE") else json.dumps(message).encode()
        request = urllib.request.Request(url or self.url, data=data, method=method)
        request.add_header("Content-Type", "application/json")
        if token is not None:
            request.add_header("Authorization", f"Bearer {token}")
        if session is not None:
            request.add_header("Mcp-Session-Id", session)
        for name, value in (headers or {}).items():
            request.add_header(name, value)
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                body = response.read().decode()
                return response.status, json.loads(body) if body else {}, dict(response.headers)
        except urllib.error.HTTPError as exc:
            body = exc.read().decode()
            return exc.code, json.loads(body) if body else {}, dict(exc.headers)

    def initialize(self, token: str = TOKEN) -> str:
        status, body, headers = self.post(
            {"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {"protocolVersion": "2025-06-18"}},
            token=token,
        )
        self.assertEqual(status, 200, body)
        session = headers["Mcp-Session-Id"]
        self.post({"jsonrpc": "2.0", "method": "notifications/initialized"},
                  token=token, session=session)
        return session

    def call(self, session: str, name: str, arguments: dict, request_id: int = 3) -> dict:
        status, body, _ = self.post(
            {"jsonrpc": "2.0", "id": request_id, "method": "tools/call",
             "params": {"name": name, "arguments": arguments}},
            session=session,
        )
        self.assertEqual(status, 200, body)
        return body["result"]


class AuthTest(HttpProxyCase):
    def test_no_token_or_a_wrong_token_is_refused(self) -> None:
        for token in (None, "wrong-token-0123456789"):
            with self.subTest(token=token):
                status, _, headers = self.post({"jsonrpc": "2.0", "id": 1,
                                                "method": "initialize"}, token=token)
                self.assertEqual(status, 401)
                self.assertIn("Bearer", headers["WWW-Authenticate"])

    def test_a_web_page_origin_is_refused(self) -> None:
        status, _, _ = self.post({"jsonrpc": "2.0", "id": 1, "method": "initialize"},
                                 headers={"Origin": "https://evil.example"})
        self.assertEqual(status, 403)

    def test_other_paths_are_not_served(self) -> None:
        status, _, _ = self.post({}, url=self.url.replace("/mcp", "/admin"))
        self.assertEqual(status, 404)

    def test_a_session_belongs_to_the_token_that_opened_it(self) -> None:
        session = self.initialize(TOKEN)
        status, _, _ = self.post({"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                                 token=OTHER, session=session)
        self.assertEqual(status, 404)


class AllowedOriginTest(HttpProxyCase):
    origins = ("https://console.example",)

    def test_an_allowed_origin_may_call(self) -> None:
        status, _, _ = self.post(
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            headers={"Origin": "https://console.example"},
        )
        self.assertEqual(status, 200)


class ProtocolTest(HttpProxyCase):
    def test_a_session_is_needed_after_initialize(self) -> None:
        status, _, _ = self.post({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        self.assertEqual(status, 400)
        status, _, _ = self.post({"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                                 session="made-up")
        self.assertEqual(status, 404)

    def test_tools_are_listed_and_a_notification_gets_202(self) -> None:
        session = self.initialize()
        status, body, _ = self.post({"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                                    session=session)
        self.assertEqual(status, 200)
        names = {t["name"] for t in body["result"]["tools"]}
        self.assertIn("db__delete_item", names)
        status, _, _ = self.post({"jsonrpc": "2.0", "method": "notifications/initialized"},
                                 session=session)
        self.assertEqual(status, 202)

    def test_the_checks_apply_over_http(self) -> None:
        session = self.initialize()
        self.assertFalse(self.call(session, "db__list_items", {})["isError"])
        held = self.call(session, "db__delete_item", {"id": "7"})
        self.assertIn("needs a person's approval", held["content"][0]["text"])
        self.assertEqual(self.effects(), [])

        pending = self.proxy.session.approvals.pending()
        self.proxy.session.approvals.approve(pending[0].approval_id, "alice")
        done = self.call(session, "db__delete_item", {"id": "7"})
        self.assertFalse(done["isError"], done)
        self.assertEqual(len(self.effects()), 1)

    def test_bad_bodies_are_refused(self) -> None:
        session = self.initialize()
        status, _, _ = self.post([{"jsonrpc": "2.0", "id": 1, "method": "ping"}],
                                 session=session)
        self.assertEqual(status, 400)
        request = urllib.request.Request(self.url, data=b"{not json", method="POST")
        request.add_header("Authorization", f"Bearer {TOKEN}")
        with self.assertRaises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(request, timeout=10)
        self.assertEqual(caught.exception.code, 400)

    def test_a_huge_body_is_refused(self) -> None:
        request = urllib.request.Request(self.url, data=b"x", method="POST")
        request.add_header("Authorization", f"Bearer {TOKEN}")
        request.add_header("Content-Length", str(10_000_000))
        with self.assertRaises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(request, timeout=10)
        self.assertEqual(caught.exception.code, 413)

    def test_get_has_no_stream_and_delete_ends_the_session(self) -> None:
        session = self.initialize()
        status, _, _ = self.post(None, session=session, method="GET")
        self.assertEqual(status, 405)
        status, _, _ = self.post(None, session=session, method="DELETE")
        self.assertEqual(status, 200)
        status, _, _ = self.post({"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                                 session=session)
        self.assertEqual(status, 404)


class ConnectorTest(HttpProxyCase):
    def run_lines(self, connector: Connector, messages: list[dict]) -> list[dict]:
        out = io.StringIO()
        connector.serve(io.StringIO("\n".join(json.dumps(m) for m in messages) + "\n"), out)
        return [json.loads(x) for x in out.getvalue().splitlines()]

    def test_it_forwards_messages_and_replies(self) -> None:
        replies = self.run_lines(Connector(self.url, TOKEN), [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
             "params": {"name": "db__delete_item", "arguments": {"id": "9"}}},
        ])
        self.assertEqual([r["id"] for r in replies], [1, 2, 3])
        self.assertIn("needs a person's approval", replies[2]["result"]["content"][0]["text"])
        self.assertEqual(self.effects(), [])

    def test_it_opens_a_new_session_when_the_proxy_forgot_it(self) -> None:
        connector = Connector(self.url, TOKEN)
        self.run_lines(connector, [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        ])
        self.http.RequestHandlerClass.sessions._items.clear()  # type: ignore[attr-defined]
        replies = self.run_lines(connector, [{"jsonrpc": "2.0", "id": 2, "method": "tools/list"}])
        self.assertIn("tools", replies[0]["result"])

    def test_a_wrong_token_becomes_an_error_reply(self) -> None:
        replies = self.run_lines(Connector(self.url, "wrong-token-0123456789"), [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        ])
        self.assertIn("refused the token", replies[0]["error"]["message"])

    def test_an_unreachable_proxy_becomes_an_error_reply(self) -> None:
        replies = self.run_lines(Connector("http://127.0.0.1:1/mcp", TOKEN, timeout=2), [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        ])
        self.assertIn("cannot reach the proxy", replies[0]["error"]["message"])


class SettingsTest(unittest.TestCase):
    def test_tokens(self) -> None:
        self.assertEqual(parse_tokens(f"{TOKEN}, {OTHER}"), (TOKEN, OTHER))
        for raw in (None, "", " , ", "short"):
            with self.subTest(raw=raw), self.assertRaises(TokenError):
                parse_tokens(raw)

    def test_the_connector_refuses_clear_text_over_a_network(self) -> None:
        for url in ("https://proxy.example/mcp", "http://127.0.0.1:8090/mcp",
                    "http://localhost:8090/mcp"):
            check_connect_url(url)
        for url in ("http://proxy.example/mcp", "ftp://x/mcp", "proxy:8090"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                check_connect_url(url)


class CommandTest(unittest.TestCase):
    def test_http_mode_needs_a_token(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AGENT_GATEWAY_PROXY_TOKEN", None)
            with mock.patch("sys.stderr", io.StringIO()) as err:
                code = main(["mcp-proxy", "--config", "missing.json", "--http"])
        self.assertEqual(code, 2)
        self.assertIn("AGENT_GATEWAY_PROXY_TOKEN", err.getvalue())

    def test_connect_needs_a_token_and_a_safe_url(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AGENT_GATEWAY_PROXY_TOKEN", None)
            with mock.patch("sys.stderr", io.StringIO()):
                self.assertEqual(main(["mcp-connect", "https://proxy.example/mcp"]), 2)
        with mock.patch.dict(os.environ, {"AGENT_GATEWAY_PROXY_TOKEN": TOKEN}):
            with mock.patch("sys.stderr", io.StringIO()) as err:
                self.assertEqual(main(["mcp-connect", "http://proxy.example/mcp"]), 2)
        self.assertIn("https", err.getvalue())


if __name__ == "__main__":
    unittest.main()
