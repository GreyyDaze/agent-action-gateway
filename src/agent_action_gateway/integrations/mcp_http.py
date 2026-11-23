"""The MCP proxy over HTTP, and a small connector for apps that only start commands.

Over stdio, the proxy is started by the agent's app and runs as the agent's own
user, on the agent's machine. That has two costs: an agent that can only reach
an MCP server by URL cannot use it, and an agent with shell or file access could
change the proxy's config or its database (where approvals live).

HTTP mode answers both. The proxy runs as its own service, under its own user,
container or host, and serves MCP's Streamable HTTP transport at `/mcp`:

* Every request needs `Authorization: Bearer <token>`. Tokens come from an
  environment variable on the proxy's side. A token lets an agent call tools
  through the checks; it cannot approve anything (approvals are given in the
  dashboard, which has its own token).
* A request that carries an `Origin` header (a web page) is refused unless that
  origin is allowed, as the MCP specification asks, so a page cannot drive the
  proxy through someone's browser.
* `initialize` opens a session (`Mcp-Session-Id`). A session belongs to the token
  that opened it.
* Replies are plain JSON. There is no server-to-client stream (GET answers 405),
  so the agent is not told when the tool list changes; it sees the change the
  next time it lists tools.

`mcp-connect URL` is the other half, for apps such as Claude Desktop that start
MCP servers as commands: it reads MCP messages on stdin, posts them to the
proxy, and writes the replies to stdout. It holds no policy, no key and no
database.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Collection, Iterable, Mapping
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, TextIO

from agent_action_gateway.integrations.mcp_proxy import (
    ConfigWatcher,
    MCPProxy,
    ProxyServer,
)

#: The environment variable both sides read the token from by default.
TOKEN_ENV = "AGENT_GATEWAY_PROXY_TOKEN"
#: The path the proxy answers on.
MCP_PATH = "/mcp"
#: A token shorter than this is refused: it would be easy to guess.
MIN_TOKEN_LENGTH = 16
#: Requests larger than this are refused.
MAX_BODY_BYTES = 1_048_576
#: Sessions kept at most; the oldest is dropped beyond this.
MAX_SESSIONS = 1_000

_LOOPBACK = {"127.0.0.1", "localhost", "::1"}


class TokenError(ValueError):
    """The token setting cannot be used."""


def parse_tokens(raw: str | None) -> tuple[str, ...]:
    """Tokens from the environment value: one, or several separated by commas."""
    tokens = tuple(t.strip() for t in (raw or "").split(",") if t.strip())
    if not tokens:
        raise TokenError(
            f"set {TOKEN_ENV} to the token agents must send (Authorization: Bearer ...)"
        )
    short = [t for t in tokens if len(t) < MIN_TOKEN_LENGTH]
    if short:
        raise TokenError(f"every token must be at least {MIN_TOKEN_LENGTH} characters")
    return tokens


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class _Sessions:
    """Session id -> (token digest, the dispatcher for that session)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._items: dict[str, tuple[str, ProxyServer]] = {}

    def open(self, token_digest: str, proxy: MCPProxy) -> tuple[str, ProxyServer]:
        session_id = secrets.token_urlsafe(24)
        server = ProxyServer(proxy)
        with self._lock:
            while len(self._items) >= MAX_SESSIONS:
                self._items.pop(next(iter(self._items)))
            self._items[session_id] = (token_digest, server)
        return session_id, server

    def get(self, session_id: str, token_digest: str) -> ProxyServer | None:
        with self._lock:
            item = self._items.get(session_id)
        if item is None or not secrets.compare_digest(item[0], token_digest):
            return None
        return item[1]

    def close(self, session_id: str, token_digest: str) -> bool:
        with self._lock:
            item = self._items.get(session_id)
            if item is None or not secrets.compare_digest(item[0], token_digest):
                return False
            del self._items[session_id]
            return True


class ProxyHttpHandler(BaseHTTPRequestHandler):
    """Streamable HTTP for the proxy. Policy stays in `MCPProxy`."""

    proxy: MCPProxy
    tokens: tuple[str, ...]
    allowed_origins: frozenset[str]
    sessions: _Sessions

    def log_message(self, *_args: object) -> None:
        return

    # -- helpers -------------------------------------------------------------

    def _send(
        self,
        status: int,
        payload: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        body = b"" if payload is None else json.dumps(payload).encode("utf-8")
        self.send_response(status)
        if payload is not None:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _error(self, status: int, code: int, message: str, request_id: Any = None) -> None:
        self._send(status, {"jsonrpc": "2.0", "id": request_id,
                            "error": {"code": code, "message": message}})

    def _caller(self) -> str | None:
        """The digest of the caller's token, or None (and a reply sent)."""
        origin = self.headers.get("Origin")
        if origin is not None and origin not in self.allowed_origins:
            self._send(403, {"error": "origin not allowed"})
            return None
        if urllib.parse.urlparse(self.path).path != MCP_PATH:
            self._send(404, {"error": f"not found; the MCP endpoint is {MCP_PATH}"})
            return None
        header = self.headers.get("Authorization", "")
        presented = header[7:] if header.startswith("Bearer ") else ""
        if not presented or not any(
            secrets.compare_digest(presented.encode(), t.encode()) for t in self.tokens
        ):
            self._send(401, {"error": "a valid bearer token is required"},
                       {"WWW-Authenticate": 'Bearer realm="agent-action-gateway"'})
            return None
        return _digest(presented)

    # -- methods -------------------------------------------------------------

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        caller = self._caller()
        if caller is None:
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = -1
        if length < 0 or length > MAX_BODY_BYTES:
            self._error(413, -32600, f"the body must be 0 to {MAX_BODY_BYTES} bytes")
            return
        try:
            message = json.loads(self.rfile.read(length).decode("utf-8") or "null")
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._error(400, -32700, "parse error")
            return
        if not isinstance(message, dict):
            self._error(400, -32600, "send one JSON-RPC message per request")
            return

        if message.get("method") == "initialize":
            new_id, new_server = self.sessions.open(caller, self.proxy)
            self._send(200, new_server.handle(message), {"Mcp-Session-Id": new_id})
            return

        session_id = self.headers.get("Mcp-Session-Id")
        if not session_id:
            self._error(400, -32600, "missing Mcp-Session-Id: send initialize first",
                        message.get("id"))
            return
        server = self.sessions.get(session_id, caller)
        if server is None:
            # 404 tells the client to start a new session.
            self._error(404, -32001, "unknown session: send initialize again",
                        message.get("id"))
            return
        reply = server.handle(message)
        if reply is None:
            self._send(202)
            return
        self._send(200, reply)

    def do_DELETE(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        caller = self._caller()
        if caller is None:
            return
        session_id = self.headers.get("Mcp-Session-Id", "")
        if self.sessions.close(session_id, caller):
            self._send(200)
        else:
            self._send(404, {"error": "unknown session"})

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self._caller() is None:
            return
        # No server-to-client stream: the spec allows a 405 here.
        self._send(405, {"error": "no event stream; use POST"}, {"Allow": "POST, DELETE"})


def build_proxy_http_server(
    proxy: MCPProxy,
    tokens: Collection[str],
    host: str = "127.0.0.1",
    port: int = 0,
    allowed_origins: Iterable[str] = (),
) -> ThreadingHTTPServer:
    """An HTTP server for the proxy. Call `serve_forever()` on it."""
    if not tokens:
        raise TokenError("at least one token is required")
    handler = type(
        "BoundProxyHttpHandler",
        (ProxyHttpHandler,),
        {
            "proxy": proxy,
            "tokens": tuple(tokens),
            "allowed_origins": frozenset(allowed_origins),
            "sessions": _Sessions(),
        },
    )
    server = ThreadingHTTPServer((host, port), handler)
    server.daemon_threads = True
    return server


def serve_proxy_http(
    proxy: MCPProxy,
    config_path: str | Path | None,
    tokens: Collection[str],
    host: str = "127.0.0.1",
    port: int = 8090,
    allowed_origins: Iterable[str] = (),
) -> None:
    """Run the proxy over HTTP until interrupted."""
    server = build_proxy_http_server(proxy, tokens, host, port, allowed_origins)
    watcher = None
    if config_path is not None:
        # Over HTTP there is no channel to announce changes on; the watcher
        # still applies config edits, and the agent sees them on its next list.
        watcher = ConfigWatcher(config_path, proxy, ProxyServer(proxy))
        watcher.start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        if watcher is not None:
            watcher.stop()
        proxy.close()


# -- the connector ------------------------------------------------------------


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow a redirect: it would send the token somewhere else."""

    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        return None


def check_connect_url(url: str) -> None:
    """Refuse a URL that would send the token in clear over a network."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme == "https":
        return
    if parsed.scheme == "http" and parsed.hostname in _LOOPBACK:
        return
    raise ValueError(
        f"refusing {url!r}: use https, or http only to this machine "
        "(the token would otherwise travel in clear text)"
    )


class Connector:
    """Forwards MCP messages from stdin to the proxy's URL, and replies back."""

    def __init__(self, url: str, token: str, timeout: float = 300.0) -> None:
        check_connect_url(url)
        self.url = url
        self.token = token
        self.timeout = timeout
        self.session_id: str | None = None
        self._initialize: dict[str, Any] | None = None
        # No environment proxies (the token stays on this path) and no redirects.
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _NoRedirect()
        )

    def _post(self, message: Mapping[str, Any]) -> tuple[int, Any, str | None]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "Authorization": f"Bearer {self.token}",
        }
        if self.session_id and message.get("method") != "initialize":
            headers["Mcp-Session-Id"] = self.session_id
        request = urllib.request.Request(
            self.url, data=json.dumps(message).encode("utf-8"), headers=headers, method="POST"
        )
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                body = response.read().decode("utf-8")
                return (response.status, _replies(body, response.headers.get_content_type()),
                        response.headers.get("Mcp-Session-Id"))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", "replace")
            return exc.code, _replies(body, exc.headers.get_content_type()), None

    def forward(self, message: Mapping[str, Any]) -> list[dict[str, Any]]:
        """Send one message; return the replies to write to the app."""
        request_id = message.get("id")
        if message.get("method") == "initialize":
            self._initialize = dict(message)
        try:
            status, replies, session_id = self._post(message)
            if status == 404 and self.session_id and self._initialize is not None:
                # The proxy forgot the session (it restarted). A server that
                # does not know the session has not acted on the message, so
                # open a new session and send it once more.
                self._reopen()
                status, replies, session_id = self._post(message)
        except (urllib.error.URLError, OSError) as exc:
            return _failure(request_id, f"cannot reach the proxy at {self.url}: {exc}")
        if session_id:
            self.session_id = session_id
        if status == 401:
            return _failure(request_id, f"the proxy refused the token; check {TOKEN_ENV}")
        if status == 202 or request_id is None:
            return []
        if replies:
            return replies
        return _failure(request_id, f"the proxy answered HTTP {status} with no message")

    def _reopen(self) -> None:
        assert self._initialize is not None
        self.session_id = None
        _, _, session_id = self._post(self._initialize)
        self.session_id = session_id
        self._post({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def serve(self, lines: Iterable[str], out: TextIO | None = None) -> None:
        out = out or sys.stdout
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                message = json.loads(line)
                if not isinstance(message, dict):
                    raise ValueError("not an object")
            except (json.JSONDecodeError, ValueError):
                replies = [{"jsonrpc": "2.0", "id": None,
                            "error": {"code": -32700, "message": "parse error"}}]
            else:
                replies = self.forward(message)
            for reply in replies:
                out.write(json.dumps(reply) + "\n")
            out.flush()


def _replies(body: str, content_type: str) -> list[dict[str, Any]]:
    """JSON-RPC messages from a reply body: plain JSON or an event stream."""
    if not body.strip():
        return []
    if content_type == "text/event-stream":
        found = []
        for raw in body.splitlines():
            if raw.startswith("data:"):
                try:
                    item = json.loads(raw[5:].strip())
                except json.JSONDecodeError:
                    continue
                if isinstance(item, dict) and ("result" in item or "error" in item):
                    found.append(item)
        return found
    try:
        item = json.loads(body)
    except json.JSONDecodeError:
        return []
    if isinstance(item, dict) and ("result" in item or "error" in item):
        return [item]
    return []


def _failure(request_id: Any, message: str) -> list[dict[str, Any]]:
    if request_id is None:
        print(f"mcp-connect: {message}", file=sys.stderr, flush=True)
        return []
    return [{"jsonrpc": "2.0", "id": request_id,
             "error": {"code": -32000, "message": message}}]


__all__ = [
    "MCP_PATH",
    "TOKEN_ENV",
    "Connector",
    "TokenError",
    "build_proxy_http_server",
    "check_connect_url",
    "parse_tokens",
    "serve_proxy_http",
]
