"""An MCP proxy: one server for the agent, a client to every real tool server.

The agent connects to this proxy and to nothing else. The proxy connects, as a
client, to the MCP servers the operator listed in a config file (a command it
starts, or a remote URL). It merges their tools into one list and runs every
`tools/call` through the same checks the library uses (`SafetySession.tool`,
which calls `engine.enforce`) before it forwards the call.

What it can and cannot do:

* It checks the calls that go through it. If the agent's platform can also reach
  a real tool server directly, those calls skip the proxy. Removing the direct
  connections is the operator's job; no code here can do it for them.
* Tools are discovered from `tools/list`. Nobody writes a route by hand.
* A tool is `read` only when an operator rule says so, or when the server says
  `readOnlyHint` and the operator trusts that server's hints. Every other tool is
  destructive and needs an approval.
* A server's tool definitions are pinned the first time they are seen. A tool
  whose definition later changes, or a new tool on a server that was already
  pinned, is hidden and refused until a person accepts it. A hint is a claim by
  the server, and this is what stops a server from flipping it after approval.
* A call that is missing a required argument is refused with a request to ask
  the user, before any step is spent and before any approval is created.
* The config file is watched. Adding, removing or changing a server, or its
  rules, takes effect without a restart, and the agent's client is told that the
  tool list changed.

Approvals: a blocked call returns an error that carries an approval id. A person
approves it (dashboard), and the agent repeats the same call. The approval is
bound to the exact arguments and is used once. The proxy finds the approval
itself, so the agent never has to pass an id.

The proxy holds no key. Credentials a real server needs go in that server's own
`env` or `headers` (use `${NAME}` to read them from the environment).
"""

from __future__ import annotations

import contextlib
import fnmatch
import hashlib
import http.client
import json
import os
import queue
import re
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, TextIO

from agent_action_gateway.guards.redaction import redact
from agent_action_gateway.policy.fuses import FuseLimits
from agent_action_gateway.runtime.records import TraceEvent
from agent_action_gateway.runtime.session import VALID_ENVIRONMENTS, SafetySession
from agent_action_gateway.storage.base import Store
from agent_action_gateway.storage.traces import TraceStore

SEPARATOR = "__"
SUPPORTED_PROTOCOLS = ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25")
#: Where an MCP client that wants to pass an approval id puts it (`params._meta`).
#: It is never read from the tool's arguments, so no argument name can collide.
APPROVAL_META_KEY = "agent-action-gateway/approval_id"
#: Where the proxy puts the idempotency key of the action it forwards. A server
#: that understands it (the gateway's /mcp endpoint) passes it on to the real
#: system, so a retry after a crash is recognised there too. Keep in step with
#: `INTENT_META_KEY` in mcp_server.py.
INTENT_META_KEY = "agent-action-gateway/intent_key"
#: A proxy lives as long as the agent's client keeps it. Ten minutes (the
#: library default) would stop a normal session, so the default is longer.
DEFAULT_LIMITS = FuseLimits(max_steps=500, max_wall_seconds=3600.0)
#: A local server that dies is restarted, but not more often than this.
MAX_RESTARTS_PER_MINUTE = 3
#: Results larger than this are not kept for repeats.
MAX_STORED_RESULT_BYTES = 16_384

_VARIABLE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


class ConfigError(ValueError):
    """The proxy config is wrong. Reported before anything starts."""


class DownstreamError(Exception):
    """Base class for a failure talking to a real tool server."""


class DownstreamNotRun(DownstreamError):
    """The call is known not to have run (not delivered, or rejected)."""


class DownstreamUnknown(DownstreamError):
    """The call was sent and no answer came. It may or may not have run."""


class ToolReportedError(Exception):
    """The tool ran and reported an error. Carries the tool's own result."""

    def __init__(self, result: Mapping[str, Any]) -> None:
        super().__init__("the tool reported an error")
        self.result = dict(result)


def say(message: str) -> None:
    """Operator-facing notes. stdout carries the protocol, so this is stderr."""
    print(f"mcp-proxy: {message}", file=sys.stderr, flush=True)


# --------------------------------------------------------------------------
# config
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class ServerConfig:
    name: str
    #: A local server: the command the proxy starts.
    command: str | None = None
    args: tuple[str, ...] = ()
    env: Mapping[str, str] = field(default_factory=dict, repr=False)
    cwd: str | None = None
    #: A remote server (Streamable HTTP).
    url: str | None = None
    headers: Mapping[str, str] = field(default_factory=dict, repr=False)
    #: OAuth client-credentials settings for a remote server: token_url,
    #: client_id, client_secret and optionally scope.
    oauth: Mapping[str, str] = field(default_factory=dict, repr=False)
    #: The environment this server's tools act on. Empty means the session's.
    environment: str | None = None
    #: Whether this server's `readOnlyHint` may mark its tools as read.
    trust_hints: bool = True
    timeout: float = 30.0


@dataclass(frozen=True)
class Rule:
    match: str
    risk: str


@dataclass(frozen=True)
class Requirement:
    """Arguments a tool must be given, on top of the ones its schema requires."""

    match: str
    arguments: tuple[str, ...]


@dataclass(frozen=True)
class ProxyConfig:
    servers: tuple[ServerConfig, ...]
    rules: tuple[Rule, ...] = ()
    require: tuple[Requirement, ...] = ()
    environment: str = "dev"
    limits: FuseLimits = DEFAULT_LIMITS


def _expand(text: str, where: str) -> str:
    """Replace `${NAME}` with the environment variable, so secrets stay out of the file."""

    def substitute(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in os.environ:
            raise ConfigError(f"{where}: the environment variable {name} is not set")
        return os.environ[name]

    return _VARIABLE.sub(substitute, text)


def load_proxy_config(path: str | Path) -> ProxyConfig:
    """Read a JSON (or, with PyYAML installed, YAML) proxy config."""
    text = Path(path).read_text(encoding="utf-8")
    try:
        raw = json.loads(text)
    except json.JSONDecodeError:
        try:
            import yaml
        except ImportError as exc:
            raise ConfigError(
                f"{path} is not valid JSON (install the [yaml] extra to use YAML)"
            ) from exc
        try:
            raw = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise ConfigError(f"{path} is not valid JSON or YAML: {exc}") from exc
    return parse_proxy_config(raw)


def parse_proxy_config(raw: Any) -> ProxyConfig:
    if not isinstance(raw, Mapping):
        raise ConfigError("the config must be an object")
    # `mcpServers` is the name Claude Desktop and Cursor use, so a user can
    # paste the block they already have.
    servers_raw = raw.get("servers", raw.get("mcpServers"))
    if not isinstance(servers_raw, Mapping) or not servers_raw:
        raise ConfigError("the config needs a non-empty 'servers' object")

    environment = str(raw.get("environment", "dev"))
    if environment not in VALID_ENVIRONMENTS:
        raise ConfigError(
            f"environment must be one of {', '.join(VALID_ENVIRONMENTS)}; got {environment!r}"
        )

    servers = [_parse_server(str(name), entry) for name, entry in servers_raw.items()]

    rules = []
    for item in raw.get("rules", ()):
        if not isinstance(item, Mapping) or "match" not in item or "risk" not in item:
            raise ConfigError("each rule needs 'match' and 'risk'")
        risk = str(item["risk"])
        if risk not in ("read", "write", "destructive"):
            raise ConfigError(f"rule {item['match']!r}: risk must be read, write or destructive")
        rules.append(Rule(str(item["match"]), risk))

    require = []
    for item in raw.get("require", ()):
        arguments = item.get("arguments") if isinstance(item, Mapping) else None
        if (
            not isinstance(item, Mapping)
            or "match" not in item
            or not isinstance(arguments, list)
            or not arguments
        ):
            raise ConfigError("each 'require' entry needs 'match' and a non-empty 'arguments' list")
        require.append(Requirement(str(item["match"]), tuple(str(a) for a in arguments)))

    limits = DEFAULT_LIMITS
    if "limits" in raw:
        known = {"max_steps", "max_wall_seconds", "max_dollars", "loop_repeat_limit",
                 "degraded_read_steps"}
        given = dict(raw["limits"])
        unknown = set(given) - known
        if unknown:
            raise ConfigError(f"unknown limits: {', '.join(sorted(unknown))}")
        merged = {
            "max_steps": DEFAULT_LIMITS.max_steps,
            "max_wall_seconds": DEFAULT_LIMITS.max_wall_seconds,
            **given,
        }
        try:
            limits = FuseLimits(**merged)
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"limits: {exc}") from exc

    return ProxyConfig(tuple(servers), tuple(rules), tuple(require), environment, limits)


def _parse_server(name: str, entry: Any) -> ServerConfig:
    if not name or SEPARATOR in name or name.startswith("_") or name.endswith("_"):
        raise ConfigError(
            f"server name {name!r} is not allowed: it must not be empty, contain "
            f"'{SEPARATOR}', or start or end with an underscore"
        )
    if not isinstance(entry, Mapping):
        raise ConfigError(f"server {name!r} must be an object")
    where = f"server {name!r}"
    command = entry.get("command")
    url = entry.get("url")
    if bool(command) == bool(url):
        raise ConfigError(f"{where} needs exactly one of 'command' (local) or 'url' (remote)")
    server_env = entry.get("environment")
    if server_env is not None and server_env not in VALID_ENVIRONMENTS:
        raise ConfigError(f"{where}: environment must be one of {', '.join(VALID_ENVIRONMENTS)}")
    if url is not None:
        url = _expand(str(url), where)
        if not url.startswith(("http://", "https://")):
            raise ConfigError(f"{where}: 'url' must start with http:// or https://")
    oauth = _parse_oauth(entry.get("oauth"), where, url is not None, entry.get("headers") or {})
    return ServerConfig(
        name=name,
        command=_expand(str(command), where) if command else None,
        args=tuple(_expand(str(a), where) for a in entry.get("args", ())),
        env={str(k): _expand(str(v), where) for k, v in dict(entry.get("env", {})).items()},
        cwd=entry.get("cwd"),
        url=url,
        headers={str(k): _expand(str(v), where) for k, v in dict(entry.get("headers", {})).items()},
        oauth=oauth,
        environment=server_env,
        trust_hints=bool(entry.get("trust_hints", True)),
        timeout=float(entry.get("timeout", 30.0)),
    )


def _is_web_url(value: str) -> bool:
    return value.startswith(("http://", "https://"))


def _parse_oauth(raw: Any, where: str, remote: bool, headers: Mapping[str, Any]) -> dict[str, str]:
    """Check an `oauth` block. Two flows: client credentials (no person involved)
    and authorization code with PKCE (a person signs in once with `mcp-login`)."""
    if raw is None:
        return {}
    if not remote:
        raise ConfigError(f"{where}: 'oauth' only applies to a remote server (one with 'url')")
    if not isinstance(raw, Mapping):
        raise ConfigError(f"{where}: 'oauth' must be an object")
    flow = str(raw.get("flow", "client_credentials"))
    if flow not in ("client_credentials", "authorization_code"):
        raise ConfigError(f"{where}: oauth 'flow' must be client_credentials or authorization_code")
    # With the sign-in flow, the endpoints and the client may be left out: `mcp-login`
    # finds them from the server and registers a client by itself.
    required = ["token_file"]
    if flow == "client_credentials":
        required = ["token_url", "client_id", "client_secret"]
    missing = [k for k in required if not raw.get(k)]
    if missing:
        raise ConfigError(f"{where}: 'oauth' needs {', '.join(missing)}")
    if any(str(k).lower() == "authorization" for k in headers):
        raise ConfigError(f"{where}: use either an Authorization header or 'oauth', not both")
    keys = ("token_url", "authorization_url", "client_id", "client_secret", "scope",
            "token_file", "redirect_port")
    settings = {k: _expand(str(raw[k]), where) for k in keys if raw.get(k)}
    settings["flow"] = flow
    for key in ("token_url", "authorization_url"):
        if key in settings and not _is_web_url(settings[key]):
            raise ConfigError(f"{where}: oauth '{key}' must start with http:// or https://")
    if "token_file" in settings:
        settings["token_file"] = str(Path(settings["token_file"]).expanduser())
    if "redirect_port" in settings and not settings["redirect_port"].isdigit():
        raise ConfigError(f"{where}: oauth 'redirect_port' must be a number")
    return settings


# --------------------------------------------------------------------------
# downstream: an MCP client, over stdio or Streamable HTTP
# --------------------------------------------------------------------------


class Downstream(Protocol):
    name: str
    #: Set when the server said its tool list changed. The proxy clears it.
    tools_changed: bool

    def start(self) -> None: ...

    def alive(self) -> bool: ...

    def list_tools(self) -> list[dict[str, Any]]: ...

    def call_tool(
        self, tool: str, arguments: Mapping[str, Any], meta: Mapping[str, Any] | None = None
    ) -> dict[str, Any]: ...

    def close(self) -> None: ...


_EOF = object()
_LIST_CHANGED = "notifications/tools/list_changed"


class StdioDownstream:
    """Talks to one MCP server it starts as a child process."""

    def __init__(
        self,
        name: str,
        command: str,
        args: Sequence[str] = (),
        env: Mapping[str, str] | None = None,
        cwd: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        self.name = name
        self.tools_changed = False
        self._command = [command, *args]
        self._env = {**os.environ, **(env or {})}
        self._cwd = cwd
        self.timeout = timeout
        self._proc: subprocess.Popen[str] | None = None
        self._inbox: queue.Queue[Any] = queue.Queue()
        self._write_lock = threading.Lock()
        self._call_lock = threading.Lock()
        self._next_id = 1

    @classmethod
    def from_config(cls, config: ServerConfig) -> StdioDownstream:
        assert config.command is not None
        return cls(config.name, config.command, config.args, config.env, config.cwd, config.timeout)

    # -- lifecycle ---------------------------------------------------------

    def alive(self) -> bool:
        proc = self._proc
        return proc is not None and proc.poll() is None

    def start(self) -> None:
        # A restart begins with an empty inbox: anything left in it belongs to
        # the process that died.
        self._inbox = queue.Queue()
        try:
            self._proc = subprocess.Popen(
                self._command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                text=True,
                bufsize=1,
                env=self._env,
                cwd=self._cwd,
            )
        except OSError as exc:
            raise DownstreamNotRun(f"cannot start {self._command[0]!r}: {exc}") from exc
        threading.Thread(target=self._read_loop, args=(self._proc, self._inbox), daemon=True).start()
        self._request(
            "initialize",
            {
                "protocolVersion": SUPPORTED_PROTOCOLS[-2],
                "capabilities": {},
                "clientInfo": {"name": "agent-action-gateway-proxy", "version": "0.2.0"},
            },
        )
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def close(self) -> None:
        proc = self._proc
        if proc is None:
            return
        try:
            if proc.stdin:
                proc.stdin.close()
            proc.terminate()
            proc.wait(timeout=3)
        except Exception:
            proc.kill()
        self._proc = None

    # -- protocol ----------------------------------------------------------

    def list_tools(self) -> list[dict[str, Any]]:
        tools: list[dict[str, Any]] = []
        cursor: str | None = None
        while True:
            result = self._request("tools/list", {"cursor": cursor} if cursor else {})
            tools.extend(result.get("tools", []))
            cursor = result.get("nextCursor")
            if not cursor:
                return tools

    def call_tool(
        self, tool: str, arguments: Mapping[str, Any], meta: Mapping[str, Any] | None = None
    ) -> dict[str, Any]:
        params: dict[str, Any] = {"name": tool, "arguments": dict(arguments)}
        if meta:
            params["_meta"] = dict(meta)
        result = self._request("tools/call", params)
        if not isinstance(result, dict):
            raise DownstreamNotRun(f"{self.name}: unreadable tool result")
        return result

    # -- plumbing ----------------------------------------------------------

    def _read_loop(self, proc: subprocess.Popen[str], inbox: queue.Queue[Any]) -> None:
        assert proc.stdout is not None
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(message, dict):
                continue
            if "method" in message and "id" in message:
                # The server is asking us something (roots, sampling). The proxy
                # offers none of that, so say so instead of leaving it waiting.
                with contextlib.suppress(DownstreamError):
                    self._send({
                        "jsonrpc": "2.0",
                        "id": message["id"],
                        "error": {"code": -32601, "message": "not supported by the proxy"},
                    })
                continue
            if message.get("method") == _LIST_CHANGED:
                self.tools_changed = True
                continue
            inbox.put(message)
        inbox.put(_EOF)

    def _send(self, message: Mapping[str, Any]) -> None:
        proc = self._proc
        if proc is None or proc.stdin is None or proc.poll() is not None:
            raise DownstreamNotRun(f"{self.name}: the server is not running")
        try:
            with self._write_lock:
                proc.stdin.write(json.dumps(message) + "\n")
                proc.stdin.flush()
        except (BrokenPipeError, OSError, ValueError) as exc:
            raise DownstreamNotRun(f"{self.name}: could not send ({exc})") from exc

    def _request(self, method: str, params: Mapping[str, Any]) -> Any:
        # One request at a time. The proxy handles calls in order, so this
        # costs nothing and keeps the reply matching simple.
        with self._call_lock:
            request_id = self._next_id
            self._next_id += 1
            self._send({"jsonrpc": "2.0", "id": request_id, "method": method, "params": dict(params)})
            deadline = time.monotonic() + self.timeout
            while True:
                remaining = deadline - time.monotonic()
                try:
                    if remaining <= 0:
                        raise queue.Empty
                    message = self._inbox.get(timeout=remaining)
                except queue.Empty:
                    raise DownstreamUnknown(
                        f"{self.name}: no answer to {method} within {self.timeout:g}s"
                    ) from None
                if message is _EOF:
                    self._inbox.put(_EOF)
                    raise DownstreamUnknown(f"{self.name}: the server exited during {method}")
                if message.get("id") != request_id:
                    continue  # a late answer to an older request
                if "error" in message:
                    error = message["error"] or {}
                    raise DownstreamNotRun(
                        f"{self.name}: {method} was rejected: {error.get('message', error)}"
                    )
                return message.get("result", {})


class _HttpRejected(DownstreamNotRun):
    """The server answered with an HTTP error status, so it did not run the call."""

    def __init__(self, message: str, status: int) -> None:
        super().__init__(message)
        self.status = status


class HttpDownstream:
    """Talks to a remote MCP server over Streamable HTTP.

    Each message is one POST. The answer is either one JSON body or an event
    stream that ends with the answer. Standard library only.
    """

    def __init__(
        self,
        name: str,
        url: str,
        headers: Mapping[str, str] | None = None,
        timeout: float = 30.0,
        oauth: Mapping[str, str] | None = None,
    ) -> None:
        self.name = name
        self.tools_changed = False
        self.url = url
        self._headers = dict(headers or {})
        self._oauth = dict(oauth or {})
        self._token: str | None = None
        self._token_expiry = 0.0
        self._force_refresh = False
        self._stopping = threading.Event()
        self._stream_socket: socket.socket | None = None
        self._listener: threading.Thread | None = None
        self.timeout = timeout
        self._session_id: str | None = None
        self._protocol = SUPPORTED_PROTOCOLS[-2]
        self._next_id = 1
        self._lock = threading.Lock()

    @classmethod
    def from_config(cls, config: ServerConfig) -> HttpDownstream:
        assert config.url is not None
        return cls(config.name, config.url, config.headers, config.timeout, config.oauth)

    def start(self) -> None:
        result = self._request(
            "initialize",
            {
                "protocolVersion": self._protocol,
                "capabilities": {},
                "clientInfo": {"name": "agent-action-gateway-proxy", "version": "0.2.0"},
            },
        )
        negotiated = result.get("protocolVersion") if isinstance(result, dict) else None
        if negotiated in SUPPORTED_PROTOCOLS:
            self._protocol = str(negotiated)
        self._post({"jsonrpc": "2.0", "method": "notifications/initialized"}, None, "initialized")
        if self._listener is None or not self._listener.is_alive():
            self._stopping.clear()
            self._listener = threading.Thread(target=self._listen, daemon=True)
            self._listener.start()

    def alive(self) -> bool:
        return True  # a remote server has no process of ours to check

    def _listen(self) -> None:
        """Hold the optional server-to-client stream open, to hear tool-list changes.

        A server that has no such stream answers 405 (or similar) and we stop. A
        dropped stream is reopened after a short wait. A plain `http.client`
        connection is used so `close()` can shut its socket and wake this thread.
        """
        parsed = urllib.parse.urlparse(self.url)
        connect = (
            http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
        )
        target = parsed.path or "/"
        if parsed.query:
            target += "?" + parsed.query
        while not self._stopping.is_set():
            connection = connect(parsed.netloc, timeout=300)
            try:
                headers = {**self._request_headers(), "Accept": "text/event-stream"}
                connection.request("GET", target, headers=headers)
                # Kept now: after `getresponse` the connection may let go of it.
                self._stream_socket = connection.sock
                response = connection.getresponse()
                if 400 <= response.status < 500:
                    return  # no stream on this server, or this session is gone
                if response.status == 200 and response.getheader("Content-Type", "").startswith(
                    "text/event-stream"
                ):
                    self._read_events(response)
            except (OSError, http.client.HTTPException, DownstreamError):
                pass
            finally:
                self._stream_socket = None
                connection.close()
            self._stopping.wait(2.0)

    def _read_events(self, response: Any) -> None:
        data: list[str] = []
        for raw in response:
            if self._stopping.is_set():
                return
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            if line == "":
                if data:
                    with contextlib.suppress(json.JSONDecodeError):
                        message = json.loads("\n".join(data))
                        if isinstance(message, dict) and message.get("method") == _LIST_CHANGED:
                            self.tools_changed = True
                    data.clear()
            elif line.startswith("data:"):
                data.append(line[5:].lstrip(" "))

    def close(self) -> None:
        self._stopping.set()
        stream_socket = self._stream_socket
        if stream_socket is not None:
            # Waking the thread that is blocked reading the stream: closing the
            # response from here would wait for that read to finish.
            with contextlib.suppress(OSError):
                stream_socket.shutdown(socket.SHUT_RDWR)
        if self._session_id is None:
            return
        request = urllib.request.Request(self.url, method="DELETE", headers=self._request_headers())
        with contextlib.suppress(Exception):
            urllib.request.urlopen(request, timeout=5).close()  # noqa: S310
        self._session_id = None

    def list_tools(self) -> list[dict[str, Any]]:
        tools: list[dict[str, Any]] = []
        cursor: str | None = None
        while True:
            result = self._request("tools/list", {"cursor": cursor} if cursor else {})
            tools.extend(result.get("tools", []))
            cursor = result.get("nextCursor")
            if not cursor:
                return tools

    def call_tool(
        self, tool: str, arguments: Mapping[str, Any], meta: Mapping[str, Any] | None = None
    ) -> dict[str, Any]:
        params: dict[str, Any] = {"name": tool, "arguments": dict(arguments)}
        if meta:
            params["_meta"] = dict(meta)
        result = self._request("tools/call", params)
        if not isinstance(result, dict):
            raise DownstreamNotRun(f"{self.name}: unreadable tool result")
        return result

    # -- plumbing ----------------------------------------------------------

    def _bearer(self) -> str | None:
        """An OAuth access token, fetched or refreshed when needed."""
        if not self._oauth:
            return None
        if self._token and time.monotonic() < self._token_expiry:
            return self._token
        if self._oauth.get("flow") == "authorization_code":
            token, lifetime = self._signed_in_token()
        else:
            token, lifetime = self._client_credentials_token()
        self._token = token
        self._token_expiry = time.monotonic() + max(lifetime - 30.0, 1.0)
        return token

    def _token_request(self, form: Mapping[str, str]) -> dict[str, Any]:
        request = urllib.request.Request(
            self._oauth["token_url"],
            data=urllib.parse.urlencode(form).encode("ascii"),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
            method="POST",
        )
        try:
            # The URL comes from the operator's config and is checked to be http(s).
            with urllib.request.urlopen(request, timeout=self.timeout) as response:  # noqa: S310
                body = json.loads(response.read())
            if not isinstance(body, dict) or "access_token" not in body:
                raise KeyError("access_token")
            return body
        except (OSError, ValueError, KeyError, TypeError) as exc:
            # Never include the form: it holds secrets.
            raise DownstreamNotRun(
                f"{self.name}: could not get an OAuth token ({type(exc).__name__})"
            ) from exc

    def _client_credentials_token(self) -> tuple[str, float]:
        form = {
            "grant_type": "client_credentials",
            "client_id": self._oauth["client_id"],
            "client_secret": self._oauth["client_secret"],
        }
        if self._oauth.get("scope"):
            form["scope"] = self._oauth["scope"]
        body = self._token_request(form)
        return str(body["access_token"]), float(body.get("expires_in", 300))

    def _signed_in_token(self) -> tuple[str, float]:
        """The token a person signed in with (`mcp-login`), refreshed when it is old."""
        path = Path(self._oauth["token_file"])
        tokens = read_token_file(path)
        if tokens is None:
            raise DownstreamNotRun(
                f"{self.name}: not signed in. Run: agent-gateway mcp-login "
                f"--config <your config> --server {self.name}"
            )
        for key in ("token_url", "client_id", "client_secret"):
            if tokens.get(key) and not self._oauth.get(key):
                self._oauth[key] = str(tokens[key])  # found by `mcp-login`
        remaining = float(tokens.get("expires_at", 0)) - time.time()
        if remaining > 30 and not self._force_refresh:
            return str(tokens["access_token"]), remaining
        refresh = tokens.get("refresh_token")
        if not refresh:
            raise DownstreamNotRun(
                f"{self.name}: the sign-in expired and has no refresh token. Run: "
                f"agent-gateway mcp-login --config <your config> --server {self.name}"
            )
        form = {
            "grant_type": "refresh_token",
            "refresh_token": str(refresh),
            "client_id": self._oauth["client_id"],
        }
        if self._oauth.get("client_secret"):
            form["client_secret"] = self._oauth["client_secret"]
        body = self._token_request(form)
        self._force_refresh = False
        lifetime = float(body.get("expires_in", 300))
        write_token_file(path, {
            **{k: v for k, v in tokens.items() if k in _KEPT_TOKEN_FIELDS},
            "access_token": str(body["access_token"]),
            # A server may rotate the refresh token; if it did not, keep ours.
            "refresh_token": str(body.get("refresh_token", refresh)),
            "expires_at": time.time() + lifetime,
        })
        return str(body["access_token"]), lifetime

    def _request_headers(self) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": self._protocol,
            **self._headers,
        }
        bearer = self._bearer()
        if bearer:
            headers["Authorization"] = f"Bearer {bearer}"
        if self._session_id:
            headers["Mcp-Session-Id"] = self._session_id
        return headers

    def _request(self, method: str, params: Mapping[str, Any]) -> Any:
        with self._lock:
            request_id = self._next_id
            self._next_id += 1
        message = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": dict(params)}
        return self._post(message, request_id, method)

    def _post(
        self,
        message: Mapping[str, Any],
        request_id: int | None,
        method: str,
        *,
        retried: bool = False,
    ) -> Any:
        """Send one message. Two refusals are safe to retry once, because in both
        the server did not act on the message: an unknown session (404) gets a
        fresh session, and a rejected token (401) gets a fresh token."""
        try:
            return self._post_once(message, request_id, method)
        except _HttpRejected as exc:
            if retried:
                raise
            if exc.status == 404 and self._session_id and method != "initialize":
                self._session_id = None
                self.start()
                return self._post(message, request_id, method, retried=True)
            if exc.status == 401 and self._oauth:
                self._token = None
                self._force_refresh = True
                return self._post(message, request_id, method, retried=True)
            raise

    def _post_once(self, message: Mapping[str, Any], request_id: int | None, method: str) -> Any:
        request = urllib.request.Request(
            self.url,
            data=json.dumps(message).encode("utf-8"),
            headers=self._request_headers(),
            method="POST",
        )
        try:
            # The URL comes from the operator's config and is checked to be http(s).
            with urllib.request.urlopen(request, timeout=self.timeout) as response:  # noqa: S310
                session_id = response.headers.get("Mcp-Session-Id")
                if session_id:
                    self._session_id = session_id
                if request_id is None or response.status == 202:
                    return None
                content_type = response.headers.get("Content-Type", "")
                if content_type.startswith("text/event-stream"):
                    return self._from_stream(response, request_id, method)
                return self._unwrap(self._load(response.read()), request_id, method)
        except urllib.error.HTTPError as exc:
            detail = f"{self.name}: {method} got HTTP {exc.code}"
            # A 5xx on a call may have come after the tool ran.
            if exc.code >= 500 and method == "tools/call":
                raise DownstreamUnknown(detail) from exc
            raise _HttpRejected(detail, exc.code) from exc
        except urllib.error.URLError as exc:
            reason = exc.reason
            if isinstance(reason, ConnectionRefusedError | socket.gaierror):
                raise DownstreamNotRun(f"{self.name}: cannot reach {self.url}: {reason}") from exc
            raise DownstreamUnknown(f"{self.name}: {method} failed: {reason}") from exc
        except (TimeoutError, OSError) as exc:
            raise DownstreamUnknown(f"{self.name}: {method} failed: {exc}") from exc

    def _load(self, body: bytes) -> Any:
        try:
            return json.loads(body)
        except json.JSONDecodeError as exc:
            raise DownstreamNotRun(f"{self.name}: the server sent unreadable JSON") from exc

    def _unwrap(self, message: Any, request_id: int, method: str) -> Any:
        items = message if isinstance(message, list) else [message]
        for item in items:
            if isinstance(item, dict) and item.get("id") == request_id:
                if "error" in item:
                    error = item["error"] or {}
                    raise DownstreamNotRun(
                        f"{self.name}: {method} was rejected: {error.get('message', error)}"
                    )
                return item.get("result", {})
        raise DownstreamUnknown(f"{self.name}: no answer to {method} in the response")

    def _from_stream(self, response: Any, request_id: int, method: str) -> Any:
        data: list[str] = []

        def finish() -> Any:
            if not data:
                return None
            text = "\n".join(data)
            data.clear()
            try:
                message = json.loads(text)
            except json.JSONDecodeError:
                return None
            if isinstance(message, dict):
                if message.get("method") == _LIST_CHANGED:
                    self.tools_changed = True
                elif message.get("id") == request_id:
                    return self._unwrap(message, request_id, method)
            return None

        for raw in response:
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            if line == "":
                found = finish()
                if found is not None:
                    return found
            elif line.startswith("data:"):
                data.append(line[5:].lstrip(" "))
        found = finish()
        if found is not None:
            return found
        raise DownstreamUnknown(f"{self.name}: the stream ended before the answer to {method}")


def default_downstream(config: ServerConfig) -> Downstream:
    """Build (but do not start) the right kind of client for a server."""
    return HttpDownstream.from_config(config) if config.url else StdioDownstream.from_config(config)


# --------------------------------------------------------------------------
# signing in (OAuth authorization code with PKCE)
# --------------------------------------------------------------------------


def read_token_file(path: Path) -> dict[str, Any] | None:
    """The saved sign-in, or None if there is none. Refuses a file others can read."""
    try:
        mode = path.stat().st_mode
    except FileNotFoundError:
        return None
    if mode & 0o077:
        raise DownstreamNotRun(
            f"{path} holds a sign-in and must be readable by you only "
            f"(mode {oct(mode & 0o777)}); run: chmod 600 {path}"
        )
    try:
        tokens = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DownstreamNotRun(f"{path} is not a readable sign-in file") from exc
    return tokens if isinstance(tokens, dict) and tokens.get("access_token") else None


def write_token_file(path: Path, tokens: Mapping[str, Any]) -> None:
    """Save a sign-in with mode 0600, replacing the old file in one step."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(dict(tokens), handle)
    os.replace(temporary, path)


_KEPT_TOKEN_FIELDS = ("token_url", "client_id", "client_secret")


class SignInError(Exception):
    """The sign-in did not finish. The message says why and is safe to print."""


def _get_json(url: str, timeout: float, *, data: bytes | None = None) -> Any:
    """Fetch (or post) JSON from a discovery address. Returns None when not found."""
    request = urllib.request.Request(
        url,
        data=data,
        method="POST" if data is not None else "GET",
        headers={"Accept": "application/json", "Content-Type": "application/json"},
    )
    try:
        # Addresses are checked by `_web_origin` before this is called.
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            return json.loads(response.read())
    except urllib.error.HTTPError:
        return None
    except (OSError, ValueError) as exc:
        raise SignInError(f"could not read {_origin(url)} ({type(exc).__name__})") from exc


def _origin(url: str) -> str:
    parts = urllib.parse.urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


def _trusted_address(url: str, what: str) -> str:
    """A discovered address must be https, or http only to this machine."""
    parts = urllib.parse.urlsplit(url)
    local = (parts.hostname or "") in ("localhost", "127.0.0.1", "::1")
    if parts.scheme == "https" or (parts.scheme == "http" and local):
        return url
    raise SignInError(f"the server gave an unsafe {what} address ({_origin(url)}); not using it")


def discover_oauth(server_url: str, timeout: float = 30.0) -> dict[str, str]:
    """Find a remote server's sign-in endpoints, the way the MCP spec describes.

    1. Ask the server something without a token. A 401 may name its metadata
       (RFC 9728 `resource_metadata`); otherwise try the well-known address.
    2. That metadata names the authorization server. Read its metadata
       (RFC 8414, then OpenID Connect) for the authorize, token and registration
       addresses.
    """
    origin = _origin(server_url)
    path = urllib.parse.urlsplit(server_url).path.rstrip("/")
    metadata_url = None
    probe = urllib.request.Request(
        server_url,
        data=json.dumps({"jsonrpc": "2.0", "id": 0, "method": "ping"}).encode(),
        method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json, text/event-stream"},
    )
    try:
        urllib.request.urlopen(probe, timeout=timeout).close()  # noqa: S310
    except urllib.error.HTTPError as exc:
        challenge = exc.headers.get("WWW-Authenticate", "") if exc.code == 401 else ""
        found = re.search(r'resource_metadata="([^"]+)"', challenge)
        metadata_url = found.group(1) if found else None
    except OSError as exc:
        raise SignInError(f"could not reach {origin} ({type(exc).__name__})") from exc
    candidates = [metadata_url] if metadata_url else []
    candidates += [
        f"{origin}/.well-known/oauth-protected-resource{path}",
        f"{origin}/.well-known/oauth-protected-resource",
    ]
    issuer = origin  # when the server names none, it is its own authorization server
    for candidate in candidates:
        resource = _get_json(_trusted_address(candidate, "metadata"), timeout)
        if isinstance(resource, dict) and resource.get("authorization_servers"):
            issuer = str(resource["authorization_servers"][0])
            break
    issuer = _trusted_address(issuer, "authorization server").rstrip("/")
    issuer_path = urllib.parse.urlsplit(issuer).path
    root = _origin(issuer)
    for address in (
        f"{root}/.well-known/oauth-authorization-server{issuer_path}",
        f"{issuer}/.well-known/openid-configuration",
    ):
        meta = _get_json(address, timeout)
        if isinstance(meta, dict) and meta.get("authorization_endpoint") and meta.get("token_endpoint"):
            methods = meta.get("code_challenge_methods_supported")
            if methods is not None and "S256" not in methods:
                raise SignInError("the server does not support PKCE with S256")
            result = {
                "authorization_endpoint": _trusted_address(
                    str(meta["authorization_endpoint"]), "sign-in"
                ),
                "token_endpoint": _trusted_address(str(meta["token_endpoint"]), "token"),
            }
            if meta.get("registration_endpoint"):
                result["registration_endpoint"] = _trusted_address(
                    str(meta["registration_endpoint"]), "registration"
                )
            return result
    raise SignInError(
        f"could not find the sign-in endpoints of {origin}; "
        "set oauth 'authorization_url', 'token_url' and 'client_id' yourself"
    )


def register_client(endpoint: str, redirect_uri: str, timeout: float = 30.0) -> tuple[str, str]:
    """Register this proxy as a public client (RFC 7591). Returns (client_id, secret or "")."""
    body = json.dumps({
        "client_name": "agent-action-gateway MCP proxy",
        "redirect_uris": [redirect_uri],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
    }).encode()
    reply = _get_json(endpoint, timeout, data=body)
    if not isinstance(reply, dict) or not reply.get("client_id"):
        raise SignInError("the server refused to register a client")
    return str(reply["client_id"]), str(reply.get("client_secret", ""))


def sign_in(
    config: ServerConfig,
    *,
    open_browser: Any = None,
    timeout: float = 300.0,
) -> Path:
    """Sign a person in to a remote server: OAuth authorization code with PKCE.

    Starts a listener on 127.0.0.1, sends the person to the server's sign-in page,
    waits for the redirect back, swaps the code for tokens and saves them (mode
    0600) in the configured `token_file`. The proxy then uses and refreshes them.
    """
    import base64
    import http.server
    import secrets
    import webbrowser

    oauth = dict(config.oauth)
    if oauth.get("flow") != "authorization_code":
        raise SignInError(f"{config.name!r} does not use the authorization_code flow")
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
    state = secrets.token_urlsafe(16)
    outcome: dict[str, str] = {}
    done = threading.Event()

    class Callback(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args: object) -> None:  # noqa: ARG002
            return

        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path != "/callback":
                self.send_error(404)
                return
            query = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}
            if query.get("state") != state:
                outcome["error"] = "the sign-in answer did not match this request (wrong state)"
            elif "error" in query:
                outcome["error"] = f"the server refused the sign-in: {query['error']}"
            elif "code" in query:
                outcome["code"] = query["code"]
            else:
                outcome["error"] = "the sign-in answer had no code"
            body = b"You can close this tab and return to the terminal."
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            done.set()

    listener = http.server.ThreadingHTTPServer(
        ("127.0.0.1", int(oauth.get("redirect_port", 0))), Callback
    )
    redirect_uri = f"http://127.0.0.1:{listener.server_address[1]}/callback"
    threading.Thread(target=listener.serve_forever, daemon=True).start()
    try:
        if not (oauth.get("authorization_url") and oauth.get("token_url")):
            found = discover_oauth(str(config.url), config.timeout)
            oauth.setdefault("authorization_url", found["authorization_endpoint"])
            oauth.setdefault("token_url", found["token_endpoint"])
            oauth.setdefault("registration_endpoint", found.get("registration_endpoint", ""))
            say(f"found the sign-in endpoints of {config.name!r} from the server")
        if not oauth.get("client_id"):
            if not oauth.get("registration_endpoint"):
                found = discover_oauth(str(config.url), config.timeout)
                oauth["registration_endpoint"] = found.get("registration_endpoint", "")
            if not oauth["registration_endpoint"]:
                raise SignInError(
                    f"{config.name!r}: the server does not register clients by itself; "
                    "set oauth 'client_id' (and 'client_secret' if it has one)"
                )
            oauth["client_id"], registered_secret = register_client(
                oauth["registration_endpoint"], redirect_uri, config.timeout
            )
            if registered_secret:
                oauth["client_secret"] = registered_secret
            say(f"registered {config.name!r} as a client of the server")
        query = {
            "response_type": "code",
            "client_id": oauth["client_id"],
            "redirect_uri": redirect_uri,
            "state": state,
            "code_challenge": challenge.rstrip(b"=").decode("ascii"),
            "code_challenge_method": "S256",
        }
        if oauth.get("scope"):
            query["scope"] = oauth["scope"]
        separator = "&" if "?" in oauth["authorization_url"] else "?"
        url = oauth["authorization_url"] + separator + urllib.parse.urlencode(query)
        say(f"sign in to {config.name!r} in your browser: {url}")
        (open_browser or webbrowser.open)(url)
        if not done.wait(timeout):
            raise SignInError(f"no sign-in answer within {timeout:g} seconds")
    finally:
        listener.shutdown()
        listener.server_close()
    if "error" in outcome:
        raise SignInError(outcome["error"])

    form = {
        "grant_type": "authorization_code",
        "code": outcome["code"],
        "redirect_uri": redirect_uri,
        "client_id": oauth["client_id"],
        "code_verifier": verifier,
    }
    if oauth.get("client_secret"):
        form["client_secret"] = oauth["client_secret"]
    downstream = HttpDownstream(
        config.name, str(config.url), config.headers, config.timeout, oauth
    )
    try:
        body = downstream._token_request(form)
    except DownstreamError as exc:
        raise SignInError(str(exc)) from exc
    path = Path(oauth["token_file"])
    saved = {
        "access_token": str(body["access_token"]),
        "refresh_token": str(body.get("refresh_token", "")),
        "expires_at": time.time() + float(body.get("expires_in", 300)),
    }
    for key in _KEPT_TOKEN_FIELDS:  # the proxy needs these to refresh later
        if oauth.get(key) and not config.oauth.get(key):
            saved[key] = str(oauth[key])
    write_token_file(path, saved)
    return path


# --------------------------------------------------------------------------
# pinned tool definitions
# --------------------------------------------------------------------------


def definition_hash(definition: Mapping[str, Any]) -> str:
    """A fingerprint of everything a server says about one tool."""
    canonical = json.dumps(definition, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _now() -> str:
    from datetime import UTC, datetime

    return datetime.now(UTC).isoformat()


class PinStore(Store):
    """The definition each tool had when a person (or first use) accepted it."""

    store_name = "mcp_tool_pins"

    def _migrations(self) -> Any:
        yield 1, [
            """
            CREATE TABLE IF NOT EXISTS mcp_tool_pins (
                tool TEXT PRIMARY KEY,
                server TEXT NOT NULL,
                definition_hash TEXT,
                pending_hash TEXT,
                updated_at TEXT NOT NULL,
                accepted_by TEXT
            );
            """
        ]

    def pinned(self, tool: str) -> str | None:
        with self.connection() as connection:
            row = connection.execute(
                "SELECT definition_hash FROM mcp_tool_pins WHERE tool = ?", (tool,)
            ).fetchone()
        return None if row is None else row["definition_hash"]

    def server_has_pins(self, server: str) -> bool:
        with self.connection() as connection:
            row = connection.execute(
                "SELECT 1 AS one FROM mcp_tool_pins "
                "WHERE server = ? AND definition_hash IS NOT NULL LIMIT 1",
                (server,),
            ).fetchone()
        return row is not None

    def pin(self, tool: str, server: str, digest: str, by: str) -> None:
        with self.connection() as connection:
            connection.execute(
                "INSERT INTO mcp_tool_pins (tool, server, definition_hash, pending_hash, "
                "updated_at, accepted_by) VALUES (?, ?, ?, NULL, ?, ?) "
                "ON CONFLICT(tool) DO UPDATE SET definition_hash = excluded.definition_hash, "
                "pending_hash = NULL, updated_at = excluded.updated_at, "
                "accepted_by = excluded.accepted_by",
                (tool, server, digest, _now(), by),
            )

    def hold(self, tool: str, server: str, digest: str) -> None:
        """Record that this tool's current definition is waiting for a person."""
        with self.connection() as connection:
            connection.execute(
                "INSERT INTO mcp_tool_pins (tool, server, definition_hash, pending_hash, "
                "updated_at) VALUES (?, ?, NULL, ?, ?) "
                "ON CONFLICT(tool) DO UPDATE SET pending_hash = excluded.pending_hash, "
                "updated_at = excluded.updated_at",
                (tool, server, digest, _now()),
            )

    def waiting(self) -> list[tuple[str, str]]:
        """(tool, why) for each tool waiting for a person."""
        with self.connection() as connection:
            rows = connection.execute(
                "SELECT tool, definition_hash FROM mcp_tool_pins "
                "WHERE pending_hash IS NOT NULL ORDER BY tool"
            ).fetchall()
        return [
            (row["tool"], "new tool" if row["definition_hash"] is None else "definition changed")
            for row in rows
        ]

    def accept(self, who: str, tool: str | None = None) -> list[str]:
        """Accept what is waiting (one tool, or all). Returns the tools accepted."""
        names = [t for t, _ in self.waiting() if tool is None or t == tool]
        with self.connection() as connection:
            for name in names:
                connection.execute(
                    "UPDATE mcp_tool_pins SET definition_hash = pending_hash, "
                    "pending_hash = NULL, updated_at = ?, accepted_by = ? WHERE tool = ?",
                    (_now(), who, name),
                )
        return names


# --------------------------------------------------------------------------
# the proxy
# --------------------------------------------------------------------------


@dataclass
class ProxiedTool:
    name: str  # what the agent sees: server__tool
    server: str
    tool: str  # what the real server calls it
    risk: str
    risk_source: str  # rule | hint | default
    definition: dict[str, Any]
    guarded: Any
    required: tuple[str, ...] = ()
    digest: str = ""


def classify(
    name: str,
    annotations: Mapping[str, Any] | None,
    rules: Sequence[Rule],
    trust_hints: bool,
) -> tuple[str, str]:
    """Risk class for one tool, and why. Anything unclear is destructive."""
    for rule in rules:
        if fnmatch.fnmatchcase(name, rule.match):
            return rule.risk, "rule"
    hints = annotations or {}
    if trust_hints and hints.get("readOnlyHint") is True and hints.get("destructiveHint") is not True:
        return "read", "hint"
    return "destructive", "default"


def _result_text(payload: Any) -> str | None:
    """The redacted result, as text to keep with the receipt (None if too big)."""
    try:
        text = json.dumps(redact(payload), default=str)
    except (TypeError, ValueError):
        return None
    return text if len(text.encode("utf-8")) <= MAX_STORED_RESULT_BYTES else None


def _never_called(**_: Any) -> None:
    """Stands in for the tool function: calls go through `guarded.call_with`."""


class MCPProxy:
    """Merges downstream tools and guards every call to them."""

    def __init__(
        self,
        downstreams: Mapping[str, Downstream],
        session: SafetySession,
        *,
        configs: Mapping[str, ServerConfig] | None = None,
        rules: Sequence[Rule] = (),
        require: Sequence[Requirement] = (),
        pins: PinStore | None = None,
        factory: Any = default_downstream,
    ) -> None:
        self.downstreams = dict(downstreams)
        self.session = session
        self.configs = dict(configs or {})
        self.rules = tuple(rules)
        self.require = tuple(require)
        self.pins = pins
        self.factory = factory
        self.tools: dict[str, ProxiedTool] = {}
        #: Tools hidden until a person accepts them: name -> reason.
        self.held: dict[str, str] = {}
        self._definitions: dict[str, list[dict[str, Any]]] = {}
        self._signature: tuple[tuple[str, str], ...] = ()
        self._asks: dict[tuple[str, tuple[str, ...]], int] = {}
        self._restarts: dict[str, list[float]] = {}
        self._lock = threading.RLock()
        for server, downstream in self.downstreams.items():
            self._definitions[server] = downstream.list_tools()
        self._rebuild()

    # -- building the tool list -------------------------------------------

    def _rebuild(self) -> bool:
        """Rebuild the visible tools from the stored definitions.

        Returns True when the set of visible tools (or any definition) changed.
        """
        tools: dict[str, ProxiedTool] = {}
        held: dict[str, str] = {}
        for server, definitions in self._definitions.items():
            config = self.configs.get(server)
            trust = config.trust_hints if config else True
            target_env = config.environment if config else None
            had_pins = self.pins.server_has_pins(server) if self.pins else False
            for definition in definitions:
                real = str(definition.get("name", ""))
                if not real:
                    continue
                name = f"{server}{SEPARATOR}{real}"
                digest = definition_hash(definition)
                reason = self._check_pin(server, name, digest, had_pins)
                if reason is not None:
                    held[name] = reason
                    continue
                risk, source = classify(name, definition.get("annotations"), self.rules, trust)
                guarded = self.session.tool(
                    _never_called, action=name, risk=risk, target_environment=target_env
                )
                public = dict(definition)
                public["name"] = name
                tools[name] = ProxiedTool(
                    name, server, real, risk, source, public, guarded,
                    self._required_for(name, definition), digest,
                )
        self.tools = tools
        self.held = held
        signature = tuple(sorted((t.name, t.digest) for t in tools.values()))
        changed = signature != self._signature
        self._signature = signature
        return changed

    def _check_pin(self, server: str, name: str, digest: str, had_pins: bool) -> str | None:
        if self.pins is None:
            return None
        pinned = self.pins.pinned(name)
        if pinned == digest:
            return None
        if pinned is None and not had_pins:
            self.pins.pin(name, server, digest, "first use")
            return None
        self.pins.hold(name, server, digest)
        return "its definition changed" if pinned is not None else "it is new on a pinned server"

    def _required_for(self, name: str, definition: Mapping[str, Any]) -> tuple[str, ...]:
        required: list[str] = []
        schema = definition.get("inputSchema")
        if isinstance(schema, Mapping) and isinstance(schema.get("required"), list):
            required.extend(str(r) for r in schema["required"])
        for entry in self.require:
            if fnmatch.fnmatchcase(name, entry.match):
                required.extend(entry.arguments)
        return tuple(dict.fromkeys(required))

    def describe(self) -> list[tuple[str, str, str]]:
        """(tool, risk, why) for each visible tool, for the start-up summary."""
        with self._lock:
            return [(t.name, t.risk, t.risk_source) for t in self.tools.values()]

    def report_held(self) -> list[tuple[str, str]]:
        with self._lock:
            return sorted(self.held.items())

    # -- keeping up with changes -------------------------------------------

    def poll(self) -> bool:
        """Pick up servers that said their tools changed, and tools a person accepted.

        Returns True when the visible tool list changed.
        """
        with self._lock:
            refetch = [s for s, d in self.downstreams.items() if d.tools_changed]
            for server in refetch:
                downstream = self.downstreams[server]
                downstream.tools_changed = False
                try:
                    self._definitions[server] = downstream.list_tools()
                except DownstreamError as exc:
                    say(f"cannot refresh the tools of {server!r}: {exc}")
            if not refetch and not self.held:
                return False
            before = dict(self.held)
            changed = self._rebuild()
            self._announce_held(before)
            return changed

    def reload(self, config: ProxyConfig) -> bool:
        """Apply a changed config without a restart. All or nothing.

        Servers are added, removed or restarted as needed. If a new server
        cannot start, nothing changes. Returns True when the visible tool list
        changed. Environment and limits belong to the running session, so a
        change to them needs a restart.
        """
        with self._lock:
            if config.environment != self.session.environment:
                say("the 'environment' changed: restart the proxy for that to apply")
            if config.limits != self.session.limits:
                say("'limits' changed: restart the proxy for that to apply")
            wanted = {s.name: s for s in config.servers}
            started: dict[str, Downstream] = {}
            fetched: dict[str, list[dict[str, Any]]] = {}
            try:
                for name, server in wanted.items():
                    if self.configs.get(name) == server and name in self.downstreams:
                        continue
                    downstream = self.factory(server)
                    started[name] = downstream
                    downstream.start()
                    fetched[name] = downstream.list_tools()
            except DownstreamError:
                for running in started.values():
                    running.close()
                raise
            for name in set(self.downstreams) - set(wanted):
                self.downstreams.pop(name).close()
                self._definitions.pop(name, None)
            for name, downstream in started.items():
                old = self.downstreams.get(name)
                if old is not None:
                    old.close()
                self.downstreams[name] = downstream
                self._definitions[name] = fetched[name]
            self.configs = dict(wanted)
            self.rules = config.rules
            self.require = config.require
            before = dict(self.held)
            changed = self._rebuild()
            self._announce_held(before)
            return changed

    def _announce_held(self, before: Mapping[str, str]) -> None:
        for name, reason in sorted(self.held.items()):
            if name not in before:
                say(
                    f"{name} is hidden and refused: {reason}. "
                    "Accept it with: agent-gateway mcp-pins accept"
                )

    # -- MCP: tools/list and tools/call -------------------------------------

    def list_tools(self) -> list[dict[str, Any]]:
        with self._lock:
            return [t.definition for t in self.tools.values()]

    def call_tool(
        self,
        name: str,
        arguments: Mapping[str, Any] | None = None,
        *,
        approval_id: str | None = None,
    ) -> dict[str, Any]:
        with self._lock:
            entry = self.tools.get(name)
            if entry is None:
                if name in self.held:
                    return _error(
                        f"tool not available: {name} ({self.held[name]}; a person must accept it)"
                    )
                return _error(f"tool not available: {name}")

            args = dict(arguments or {})
            missing = [n for n in entry.required if args.get(n) in (None, "")]
            if missing:
                return self._ask(entry, missing)

            approvals = self.session.approvals
            if approval_id is None and entry.risk != "read":
                usable = approvals.find_usable(name, args)
                if usable is not None:
                    approval_id = usable.approval_id

            if not self.downstreams[entry.server].alive():
                try:
                    self._restart(entry.server)
                except DownstreamError as exc:
                    return _error(f"the tool did not run: {exc}")
                entry = self.tools.get(name)
                if entry is None:
                    return _error(
                        f"tool not available: {name} "
                        f"({self.held.get(name, 'it is gone')}; a person must accept it)"
                    )
            downstream = self.downstreams[entry.server]

            def call(intent_key: str | None) -> dict[str, Any]:
                meta = {INTENT_META_KEY: intent_key} if intent_key else None
                result = downstream.call_tool(entry.tool, args, meta)
                if result.get("isError"):
                    raise ToolReportedError(result)
                return result

            try:
                outcome = entry.guarded.call_with(
                    args, call, approval_id=approval_id, describe=_result_text
                )
            except ToolReportedError as exc:
                return exc.result
            except DownstreamNotRun as exc:
                return _error(f"the tool did not run: {exc}")
            except DownstreamUnknown as exc:
                self._keep_unknown()
                return _error(
                    f"the result is unknown: {exc}. The action may or may not have happened; "
                    "check the real system before trying again. The attempt is held as unfinished."
                )

            if outcome.get("status") == "blocked":
                return self._blocked(entry, args, outcome)
            if outcome.get("decision") == "DEDUPLICATED":
                return _repeat(outcome)
            result = outcome.get("result")
            if isinstance(result, dict) and "content" in result:
                return result
            return {
                "content": [{"type": "text", "text": json.dumps(result, default=str)}],
                "isError": False,
            }

    def _restart(self, server: str) -> None:
        """Start a local server that has died, then check its tools again.

        The call that found it dead has not been sent, so nothing is repeated.
        The tools are read again and checked against their pins, because a
        server that comes back may not be the same one. A server that keeps
        dying is not restarted forever.
        """
        now = time.monotonic()
        recent = [t for t in self._restarts.get(server, []) if now - t < 60.0]
        if len(recent) >= MAX_RESTARTS_PER_MINUTE:
            raise DownstreamNotRun(
                f"{server}: the server keeps stopping ({MAX_RESTARTS_PER_MINUTE} restarts "
                "in the last minute), so it is not being restarted again"
            )
        self._restarts[server] = [*recent, now]
        say(f"{server!r} is not running: restarting it")
        downstream = self.downstreams[server]
        downstream.close()
        downstream.start()
        self._definitions[server] = downstream.list_tools()
        before = dict(self.held)
        self._rebuild()
        self._announce_held(before)

    def _ask(self, entry: ProxiedTool, missing: list[str]) -> dict[str, Any]:
        """Refuse a call that lacks required input, and tell the agent to ask."""
        key = (entry.name, tuple(missing))
        self._asks[key] = self._asks.get(key, 0) + 1
        self.session.store.append_trace(
            TraceEvent(
                self.session.run_id, 0, "validation", entry.name, list(missing), "ask"
            )
        )
        repeated = ""
        if self._asks[key] > 1:
            repeated = (
                f" This is attempt {self._asks[key]} without it: stop and ask the user "
                "instead of trying again."
            )
        return _error(
            f"more information is needed before {entry.name} can run: missing "
            f"{', '.join(missing)}. Ask the user for it. Do not guess or fill in a "
            f"default.{repeated}"
        )

    def _keep_unknown(self) -> None:
        if not self.session.decisions:
            return
        key = self.session.decisions[-1].intent_key
        if key is not None:
            self.session.store.mark_outcome_unknown(key)

    def _blocked(
        self, entry: ProxiedTool, args: dict[str, Any], outcome: Mapping[str, Any]
    ) -> dict[str, Any]:
        reason = str(outcome.get("error") or outcome.get("decision") or "blocked")
        if outcome.get("needs_approval"):
            approvals = self.session.approvals
            pending = approvals.find_pending(entry.name, args)
            if pending is None:
                pending = self.session.request_approval(entry.name, args)
            return _error(
                f"blocked: {entry.name} needs a person's approval before it runs. "
                f"Approval id: {pending.approval_id}. Ask the operator to approve it "
                "(agent-gateway dashboard), then call this tool again with exactly the "
                "same arguments. The approval works once, for these arguments only."
            )
        return _error(f"blocked ({outcome.get('decision')}): {reason}")

    def close(self) -> None:
        with self._lock:
            for downstream in self.downstreams.values():
                downstream.close()


def _error(message: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": message}], "isError": True}


def _repeat(outcome: Mapping[str, Any]) -> dict[str, Any]:
    """The answer to an action that already ran: its first result, when kept."""
    stored = None
    result = outcome.get("result")
    if isinstance(result, Mapping) and isinstance(result.get("provider_ref"), str):
        with contextlib.suppress(json.JSONDecodeError):
            stored = json.loads(result["provider_ref"])
    if isinstance(stored, dict) and "content" in stored:
        note = {
            "type": "text",
            "text": "This exact action already ran, so it was not run again. "
                    "Below is a redacted copy of its first result.",
        }
        return {**stored, "content": [note, *stored["content"]], "isError": False}
    return {
        "content": [{
            "type": "text",
            "text": "This exact action already ran earlier, so it was not run again. "
                    "Its first result was not kept.",
        }],
        "isError": False,
    }


# --------------------------------------------------------------------------
# the MCP server the agent talks to
# --------------------------------------------------------------------------


class ProxyServer:
    """JSON-RPC over newline-delimited stdio, answering for the proxy."""

    def __init__(self, proxy: MCPProxy) -> None:
        self.proxy = proxy
        self._out: TextIO | None = None
        self._write_lock = threading.Lock()
        self._initialized = False

    def handle(self, message: Mapping[str, Any]) -> dict[str, Any] | None:
        method = message.get("method")
        request_id = message.get("id")
        params = message.get("params") or {}

        if method == "initialize":
            wanted = str(params.get("protocolVersion", ""))
            version = wanted if wanted in SUPPORTED_PROTOCOLS else SUPPORTED_PROTOCOLS[-1]
            return _rpc(request_id, {
                "protocolVersion": version,
                "capabilities": {"tools": {"listChanged": True}},
                "serverInfo": {"name": "agent-action-gateway", "version": "0.2.0"},
            })
        if method == "notifications/initialized":
            self._initialized = True
            return None
        if method == "ping":
            return _rpc(request_id, {})
        if method == "tools/list":
            self.proxy.poll()
            return _rpc(request_id, {"tools": self.proxy.list_tools()})
        if method == "tools/call":
            meta = params.get("_meta") or {}
            approval = meta.get(APPROVAL_META_KEY) if isinstance(meta, Mapping) else None
            result = self.proxy.call_tool(
                str(params.get("name", "")),
                params.get("arguments") or {},
                approval_id=str(approval) if approval else None,
            )
            return _rpc(request_id, result)
        if request_id is None:
            return None  # a notification: nothing to answer
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": -32601, "message": f"method not found: {method}"},
        }

    def _write(self, payload: Mapping[str, Any]) -> None:
        out = self._out
        if out is None:
            return
        with self._write_lock:
            out.write(json.dumps(payload) + "\n")
            out.flush()

    def notify_tools_changed(self) -> None:
        """Tell the agent's client to fetch the tool list again."""
        if self._initialized:
            self._write({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"})

    def serve(self, lines: Iterable[str], out: TextIO | None = None) -> None:
        self._out = out or sys.stdout
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                message = json.loads(line)
                if not isinstance(message, dict):
                    raise ValueError("not an object")
            except (json.JSONDecodeError, ValueError):
                response: dict[str, Any] | None = {
                    "jsonrpc": "2.0", "id": None,
                    "error": {"code": -32700, "message": "parse error"},
                }
            else:
                response = self.handle(message)
            if response is not None:
                self._write(response)


def _rpc(request_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


class ConfigWatcher(threading.Thread):
    """Applies config changes and tool-list changes while the proxy runs."""

    def __init__(
        self,
        path: str | Path,
        proxy: MCPProxy,
        server: ProxyServer,
        interval: float = 1.0,
    ) -> None:
        super().__init__(daemon=True)
        self.path = Path(path)
        self.proxy = proxy
        self.server = server
        self.interval = interval
        self._stop_event = threading.Event()
        self._seen = self._stamp()

    def _stamp(self) -> tuple[int, int] | None:
        try:
            stat = self.path.stat()
        except OSError:
            return None
        return (stat.st_mtime_ns, stat.st_size)

    def stop(self) -> None:
        self._stop_event.set()

    def check(self) -> bool:
        """One pass. Returns True when the tool list changed."""
        changed = False
        stamp = self._stamp()
        if stamp is not None and stamp != self._seen:
            self._seen = stamp
            try:
                changed = self.proxy.reload(load_proxy_config(self.path))
                say("config reloaded")
            except (OSError, ConfigError, DownstreamError) as exc:
                say(f"config not applied, keeping the current one: {exc}")
        changed = self.proxy.poll() or changed
        if changed:
            self.server.notify_tools_changed()
        return changed

    def run(self) -> None:
        while not self._stop_event.wait(self.interval):
            try:
                self.check()
            except Exception as exc:  # a watcher must never take the proxy down
                say(f"watcher error: {exc}")


def build_proxy(
    config: ProxyConfig,
    db: str | Path,
    *,
    factory: Any = default_downstream,
) -> MCPProxy:
    """Start every configured server and return a proxy over them.

    If any server cannot start, nothing is served: a proxy that silently lacks
    one server's tools would look healthy and guard less than the operator thinks.
    """
    started: dict[str, Downstream] = {}
    try:
        for server in config.servers:
            downstream = factory(server)
            started[server.name] = downstream
            downstream.start()
        session = SafetySession(
            TraceStore(db), environment=config.environment, limits=config.limits
        )
        return MCPProxy(
            started,
            session,
            configs={s.name: s for s in config.servers},
            rules=config.rules,
            require=config.require,
            pins=PinStore(db),
            factory=factory,
        )
    except BaseException:
        for running in started.values():
            running.close()
        raise


def serve_proxy(proxy: MCPProxy, config_path: str | Path | None = None) -> None:
    server = ProxyServer(proxy)
    watcher = None
    if config_path is not None:
        watcher = ConfigWatcher(config_path, proxy, server)
        watcher.start()
    try:
        server.serve(sys.stdin)
    finally:
        if watcher is not None:
            watcher.stop()
        proxy.close()


__all__ = [
    "ConfigError",
    "ConfigWatcher",
    "DownstreamError",
    "HttpDownstream",
    "MCPProxy",
    "PinStore",
    "ProxyConfig",
    "SignInError",
    "ProxyServer",
    "StdioDownstream",
    "build_proxy",
    "classify",
    "default_downstream",
    "definition_hash",
    "load_proxy_config",
    "parse_proxy_config",
    "serve_proxy",
    "sign_in",
]
