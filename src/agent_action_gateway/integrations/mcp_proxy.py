"""An MCP proxy: one server for the agent, a client to every real tool server.

The agent connects to this proxy and to nothing else. The proxy connects, as a
client, to the MCP servers the operator listed in a config file. It merges their
tools into one list and runs every `tools/call` through the same checks the
library uses (`SafetySession.tool`, which calls `engine.enforce`) before it
forwards the call.

What it can and cannot do:

* It checks the calls that go through it. If the agent's platform can also reach
  a real tool server directly, those calls skip the proxy. Removing the direct
  connections is the operator's job; no code here can do it for them.
* Tools are discovered from `tools/list`. Nobody writes a route by hand.
* A tool is `read` only when an operator rule says so, or when the server says
  `readOnlyHint` and the operator trusts that server's hints. Every other tool is
  destructive and needs an approval.

Approvals: a blocked call returns an error that carries an approval id. A person
approves it (dashboard), and the agent repeats the same call. The approval is
bound to the exact arguments and is used once.

Stdio is the only downstream transport so far.
"""

from __future__ import annotations

import contextlib
import fnmatch
import json
import os
import queue
import subprocess
import sys
import threading
import time
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, TextIO

from agent_action_gateway.policy.fuses import FuseLimits
from agent_action_gateway.runtime.session import VALID_ENVIRONMENTS, SafetySession
from agent_action_gateway.storage.traces import TraceStore

SEPARATOR = "__"
SUPPORTED_PROTOCOLS = ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25")
#: Names the checks use for their own purposes. A tool argument with one of
#: these names would be swallowed, so such a call is refused instead.
RESERVED_ARGUMENTS = frozenset({"approval_id", "actual_cost_usd", "intent_key"})
#: A proxy lives as long as the agent's client keeps it. Ten minutes (the
#: library default) would stop a normal session, so the default is longer.
DEFAULT_LIMITS = FuseLimits(max_steps=500, max_wall_seconds=3600.0)


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


# --------------------------------------------------------------------------
# config
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class ServerConfig:
    name: str
    command: str
    args: tuple[str, ...] = ()
    env: Mapping[str, str] = field(default_factory=dict)
    cwd: str | None = None
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
class ProxyConfig:
    servers: tuple[ServerConfig, ...]
    rules: tuple[Rule, ...] = ()
    environment: str = "dev"
    limits: FuseLimits = DEFAULT_LIMITS


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
        raw = yaml.safe_load(text)
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

    servers = []
    for name, entry in servers_raw.items():
        name = str(name)
        if not name or SEPARATOR in name or name.startswith("_") or name.endswith("_"):
            raise ConfigError(
                f"server name {name!r} is not allowed: it must not be empty, contain "
                f"'{SEPARATOR}', or start or end with an underscore"
            )
        if not isinstance(entry, Mapping):
            raise ConfigError(f"server {name!r} must be an object")
        if "url" in entry and "command" not in entry:
            raise ConfigError(
                f"server {name!r} uses 'url': only stdio servers ('command') are supported so far"
            )
        command = entry.get("command")
        if not isinstance(command, str) or not command:
            raise ConfigError(f"server {name!r} needs a 'command'")
        server_env = entry.get("environment")
        if server_env is not None and server_env not in VALID_ENVIRONMENTS:
            raise ConfigError(
                f"server {name!r}: environment must be one of {', '.join(VALID_ENVIRONMENTS)}"
            )
        servers.append(
            ServerConfig(
                name=name,
                command=command,
                args=tuple(str(a) for a in entry.get("args", ())),
                env={str(k): str(v) for k, v in dict(entry.get("env", {})).items()},
                cwd=entry.get("cwd"),
                environment=server_env,
                trust_hints=bool(entry.get("trust_hints", True)),
                timeout=float(entry.get("timeout", 30.0)),
            )
        )

    rules = []
    for item in raw.get("rules", ()):
        if not isinstance(item, Mapping) or "match" not in item or "risk" not in item:
            raise ConfigError("each rule needs 'match' and 'risk'")
        risk = str(item["risk"])
        if risk not in ("read", "write", "destructive"):
            raise ConfigError(f"rule {item['match']!r}: risk must be read, write or destructive")
        rules.append(Rule(str(item["match"]), risk))

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

    return ProxyConfig(tuple(servers), tuple(rules), environment, limits)


# --------------------------------------------------------------------------
# downstream: an MCP client over stdio
# --------------------------------------------------------------------------


class Downstream(Protocol):
    name: str

    def list_tools(self) -> list[dict[str, Any]]: ...

    def call_tool(self, tool: str, arguments: Mapping[str, Any]) -> dict[str, Any]: ...

    def close(self) -> None: ...


_EOF = object()


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
        return cls(config.name, config.command, config.args, config.env, config.cwd, config.timeout)

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> None:
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
        threading.Thread(target=self._read_loop, daemon=True).start()
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

    def call_tool(self, tool: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
        result = self._request("tools/call", {"name": tool, "arguments": dict(arguments)})
        if not isinstance(result, dict):
            raise DownstreamNotRun(f"{self.name}: unreadable tool result")
        return result

    # -- plumbing ----------------------------------------------------------

    def _read_loop(self) -> None:
        proc = self._proc
        assert proc is not None and proc.stdout is not None
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
            self._inbox.put(message)
        self._inbox.put(_EOF)

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
                    continue  # a late answer to an older request, or a notification
                if "error" in message:
                    error = message["error"] or {}
                    raise DownstreamNotRun(
                        f"{self.name}: {method} was rejected: {error.get('message', error)}"
                    )
                return message.get("result", {})


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


class MCPProxy:
    """Merges downstream tools and guards every call to them."""

    def __init__(
        self,
        downstreams: Mapping[str, Downstream],
        session: SafetySession,
        *,
        configs: Mapping[str, ServerConfig] | None = None,
        rules: Sequence[Rule] = (),
    ) -> None:
        self.downstreams = dict(downstreams)
        self.session = session
        self.configs = dict(configs or {})
        self.rules = tuple(rules)
        self.tools: dict[str, ProxiedTool] = {}
        self._refresh()

    # -- building the tool list -------------------------------------------

    def _refresh(self) -> None:
        self.tools.clear()
        for server, downstream in self.downstreams.items():
            config = self.configs.get(server)
            trust = config.trust_hints if config else True
            target_env = config.environment if config else None
            for definition in downstream.list_tools():
                real = str(definition.get("name", ""))
                if not real:
                    continue
                name = f"{server}{SEPARATOR}{real}"
                risk, source = classify(name, definition.get("annotations"), self.rules, trust)
                guarded = self.session.tool(
                    self._forwarder(downstream, real),
                    action=name,
                    risk=risk,
                    target_environment=target_env,
                )
                public = dict(definition)
                public["name"] = name
                self.tools[name] = ProxiedTool(name, server, real, risk, source, public, guarded)

    @staticmethod
    def _forwarder(downstream: Downstream, real: str) -> Any:
        # `intent_key` is named here so the session does not forward it to the
        # real server as if it were a tool argument.
        def forward(*, intent_key: str | None = None, **arguments: Any) -> dict[str, Any]:  # noqa: ARG001
            result = downstream.call_tool(real, arguments)
            if result.get("isError"):
                raise ToolReportedError(result)
            return result

        return forward

    def describe(self) -> list[tuple[str, str, str]]:
        """(tool, risk, why) for each tool, for the startup summary."""
        return [(t.name, t.risk, t.risk_source) for t in self.tools.values()]

    # -- MCP: tools/list and tools/call -------------------------------------

    def list_tools(self) -> list[dict[str, Any]]:
        return [t.definition for t in self.tools.values()]

    def call_tool(self, name: str, arguments: Mapping[str, Any] | None = None) -> dict[str, Any]:
        entry = self.tools.get(name)
        if entry is None:
            return _error(f"tool not available: {name}")

        args = dict(arguments or {})
        explicit = args.pop("_approval_id", None)
        clash = sorted(RESERVED_ARGUMENTS & set(args))
        if clash:
            return _error(
                f"blocked: the argument name {clash[0]!r} is used by the gateway's checks; "
                "this tool cannot be called through the proxy with it"
            )

        approvals = self.session.approvals
        approval_id = str(explicit) if explicit is not None else None
        if approval_id is None and entry.risk != "read":
            usable = approvals.find_usable(name, args)
            if usable is not None:
                approval_id = usable.approval_id

        kwargs = dict(args)
        if approval_id is not None:
            kwargs["approval_id"] = approval_id

        try:
            outcome = entry.guarded(**kwargs)
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
            return {
                "content": [{
                    "type": "text",
                    "text": "This exact action already ran earlier, so it was not run again.",
                }],
                "isError": False,
            }
        result = outcome.get("result")
        if isinstance(result, dict) and "content" in result:
            return result
        return {"content": [{"type": "text", "text": json.dumps(result, default=str)}], "isError": False}

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
        for downstream in self.downstreams.values():
            downstream.close()


def _error(message: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": message}], "isError": True}


# --------------------------------------------------------------------------
# the MCP server the agent talks to
# --------------------------------------------------------------------------


class ProxyServer:
    """JSON-RPC over newline-delimited stdio, answering for the proxy."""

    def __init__(self, proxy: MCPProxy) -> None:
        self.proxy = proxy

    def handle(self, message: Mapping[str, Any]) -> dict[str, Any] | None:
        method = message.get("method")
        request_id = message.get("id")
        params = message.get("params") or {}

        if method == "initialize":
            wanted = str(params.get("protocolVersion", ""))
            version = wanted if wanted in SUPPORTED_PROTOCOLS else SUPPORTED_PROTOCOLS[-1]
            return _rpc(request_id, {
                "protocolVersion": version,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "agent-action-gateway", "version": "0.2.0"},
            })
        if method == "ping":
            return _rpc(request_id, {})
        if method == "tools/list":
            return _rpc(request_id, {"tools": self.proxy.list_tools()})
        if method == "tools/call":
            result = self.proxy.call_tool(
                str(params.get("name", "")), params.get("arguments") or {}
            )
            return _rpc(request_id, result)
        if request_id is None:
            return None  # a notification: nothing to answer
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": -32601, "message": f"method not found: {method}"},
        }

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
                response: dict[str, Any] | None = {
                    "jsonrpc": "2.0", "id": None,
                    "error": {"code": -32700, "message": "parse error"},
                }
            else:
                response = self.handle(message)
            if response is not None:
                out.write(json.dumps(response) + "\n")
                out.flush()


def _rpc(request_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def build_proxy(config: ProxyConfig, db: str | Path) -> MCPProxy:
    """Start every configured server and return a proxy over them.

    If any server cannot start, nothing is served: a proxy that silently lacks
    one server's tools would look healthy and guard less than the operator thinks.
    """
    started: dict[str, Downstream] = {}
    try:
        for server in config.servers:
            downstream = StdioDownstream.from_config(server)
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
        )
    except BaseException:
        for running in started.values():
            running.close()
        raise


def serve_proxy(proxy: MCPProxy) -> None:
    try:
        ProxyServer(proxy).serve(sys.stdin)
    finally:
        proxy.close()


__all__ = [
    "ConfigError",
    "DownstreamError",
    "MCPProxy",
    "ProxyConfig",
    "ProxyServer",
    "StdioDownstream",
    "build_proxy",
    "classify",
    "load_proxy_config",
    "parse_proxy_config",
    "serve_proxy",
]
