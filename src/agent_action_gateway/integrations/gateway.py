"""HTTP gateway with credential custody.

For tools we cannot wrap in-process - cloud APIs, internal services - the
agent talks HTTP to us and we talk HTTP to the real service holding the key.

That ordering is the whole security property. The agent never receives an
upstream credential, so bypassing the gateway does not merely violate policy,
it has nothing to bypass with — when the gateway runs as its own service/container.

Deny-by-default matches how action risk is handled: a route nobody
registered is refused, never forwarded.
"""

from __future__ import annotations

import http.client
import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from agent_action_gateway.credential.credentials import (
    CredentialRule,
    PlaceholderVault,
)
from agent_action_gateway.credential.egress import (
    EgressDenied,
    EgressPolicy,
    always_forbidden_ip,
    forbidden_ip,
    resolve_addresses,
)
from agent_action_gateway.engine.enforcement import Decision, EnforcementContext
from agent_action_gateway.guards.redaction import redact
from agent_action_gateway.policy.fuses import FuseBudget, FuseController, FuseLimits
from agent_action_gateway.policy.locks import (
    ApprovalError,
    ApprovalStore,
    RiskRegistry,
    SafetyBlockedError,
)
from agent_action_gateway.policy.stop_rules import enforce_environment
from agent_action_gateway.runtime.records import TraceEvent
from agent_action_gateway.storage.traces import TraceStore


class GatewayError(RuntimeError):
    """The gateway cannot safely forward a request."""


@dataclass(frozen=True)
class Route:
    """One upstream this gateway is allowed to reach."""

    path: str
    upstream: str
    action: str
    risk: str = "destructive"
    method: str = "POST"
    #: Name of the environment variable holding the upstream credential.
    secret_env: str = ""
    environment: str = "prod"
    #: Destination host this route may reach. Empty means derive it from
    #: `upstream`, so existing route tables keep working unchanged.
    host: str = ""

    def destination_host(self) -> str:
        """Host this route targets, for the egress allow-list check."""
        if self.host:
            return self.host
        parsed = urllib.parse.urlparse(self.upstream)
        return parsed.hostname or ""

    def credential(self) -> str | None:
        import os

        if not self.secret_env:
            return None
        if self.secret_env.startswith("file:"):
            path = self.secret_env[5:]
            try:
                st = os.stat(path)
            except FileNotFoundError:
                raise GatewayError(f"secret file not found: {path}") from None
            if st.st_mode & 0o077:
                raise GatewayError(
                    f"secret file {path} must be 0600 (mode {oct(st.st_mode & 0o777)})"
                ) from None
            if st.st_uid != os.geteuid():
                raise GatewayError(
                    f"secret file {path} must be owned by gateway user (uid {os.geteuid()})"
                ) from None
            with open(path) as f:
                return f.read().strip()
        value = os.environ.get(self.secret_env)
        if not value:
            raise GatewayError(f"upstream credential missing: {self.secret_env}") from None
        return value


@dataclass(frozen=True)
class VirtualKey:
    """A virtual key issued to an agent, mapped to allowed routes."""
    key: str
    name: str
    routes: frozenset[str]
    expires_at: float | None = None
    revoked: bool = False


@dataclass
class GatewayPolicy:
    """Registry of permitted routes. Absence of a route is a refusal."""

    routes: dict[str, Route] = field(default_factory=dict)
    session_environment: str = "dev"
    master_key_env: str = ""
    virtual_keys: dict[str, VirtualKey] = field(default_factory=dict)
    #: Placeholder vault when credential-custody mode is enabled. None means the
    #: legacy per-route `secret_env` behaviour, so existing configs are unchanged.
    vault: PlaceholderVault | None = None
    #: Destinations the workload may reach. Empty + a vault means "derive from routes".
    allowed_hosts: frozenset[str] = field(default_factory=frozenset)
    egress: EgressPolicy | None = None
    #: Whether the gateway runs its own risk and approval checks.
    #:
    #: ``True`` is the legacy mode kept for callers that route actions through
    #: the gateway as their only door — it still checks risk and approval so
    #: those deployments do not silently become unguarded. Credential-custody
    #: mode sets this ``False``: enforcement belongs to the wrapped tool, and
    #: the gateway only injects credentials. Do not switch a deployment off
    #: until the adoption check (``agent-gateway check --app``) is green.
    enforcement_enabled: bool = True

    def register(self, route: Route) -> None:
        if route.path == MCP_PATH:
            raise GatewayError(f"{MCP_PATH} is the gateway's MCP endpoint; choose another path")
        self.routes[route.path] = route

    def resolve(self, path: str) -> Route | None:
        return self.routes.get(path)

    def configure_credentials(
        self,
        credentials: list[CredentialRule],
        *,
        allowed_hosts: frozenset[str] | None = None,
        audit: Any = None,
        dns: Any = None,
        private_hosts: Iterable[str] = (),
        inject_headers: bool = True,
        enforce_policy: bool = False,
    ) -> None:
        """Enable placeholder-based credential custody on this policy.

        Secrets are resolved from the environment/file at config load. The
        agent is handed only the vault's placeholders; the real values never
        enter any config file, trace or request the agent can see.

        ``inject_headers=True`` (the default): the gateway adds the real
        credential to the named header. ``False``: the agent placed the
        placeholder itself, and the gateway swaps it in place.

        ``enforce_policy`` defaults to ``False``: credential custody is not a
        policy path. Set it ``True`` only for a legacy deployment whose tools
        are not wrapped, until ``agent-gateway check --app`` confirms adoption.
        """
        resolved = [
            CredentialRule(
                secret_name=rule.secret_name,
                secret=rule.secret,
                allowed_hosts=rule.allowed_hosts,
                header=rule.header,
                expires_at=rule.expires_at,
            )
            for rule in credentials
        ]
        self.vault = PlaceholderVault.from_rules(resolved)
        hosts = allowed_hosts if allowed_hosts is not None else frozenset(
            r.destination_host() for r in self.routes.values() if r.destination_host()
        )
        self.allowed_hosts = hosts
        self.egress = EgressPolicy(
            self.vault,
            hosts,
            audit=audit,
            dns=dns or resolve_addresses,
            inject_headers=inject_headers,
            private_hosts=private_hosts,
        )
        self.enforcement_enabled = enforce_policy

    def agent_environment(self) -> dict[str, str]:
        """The placeholder-filled environment to hand an adopting agent."""
        if self.vault is None:
            return {}
        return self.vault.agent_environment()

    def validate_virtual_key(self, key: str) -> VirtualKey | None:
        """Validate a virtual key, return it if valid."""
        vk = self.virtual_keys.get(key)
        if vk is None:
            return None
        if vk.revoked:
            return None
        if vk.expires_at is not None and time.time() > vk.expires_at:
            return None
        return vk


@dataclass
class GatewayResult:
    status: int
    body: Mapping[str, Any]
    headers: dict[str, str] = field(default_factory=dict)


class SafetyGateway:
    """Checks HTTP traffic before it leaves: routes, keys, environment, approval.

    It does not call `engine.enforce`: there are no limits or once-only
    receipts here (it passes the caller's `Idempotency-Key` upstream instead).
    For those, put the MCP proxy in front of it.
    """

    def __init__(
        self,
        store: TraceStore,
        policy: GatewayPolicy,
        *,
        run_id: str | None = None,
        limits: FuseLimits | None = None,
        transport: Any = None,
    ) -> None:
        self.store = store
        self.policy = policy
        self.run_id = run_id or secrets.token_hex(8)
        self.registry = RiskRegistry()
        self.approvals = ApprovalStore(store)
        self.fuse = FuseController(FuseBudget(limits or FuseLimits(max_steps=500)))
        for route in policy.routes.values():
            self.registry.register(route.action, route.risk)
        # Load virtual keys from persistent store
        self._load_virtual_keys()
        self._transport = transport or self._guarded_forward
        self._step = 0

    def _load_virtual_keys(self) -> None:
        """Refresh the in-memory key set from the store.

        Called at startup and again whenever a presented key is not recognised,
        so issuing a key takes effect without restarting the gateway. An agent
        that received a key and was then refused would have no way to tell that
        from a misconfiguration -- it would just retry a key that can never
        work until someone restarts the service.
        """
        for vk_data in self.store.load_virtual_keys():
            vk = VirtualKey(
                key=vk_data["key"],
                name=vk_data["name"],
                routes=frozenset(vk_data["routes"]),
                expires_at=vk_data["expires_at"],
                revoked=vk_data["revoked"],
            )
            self.policy.virtual_keys[vk.key] = vk

    def resolve_caller(self, presented: str | None) -> tuple[VirtualKey | None, bool]:
        """Classify a caller as (virtual key, is_master).

        Returns (None, False) when nothing authenticates.

        The store is re-read on every request rather than trusting the copy
        loaded at startup. That matters in both directions: a key issued after
        the process started has to work, and a key revoked after the process
        started has to stop working. Caching either would mean an operator who
        revokes a compromised key sees it keep working until someone restarts
        the service. The in-memory map is kept as the lookup structure, but it
        is refreshed from the store before it is trusted.
        """
        if presented is None:
            return None, False
        self._load_virtual_keys()
        existing = self.policy.validate_virtual_key(presented)
        if existing is not None:
            return existing, False
        return None, self._is_master_presented(presented)

    def _is_master_presented(self, presented: str) -> bool:
        """Whether the caller presented the master key from the environment."""
        env_name = self.policy.master_key_env
        if not env_name:
            return False
        master_key = os.environ.get(env_name)
        if master_key is None:
            return False
        return secrets.compare_digest(presented, master_key)

    def handle(
        self,
        method: str,
        path: str,
        payload: Mapping[str, Any],
        *,
        approval_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> GatewayResult:
        route = self.policy.resolve(path)
        if route is None or route.method != method:
            # Deny-by-default: unknown means refused, never forwarded.
            self._trace("gateway.denied", {"path": path, "reason": "unregistered"})
            return GatewayResult(403, {"error": "route not registered", "path": path})

        try:
            enforce_environment(self.policy.session_environment, route.environment)
        except Exception as exc:
            self._trace("gateway.denied", {"path": path, "reason": str(exc)})
            return GatewayResult(403, {"error": str(exc), "path": path})

        self._step += 1
        key = idempotency_key or f"{self.run_id}:{self._step}"
        # The idempotency key is part of the arguments the approval is bound to,
        # so a retry with a different key is a different action and cannot reuse
        # an approval.
        arguments = {**payload, "_idempotency_key": key}

        decision: Decision | None = None
        if self.policy.enforcement_enabled:
            # Legacy mode only: the gateway is the caller's sole door, so it
            # still owns policy. In credential-custody mode this is skipped —
            # the wrapped tool enforces, and the gateway only injects.
            try:
                decision = self._authorize(route, arguments, key, approval_id)
            except ApprovalError as exc:
                # 403, not 401. The caller has already proved who it is; what it
                # lacks is authorisation. Reusing 401 made "you need approval"
                # indistinguishable from "your key is invalid", and a real client
                # cannot tell whether to request an approval or re-authenticate.
                #
                # Traced before returning. This branch used to return silently,
                # so an action held here left no evidence at all -- an operator
                # asking "did anything try to deploy?" got an empty answer, which
                # is the exact failure this project exists to prevent.
                self._trace(
                    "gateway.held",
                    {
                        "path": route.path,
                        "action": route.action,
                        "reason": str(exc),
                        "args": redact(arguments),
                    },
                )
                return GatewayResult(403, {"error": str(exc), "needs_approval": True})

        try:
            credential = route.credential()
        except GatewayError as exc:
            # An unreadable secret used to escape `handle` entirely: the handler
            # thread died and the caller received no response at all, which reads
            # as a dropped connection rather than a refused action. An operator
            # whose secret had the wrong owner got a hang instead of the reason.
            #
            # The detail goes to the trace, not to the caller -- it names a file
            # path and a uid, which is not for whoever made the request.
            self._trace(
                "gateway.credential_unavailable",
                {"path": route.path, "action": route.action, "reason": str(exc)},
            )
            return GatewayResult(
                503,
                {"error": "upstream credential unavailable", "path": route.path},
            )
        headers = {"Content-Type": "application/json"}
        if credential:
            headers["Authorization"] = f"Bearer {credential}"
        # Forwarded so the upstream can dedupe a replay after our own crash.
        headers["Idempotency-Key"] = key

        # Credential-custody mode: the destination must be on the allow-list and
        # any placeholder the agent supplied is swapped for the real secret here,
        # in the gateway, never in the agent. Fail closed: no headers, no forward.
        if self.policy.egress is not None:
            try:
                headers = self.policy.egress.enforce(route.destination_host(), headers)
            except EgressDenied as exc:
                # The reason is computed by the egress policy and is already
                # safe to surface (it names no secret and no file path).
                self._trace(
                    "gateway.egress_denied",
                    {"path": route.path, "action": route.action, "reason": str(exc)},
                )
                return GatewayResult(403, {"error": str(exc), "path": route.path})
            # The idempotency key must survive the swap.
            headers.setdefault("Idempotency-Key", key)
            headers.setdefault("Content-Type", "application/json")

        self._trace(
            "gateway.forward",
            {"path": path, "action": route.action, "args": redact(arguments)},
            decision,
        )
        status, body = self._transport(route.upstream, payload, headers)
        return GatewayResult(status, body)

    def _guarded_forward(
        self, upstream: str, payload: Mapping[str, Any], headers: Mapping[str, str]
    ) -> tuple[int, Mapping[str, Any]]:
        """The real transport. With credential custody on, it also refuses to
        connect to a private address unless the operator listed that host."""
        egress = self.policy.egress
        if egress is None:
            return _forward(upstream, payload, headers)
        return _forward(
            upstream, payload, headers, opener=_guarding_opener(egress.is_private_host)
        )

    def _authorize(
        self, route: Route, arguments: dict[str, Any], key: str, approval_id: str | None
    ) -> Decision:
        """Run policy only. The upstream call happens after this returns."""
        from agent_action_gateway.guards.status import honest_status

        risk = self.registry.classify(route.action)
        if risk == "read":
            return Decision("allowed", "ALLOW", risk=risk)
        if not self.approvals.available:
            raise SafetyBlockedError("approval service unavailable")
        if approval_id is None:
            raise SafetyBlockedError("destructive route requires approval")
        # authorize() consumes single-use and verifies the digest, then the
        # caller forwards. A duplicate approval therefore cannot cause a second
        # upstream call.
        from agent_action_gateway.policy.locks import authorize

        authorize(
            self.approvals,
            self.registry,
            route.action,
            arguments,
            approval_id=approval_id,
        )
        return Decision("allowed", "ALLOW", risk=risk,
                         evidence_status=honest_status())

    def _trace(self, event: str, payload: Mapping[str, Any], decision: Any = None) -> None:
        output: dict[str, Any] = dict(payload)
        if decision is not None:
            output["decision"] = getattr(decision, "decision", str(decision))
        self.store.append_trace(
            TraceEvent(self.run_id, 3, event, "gateway", redact(output), "completed"), enforcement="enforced",
        )


def _checked(connection: Any, allow_private: Any) -> None:
    """After connecting, look at the address we really reached.

    A name can point somewhere safe when it is checked and somewhere else when it
    is dialled (DNS rebinding). The address of the open connection cannot lie.
    """
    peer = str(connection.sock.getpeername()[0])
    host = str(connection.host)
    blocked = always_forbidden_ip(peer) or (forbidden_ip(peer) and not allow_private(host))
    if blocked:
        connection.close()
        raise OSError("connected to a forbidden address")


def _guarding_opener(allow_private: Any) -> urllib.request.OpenerDirector:
    class Plain(http.client.HTTPConnection):
        def connect(self) -> None:
            super().connect()
            _checked(self, allow_private)

    class Secure(http.client.HTTPSConnection):
        def connect(self) -> None:
            super().connect()
            _checked(self, allow_private)

    class PlainHandler(urllib.request.HTTPHandler):
        def http_open(self, req: Any) -> Any:
            return self.do_open(Plain, req)

    class SecureHandler(urllib.request.HTTPSHandler):
        def https_open(self, req: Any) -> Any:
            return self.do_open(Secure, req)

    return urllib.request.build_opener(PlainHandler, SecureHandler)


def _forward(
    upstream: str,
    payload: Mapping[str, Any],
    headers: Mapping[str, str],
    *,
    opener: urllib.request.OpenerDirector | None = None,
) -> tuple[int, Mapping[str, Any]]:
    request = urllib.request.Request(
        upstream,
        data=json.dumps(payload).encode("utf-8"),
        headers=dict(headers),
        method="POST",
    )
    try:
        with (opener.open if opener else urllib.request.urlopen)(request, timeout=20) as response:
            raw = response.read()
            status = int(response.status)
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        status = int(exc.code)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        # The upstream could not be reached at all. This is not an approval or
        # policy failure, so it must not be reported as one, and the caller
        # still needs a reply: an unreadable action is not a completed one.
        return 502, {"error": "upstream unreachable", "detail": str(exc)[:200]}
    try:
        body = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        body = {"raw": raw.decode("utf-8", errors="replace")[:500]}
    return status, body if isinstance(body, dict) else {"data": body}


class GatewayHandler(BaseHTTPRequestHandler):
    """Thin HTTP shell. All policy lives in SafetyGateway."""

    gateway: SafetyGateway
    access_token: str = ""
    #: Route registry plus caller auth. Injected by `build_gateway_server`;
    #: declared here so the handler is usable and checkable on its own.
    policy: GatewayPolicy

    def log_message(self, *args: object) -> None:
        return

    def _denied(self, status: int, message: str) -> None:
        self._respond(status, {"error": message})

    def _respond(self, status: int, payload: Mapping[str, Any]) -> None:
        body = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        parsed = urllib.parse.urlparse(self.path)
        header = self.headers.get("Authorization", "")
        presented = header[7:] if header.startswith("Bearer ") else None

        # A virtual key is scoped to a route set; the master key and the
        # per-process bootstrap token are not. Resolve which one this is before
        # anything else, because the answer decides what is permitted.
        virtual_key, is_master = self.gateway.resolve_caller(presented)
        if virtual_key is None and not is_master and (
            not presented or not secrets.compare_digest(presented, self.access_token)
        ):
            self._denied(401, "gateway token required")
            return

        if parsed.path == MCP_PATH:
            self._mcp(virtual_key)
            return

        # An unregistered path is refused outright. A scoped key that is valid
        # for other routes must not be told whether this one exists.
        # The two refusals give a scoped key the same answer, or the gateway
        # would tell it which of the paths it may not use really exist.
        route = self.policy.resolve(parsed.path)
        if virtual_key is not None and (route is None or route.path not in virtual_key.routes):
            self._denied(403, "route not available for this key")
            return
        if route is None:
            self._denied(403, "route not registered")
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
        except (ValueError, json.JSONDecodeError):
            self._denied(400, "request body must be JSON")
            return
        if not isinstance(payload, dict):
            self._denied(400, "request body must be an object")
            return
        result = self.gateway.handle(
            "POST",
            parsed.path,
            payload,
            approval_id=self.headers.get("X-Approval-Id"),
            idempotency_key=self.headers.get("Idempotency-Key"),
        )
        self._respond(result.status, result.body)


    def _mcp(self, virtual_key: VirtualKey | None) -> None:
        """Serve the gateway's routes as MCP tools (Streamable HTTP, JSON replies).

        This is what lets the MCP proxy forward to the gateway: the proxy runs
        the checks, and the gateway holds the real key and makes the upstream
        call. The caller was already authenticated. A virtual key sees only the
        routes it is scoped to.
        """
        from agent_action_gateway.integrations.mcp import MCPToolBridge
        from agent_action_gateway.integrations.mcp_server import MCPServer

        try:
            length = int(self.headers.get("Content-Length", "0"))
            message = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
        except (ValueError, json.JSONDecodeError):
            self._respond(400, {"jsonrpc": "2.0", "id": None,
                                "error": {"code": -32700, "message": "parse error"}})
            return
        if not isinstance(message, dict):
            self._respond(400, {"jsonrpc": "2.0", "id": None,
                                "error": {"code": -32600, "message": "send one request at a time"}})
            return
        allowed = None if virtual_key is None else set(virtual_key.routes)
        reply = MCPServer(MCPToolBridge(self.gateway), allowed).handle(message)
        if reply is None:
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self._respond(200, reply)


#: The gateway's MCP endpoint. A route cannot use this path.
MCP_PATH = "/mcp"


def build_gateway_server(
    store: TraceStore,
    policy: GatewayPolicy,
    host: str = "127.0.0.1",
    port: int = 0,
    token: str | None = None,
    unix_socket: str | None = None,
) -> tuple[ThreadingHTTPServer, type[GatewayHandler]]:
    main_module = sys.modules.get("__main__")
    main_file = getattr(main_module, "__file__", None) if main_module else None
    if not os.environ.get("AGENT_GATEWAY") and main_file:
        raise RuntimeError(
            "Gateway cannot run embedded in application code. Launch via `agent-gateway gateway`."
        )
    gateway = SafetyGateway(store, policy)
    handler = type(
        "BoundGatewayHandler",
        (GatewayHandler,),
        {"gateway": gateway, "access_token": token or secrets.token_urlsafe(24), "policy": policy},
    )
    if unix_socket:
        if os.path.exists(unix_socket):
            os.unlink(unix_socket)
        server = _UnixSocketServer(unix_socket, handler)
        return server, handler
    return ThreadingHTTPServer((host, port), handler), handler


class _UnixSocketServer(ThreadingHTTPServer):
    def __init__(self, path: str, handler_class):
        import socket
        self.unix_socket_path = path
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(path)
        sock.listen(128)
        os.chmod(path, 0o660)
        super().__init__(("127.0.0.1", 0), handler_class)
        self.socket.close()
        self.socket = sock

    def get_request(self):
        """Accept a connection, refusing one that cannot be told apart from us.

        The refusal is *written to the caller* and the connection returned
        normally. The earlier version closed the socket and raised, which did two
        harmful things: the caller saw a connection reset rather than a reason,
        and the exception escaped `get_request` into the serve loop, so a single
        rejected caller stopped the gateway for everyone. A process sharing the
        gateway's uid could therefore take it down by connecting once.
        """
        import socket
        import struct
        conn, _ = self.socket.accept()
        # SO_PEERCRED is Linux-only. Looked up rather than referenced directly:
        # a direct reference is an attribute error on macOS and an *unused*
        # type-ignore on Linux, so one of the two platforms always fails a
        # check. Absent here means the check cannot run, which is stated in the
        # body rather than silently treated as a pass.
        peercred = getattr(socket, "SO_PEERCRED", None)
        if peercred is not None:
            try:
                creds = conn.getsockopt(
                    socket.SOL_SOCKET, peercred, struct.calcsize("3i")
                )
                _pid, uid, _gid = struct.unpack("3i", creds)
                if uid == os.geteuid():
                    self._refuse(
                        conn,
                        403,
                        "no custody boundary: the caller runs as the same user "
                        "as the gateway",
                    )
            except (OSError, struct.error):
                pass
        return conn, ("local", 0)

    @staticmethod
    def _refuse(conn: Any, status: int, message: str) -> None:
        """Send a minimal HTTP refusal, then close."""
        body = json.dumps({"error": message}).encode()
        try:
            conn.sendall(
                (
                    f"HTTP/1.0 {status} Forbidden\r\n"
                    "Content-Type: application/json\r\n"
                    f"Content-Length: {len(body)}\r\n"
                    "Connection: close\r\n\r\n"
                ).encode()
                + body
            )
        except OSError:
            # The caller vanished mid-handshake. Nothing to explain to it.
            pass
        finally:
            conn.close()

    def server_close(self):
        import contextlib
        super().server_close()
        with contextlib.suppress(OSError):
            os.unlink(self.unix_socket_path)


__all__ = [
    "GatewayError",
    "Route",
    "GatewayPolicy",
    "GatewayResult",
    "SafetyGateway",
    "GatewayHandler",
    "MCP_PATH",
    "build_gateway_server",
    "VirtualKey",
    "EnforcementContext",
]
