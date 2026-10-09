"""HTTP gateway with credential custody.

For tools we cannot wrap in-process - payment APIs, internal services - the
agent talks HTTP to us and we talk HTTP to the real service holding the key.

That ordering is the whole security property. The agent never receives an
upstream credential, so bypassing the gateway does not merely violate policy,
it has nothing to bypass with.

Deny-by-default matches how action risk is handled: a route nobody
registered is refused, never forwarded.
"""

from __future__ import annotations

import json
import secrets
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from ..core.enforcement import Decision, EnforcementContext
from ..core.fuses import FuseBudget, FuseController, FuseLimits
from ..core.locks import ApprovalError, ApprovalStore, RiskRegistry, SafetyBlockedError
from ..core.stop_rules import enforce_environment
from ..evidence.redaction import redact
from ..runtime.records import TraceEvent
from ..storage.traces import TraceStore


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
    #: Extracts the receipt target from the request payload, when the action is
    #: a real side effect that needs replay.
    target_field: str | None = None

    def credential(self) -> str | None:
        import os

        if not self.secret_env:
            return None
        value = os.environ.get(self.secret_env)
        if not value:
            raise GatewayError(f"upstream credential missing: {self.secret_env}")
        return value


@dataclass
class GatewayPolicy:
    """Registry of permitted routes. Absence of a route is a refusal."""

    routes: dict[str, Route] = field(default_factory=dict)
    session_environment: str = "dev"

    def register(self, route: Route) -> None:
        self.routes[route.path] = route

    def resolve(self, path: str) -> Route | None:
        return self.routes.get(path)


@dataclass
class GatewayResult:
    status: int
    body: Mapping[str, Any]
    headers: dict[str, str] = field(default_factory=dict)


class SafetyGateway:
    """Applies the shared pipeline to HTTP traffic before it leaves the process."""

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
        self._transport = transport or _forward
        self._step = 0

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
        # The idempotency key is bound into the payload the receipt hashes, so a
        # retry with a different key is a different action and cannot reuse an
        # approval.
        arguments = {**payload, "_idempotency_key": key}

        try:
            decision = self._authorize(route, arguments, key, approval_id)
        except ApprovalError as exc:
            return GatewayResult(401, {"error": str(exc), "needs_approval": True})

        credential = route.credential()
        headers = {"Content-Type": "application/json"}
        if credential:
            headers["Authorization"] = f"Bearer {credential}"
        # Forwarded so the upstream can dedupe a replay after our own crash.
        headers["Idempotency-Key"] = key

        self._trace(
            "gateway.forward",
            {"path": path, "action": route.action, "args": redact(arguments)},
            decision,
        )
        status, body = self._transport(route.upstream, payload, headers)
        return GatewayResult(status, body)

    def _authorize(
        self, route: Route, arguments: dict[str, Any], key: str, approval_id: str | None
    ) -> Decision:
        """Run policy only. The upstream call happens after this returns."""
        from ..evidence.status import honest_status

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
        from ..core.locks import authorize

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


def _forward(
    upstream: str, payload: Mapping[str, Any], headers: Mapping[str, str]
) -> tuple[int, Mapping[str, Any]]:
    request = urllib.request.Request(
        upstream,
        data=json.dumps(payload).encode("utf-8"),
        headers=dict(headers),
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            raw = response.read()
            status = int(response.status)
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        status = int(exc.code)
    try:
        body = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        body = {"raw": raw.decode("utf-8", errors="replace")[:500]}
    return status, body if isinstance(body, dict) else {"data": body}


class GatewayHandler(BaseHTTPRequestHandler):
    """Thin HTTP shell. All policy lives in SafetyGateway."""

    gateway: SafetyGateway
    access_token: str = ""

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
        if not presented or not secrets.compare_digest(presented, self.access_token):
            self._denied(401, "gateway token required")
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


def build_gateway_server(
    store: TraceStore,
    policy: GatewayPolicy,
    host: str = "127.0.0.1",
    port: int = 0,
    token: str | None = None,
) -> tuple[ThreadingHTTPServer, type[GatewayHandler]]:
    gateway = SafetyGateway(store, policy)
    handler = type(
        "BoundGatewayHandler",
        (GatewayHandler,),
        {"gateway": gateway, "access_token": token or secrets.token_urlsafe(24)},
    )
    return ThreadingHTTPServer((host, port), handler), handler


__all__ = [
    "GatewayError",
    "Route",
    "GatewayPolicy",
    "GatewayResult",
    "SafetyGateway",
    "GatewayHandler",
    "build_gateway_server",
    "EnforcementContext",
]
