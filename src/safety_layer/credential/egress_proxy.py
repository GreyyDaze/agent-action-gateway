"""HTTP forward proxy that applies the egress policy before forwarding.

An unmodified agent points its HTTP client at this proxy (``HTTP_PROXY`` /
``HTTPS_PROXY``). The agent still addresses the real vendor; the proxy reads the
destination, applies the host allow-list and SSRF guard, swaps any placeholder
for the real credential, and only then opens the upstream connection.

TLS is deliberately not terminated here. Terminating TLS to inspect arbitrary
HTTPS requires a platform CA and per-host certificates — an operator concern,
not something a stdlib library can do safely on its own. So:

- absolute-form HTTP requests are forwarded with credentials injected;
- ``CONNECT`` (HTTPS tunnelling) is **refused by default**, with a clear reason.

Deployments that need HTTPS credential injection terminate TLS at the network
layer (Envoy's ``credential_injector`` filter, or an egress proxy with a platform
CA) using the same :class:`~safety_layer.credential.egress.EgressPolicy`. This
proxy is the reference enforcement point for plaintext and for policy decisions;
it never claims a guarantee it cannot provide for HTTPS.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from safety_layer.credential.egress import EgressDenied, EgressPolicy
from safety_layer.credential.tls import TLSTerminator


class ForwardProxyError(RuntimeError):
    """The proxy could not safely forward the request."""


class ForwardProxy:
    """Policy application, separated from the socket handler so it is testable."""

    def __init__(
        self,
        policy: EgressPolicy,
        *,
        transport: Callable[[str, str, Mapping[str, str], bytes], tuple[int, bytes]] | None = None,
        tls_terminator: TLSTerminator | None = None,
    ) -> None:
        self.policy = policy
        self._transport = transport or self._default_transport
        self.tls_terminator = tls_terminator

    def forward(
        self, method: str, url: str, headers: Mapping[str, str], body: bytes
    ) -> tuple[int, bytes]:
        """Decide, inject, forward. Raises :class:`EgressDenied` on refusal."""
        host = urllib.parse.urlparse(url).hostname or ""
        outbound = self.policy.enforce(host, headers)
        # Strip hop-by-hop headers the proxy itself owns.
        clean = {
            k: v
            for k, v in outbound.items()
            if k.lower() not in {"proxy-connection", "proxy-authorization", "host", "content-length"}
        }
        return self._transport(method, url, clean, body)

    @staticmethod
    def _default_transport(
        method: str, url: str, headers: Mapping[str, str], body: bytes
    ) -> tuple[int, bytes]:
        request = urllib.request.Request(url, data=body or None, headers=dict(headers), method=method)
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                return int(response.status), response.read()
        except urllib.error.HTTPError as exc:
            return int(exc.code), exc.read()


def build_proxy_server(
    proxy: ForwardProxy,
    host: str = "127.0.0.1",
    port: int = 0,
) -> tuple[ThreadingHTTPServer, type[BaseHTTPRequestHandler]]:
    """Build a forward-proxy HTTP server. HTTPS CONNECT is refused fail-closed."""

    handler = _make_handler(proxy)
    return ThreadingHTTPServer((host, port), handler), handler


def _make_handler(proxy: ForwardProxy) -> type[BaseHTTPRequestHandler]:
    class ProxyHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args: object) -> None:
            return

        def _reply(self, status: int, body: bytes, ctype: str = "text/plain") -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _headers(self) -> dict[str, str]:
            return {k: v for k, v in self.headers.items()}

        def do_CONNECT(self) -> None:  # noqa: N802
            # A platform may supply a TLS terminator (MITM with its own CA) that
            # applies the same policy to the decrypted request. With none, refuse
            # rather than tunnel blindly — a blind tunnel would let the agent
            # bypass the host allow-list entirely. Fail closed by default.
            if proxy.tls_terminator is not None:
                proxy.tls_terminator.serve(self)
                return
            body = json.dumps(
                {
                    "error": "HTTPS CONNECT is not supported by this proxy",
                    "hint": "configure a tls_terminator with a platform CA, terminate "
                    "TLS at your network egress layer, or use Envoy credential_injector "
                    "applying the same EgressPolicy",
                }
            ).encode()
            self._reply(405, body, "application/json")

        def _handle(self, method: str) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length) if length else b""
            try:
                status, payload = proxy.forward(method, self.path, self._headers(), body)
            except EgressDenied as exc:
                self._reply(403, json.dumps({"error": str(exc)}).encode(), "application/json")
                return
            except (ForwardProxyError, OSError) as exc:
                self._reply(502, json.dumps({"error": f"upstream failed: {exc}"}).encode(), "application/json")
                return
            self._reply(status, payload)

        def do_GET(self) -> None:  # noqa: N802
            self._handle("GET")

        def do_POST(self) -> None:  # noqa: N802
            self._handle("POST")

        def do_PUT(self) -> None:  # noqa: N802
            self._handle("PUT")

        def do_DELETE(self) -> None:  # noqa: N802
            self._handle("DELETE")

    return ProxyHandler


__all__ = ["ForwardProxy", "ForwardProxyError", "build_proxy_server"]
