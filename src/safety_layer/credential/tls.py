"""Optional TLS termination for the forward proxy (MITM egress).

Terminating HTTPS requires a platform CA and a certificate for each allowed
host — operator-owned material, not something this stdlib-only library can
generate. So TLS is a **pluggable hook**:

- ``ForwardProxy`` with no terminator refuses ``CONNECT`` (fail-closed default).
- A platform supplies a :class:`TLSTerminator` whose job is to terminate the
  client's TLS, apply the same :class:`~safety_layer.credential.egress.EgressPolicy`
  to the decrypted request, dial the upstream with normal certificate
  validation, and pipe the bytes.

:class:`MITMTerminator` is a reference implementation. It takes a
``context_provider(host) -> ssl.SSLContext`` from the operator (the context must
present a cert for ``host`` signed by the platform CA the agent trusts). The
upstream connection is injectable so the policy decision can be tested without
a live network.

This module never mints certificates. A wrong CA or a missing per-host cert is
a deployment failure, and the proxy refuses the connection rather than fall
back to a blind tunnel that would let the agent bypass the allow-list.
"""

from __future__ import annotations

import contextlib
import socket
import ssl
import threading
from collections.abc import Callable, Mapping
from typing import Any, Protocol

from safety_layer.credential.egress import EgressDenied, EgressPolicy

SSLContextProvider = Callable[[str], ssl.SSLContext]
UpstreamConnector = Callable[[str, int], socket.socket]


class TLSTerminator(Protocol):
    """A platform's TLS termination strategy for CONNECT requests."""

    def handles(self, host: str, port: int) -> bool:
        """Whether this terminator can handle the destination (policy gate)."""
        ...

    def serve(self, handler: Any) -> None:
        """Take over the handler's connection, terminate TLS, then pipe."""
        ...


def _default_connect_upstream(host: str, port: int) -> socket.socket:
    raw = socket.create_connection((host, port), timeout=20)
    context = ssl.create_default_context()  # verifies upstream cert + SAN
    return context.wrap_socket(raw, server_hostname=host)


class MITMTerminator:
    """Reference TLS terminator using an operator-supplied SSL context per host.

    The policy is applied to the **decrypted** request before the upstream call,
    which is the whole point: a placeholder is swapped for the real secret here,
    in the proxy, while the agent's TLS ends at a cert it was made to trust.
    """

    def __init__(
        self,
        context_provider: SSLContextProvider,
        policy: EgressPolicy,
        *,
        connect_upstream: UpstreamConnector | None = None,
    ) -> None:
        self._context_provider = context_provider
        self.policy = policy
        self._connect_upstream = connect_upstream or _default_connect_upstream

    def handles(self, host: str, port: int) -> bool:
        # Decide against the same policy. A host that is not allowed never gets
        # a tunnel established, so no byte reaches a forbidden destination.
        return self.policy.decide(host).allowed

    def apply_policy(self, host: str, headers: Mapping[str, str]) -> dict[str, str]:
        """Public seam for testing the decrypted-request decision."""
        return self.policy.enforce(host, headers)

    def serve(self, handler: Any) -> None:
        """Terminate the client's TLS, apply policy, dial upstream, pipe bytes."""
        authority = handler.path  # e.g. "api.github.com:443"
        host, _, port_str = authority.rpartition(":")
        try:
            port = int(port_str) if port_str else 443
        except ValueError:
            port = 443

        if not self.handles(host, port):
            handler._reply(403, b'{"error":"destination not allowed"}', "application/json")
            handler.close_connection = True
            return

        # Accept the CONNECT. From here the bytes on this socket are TLS from the
        # agent to us; we are the endpoint the agent thinks is the vendor.
        handler.send_response(200, "Connection Established")
        handler.end_headers()
        handler.wfile.flush()

        client: socket.socket | None = None
        upstream: socket.socket | None = None
        try:
            context = self._context_provider(host)
            client = context.wrap_socket(handler.connection, server_side=True)
            client.settimeout(20)
            headers, body = _read_request(client)
            outbound = self.policy.enforce(host, headers)
            request_bytes = _serialise_request(outbound, body)

            upstream = self._connect_upstream(host, port)
            upstream.sendall(request_bytes)
            _pipe(client, upstream)
        except EgressDenied:
            # Decrypted request tried to spend a credential on a host it is not
            # scoped to. The tunnel is dropped; nothing reaches the upstream.
            pass
        except (ssl.SSLError, OSError, ValueError):
            # A failed handshake or dead upstream closes the connection. Never
            # fall back to a blind relay — that is the bypass this layer exists
            # to prevent.
            pass
        finally:
            for sock in (upstream, client):
                if sock is not None:
                    with contextlib.suppress(OSError):
                        sock.close()
            handler.close_connection = True


def _read_request(sock: socket.socket) -> tuple[dict[str, str], bytes]:
    """Read one HTTP request (request line ignored, headers + body returned)."""
    stream = sock.makefile("rb")
    stream.readline()  # request line — method/path are not policy inputs here
    headers: dict[str, str] = {}
    while True:
        line = stream.readline()
        if line in (b"\r\n", b"\n", b""):
            break
        name, _, value = line.decode("latin-1").partition(":")
        headers[name.strip()] = value.strip()
    length = int(headers.get("Content-Length", "0") or "0")
    body = stream.read(length) if length else b""
    stream.close()
    return headers, body


def _serialise_request(outbound: Mapping[str, str], body: bytes) -> bytes:
    """Rebuild the request with the proxy's (credential-injected) headers."""
    lines = [f"{name}: {value}\r\n" for name, value in outbound.items()]
    lines.append("\r\n")
    head = "".join(lines).encode("latin-1")
    return head + body


def _pipe(a: socket.socket, b: socket.socket) -> None:
    """Relay bytes in both directions until either side closes."""

    def relay(src: socket.socket, dst: socket.socket) -> None:
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        except OSError:
            pass
        finally:
            with contextlib.suppress(OSError):
                dst.shutdown(socket.SHUT_WR)

    t1 = threading.Thread(target=relay, args=(a, b), daemon=True)
    t2 = threading.Thread(target=relay, args=(b, a), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()


__all__ = ["MITMTerminator", "SSLContextProvider", "TLSTerminator", "UpstreamConnector"]
