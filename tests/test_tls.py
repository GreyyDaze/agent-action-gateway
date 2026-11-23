"""TLS terminator hook: default fails closed; a terminator applies policy to decrypted requests."""

from __future__ import annotations

import socket
import threading
import unittest
from unittest import mock

from safety_layer.credential.credentials import CredentialRule, PlaceholderVault
from safety_layer.credential.egress import EgressDenied, EgressPolicy
from safety_layer.credential.egress_proxy import ForwardProxy, build_proxy_server
from safety_layer.credential.tls import MITMTerminator


class TerminatorTest(unittest.TestCase):
    def setUp(self) -> None:
        self.vault = PlaceholderVault.from_rules(
            [CredentialRule("TOKEN", "real-secret", frozenset({"api.github.com"}))]
        )
        self.policy = EgressPolicy(self.vault, frozenset({"api.github.com"}), inject_headers=False)

    def test_handles_refuses_disallowed_host_before_tunnel(self) -> None:
        terminator = MITMTerminator(context_provider=mock.Mock(), policy=self.policy)
        self.assertTrue(terminator.handles("api.github.com", 443))
        self.assertFalse(terminator.handles("evil.example", 443))

    def test_apply_policy_injects_for_allowed_host(self) -> None:
        terminator = MITMTerminator(context_provider=mock.Mock(), policy=self.policy)
        placeholder = self.vault.agent_environment()["TOKEN"]
        headers = terminator.apply_policy("api.github.com", {"Authorization": placeholder})
        self.assertEqual(headers["Authorization"], "real-secret")

    def test_apply_policy_refuses_wrong_host(self) -> None:
        terminator = MITMTerminator(context_provider=mock.Mock(), policy=self.policy)
        placeholder = self.vault.agent_environment()["TOKEN"]
        # Build a policy that would allow the host so the swap is the only gate.
        from safety_layer.credential.egress import EgressPolicy as EP

        wide = EP(self.vault, frozenset({"api.github.com", "other.example"}), inject_headers=False)
        terminator = MITMTerminator(context_provider=mock.Mock(), policy=wide)
        with self.assertRaises(EgressDenied):
            terminator.apply_policy("other.example", {"Authorization": placeholder})

    def test_proxy_refuses_connect_without_terminator(self) -> None:
        proxy = ForwardProxy(self.policy)
        server, _ = build_proxy_server(proxy, port=0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            s = socket.create_connection(server.server_address, timeout=5)
            s.sendall(b"CONNECT api.github.com:443 HTTP/1.1\r\nHost: api.github.com\r\n\r\n")
            s.settimeout(5)
            self.assertIn(b"405", s.recv(4096))
            s.close()
        finally:
            server.shutdown()
            server.server_close()

    def test_proxy_delegates_connect_to_terminator(self) -> None:
        called: list[str] = []

        class FakeTerminator:
            def handles(self, host: str, port: int) -> bool:
                return True

            def serve(self, handler: object) -> None:
                called.append("served")
                handler._reply(200, b"ok")  # type: ignore[attr-defined]
                handler.close_connection = True  # type: ignore[attr-defined]

        proxy = ForwardProxy(self.policy, tls_terminator=FakeTerminator())
        server, _ = build_proxy_server(proxy, port=0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            s = socket.create_connection(server.server_address, timeout=5)
            s.sendall(b"CONNECT api.github.com:443 HTTP/1.1\r\nHost: api.github.com\r\n\r\n")
            s.settimeout(5)
            response = s.recv(4096)
            s.close()
            self.assertIn(b"200", response)
            self.assertEqual(called, ["served"])
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
