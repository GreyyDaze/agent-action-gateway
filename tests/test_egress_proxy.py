"""Forward proxy: credentials injected only for allowed destinations."""

from __future__ import annotations

import socket
import threading
import unittest

from agent_action_gateway.credential.credentials import CredentialRule, PlaceholderVault
from agent_action_gateway.credential.egress import EgressPolicy
from agent_action_gateway.credential.egress_proxy import ForwardProxy, build_proxy_server


class ForwardProxyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.vault = PlaceholderVault.from_rules(
            [CredentialRule("TOKEN", "real-secret", frozenset({"allowed.example"}))]
        )
        self.policy = EgressPolicy(self.vault, frozenset({"allowed.example"}), inject_headers=False)
        self.calls: list[dict] = []

    def _transport(self, method, url, headers, body):
        self.calls.append({"url": url, "headers": dict(headers)})
        return 200, b'{"ok":true}'

    def test_injects_real_secret_for_allowed_host(self) -> None:
        proxy = ForwardProxy(self.policy, transport=self._transport)
        placeholder = self.vault.agent_environment()["TOKEN"]
        status, _ = proxy.forward("GET", "http://allowed.example/x", {"Authorization": placeholder}, b"")
        self.assertEqual(status, 200)
        self.assertEqual(self.calls[0]["headers"]["Authorization"], "real-secret")

    def test_refuses_host_not_in_allow_list(self) -> None:
        proxy = ForwardProxy(self.policy, transport=self._transport)
        from agent_action_gateway.credential.egress import EgressDenied

        with self.assertRaises(EgressDenied):
            proxy.forward("GET", "http://evil.example/x", {}, b"")
        self.assertEqual(self.calls, [])

    def test_placeholder_for_wrong_host_is_refused(self) -> None:
        self.policy = EgressPolicy(
            self.vault, frozenset({"allowed.example", "other.example"}), inject_headers=False
        )
        proxy = ForwardProxy(self.policy, transport=self._transport)
        placeholder = self.vault.agent_environment()["TOKEN"]
        from agent_action_gateway.credential.egress import EgressDenied

        with self.assertRaises(EgressDenied):
            proxy.forward("GET", "http://other.example/x", {"Authorization": placeholder}, b"")

    def test_hop_by_hop_headers_stripped(self) -> None:
        proxy = ForwardProxy(self.policy, transport=self._transport)
        proxy.forward("GET", "http://allowed.example/x", {"Proxy-Connection": "keep-alive"}, b"")
        self.assertNotIn("proxy-connection", {k.lower() for k in self.calls[0]["headers"]})

    def test_connect_refused_fail_closed(self) -> None:
        proxy = ForwardProxy(self.policy, transport=self._transport)
        server, _ = build_proxy_server(proxy, port=0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            s = socket.create_connection(server.server_address, timeout=5)
            s.sendall(b"CONNECT allowed.example:443 HTTP/1.1\r\nHost: allowed.example\r\n\r\n")
            s.settimeout(5)
            data = s.recv(4096)
            s.close()
            self.assertIn(b"405", data)
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
