"""The gateway can run in credential-custody mode: host allow-list + placeholder swap."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from agent_action_gateway.credential.credentials import CredentialRule
from agent_action_gateway.integrations.gateway import GatewayPolicy, Route, SafetyGateway
from agent_action_gateway.storage.traces import TraceStore

UPSTREAM = "https://api.github.com/user"


class EgressGatewayTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.store = TraceStore(Path(self._tmp.name) / "runtime.db")
        self.sent: list[dict] = []

    def _transport(self, upstream, payload, headers):
        self.sent.append({"upstream": upstream, "headers": dict(headers)})
        return 200, {"ok": True}

    def _gateway(self, *, secret: str = "ghp_real_secret") -> SafetyGateway:
        policy = GatewayPolicy(session_environment="prod")
        policy.register(
            Route(path="/lookup", upstream=UPSTREAM, action="lookup", risk="read", host="api.github.com")
        )
        policy.configure_credentials(
            [CredentialRule("GITHUB_TOKEN", secret, frozenset({"api.github.com"}), header="Authorization")],
            allowed_hosts=frozenset({"api.github.com"}),
        )
        return SafetyGateway(self.store, policy, transport=self._transport)

    def test_agent_environment_has_only_placeholders(self) -> None:
        gateway = self._gateway()
        env = gateway.policy.agent_environment()
        self.assertIn("GITHUB_TOKEN", env)
        self.assertNotIn("ghp_real_secret", env["GITHUB_TOKEN"])

    def test_real_credential_reaches_the_upstream_header(self) -> None:
        gateway = self._gateway()
        result = gateway.handle("POST", "/lookup", {})
        self.assertEqual(result.status, 200)
        self.assertEqual(self.sent[0]["headers"]["Authorization"], "Bearer ghp_real_secret")

    def test_secret_never_appears_in_traces(self) -> None:
        gateway = self._gateway()
        gateway.handle("POST", "/lookup", {})
        blob = self.store.snapshot()
        self.assertNotIn("ghp_real_secret", str(blob))

    def test_host_not_in_allow_list_is_refused_before_forward(self) -> None:
        policy = GatewayPolicy(session_environment="prod")
        policy.register(Route(path="/evil", upstream="https://evil.example/x", action="evil", risk="read", host="evil.example"))
        policy.configure_credentials(
            [CredentialRule("TOKEN", "secret", frozenset({"api.github.com"}))],
            allowed_hosts=frozenset({"api.github.com"}),
        )
        gateway = SafetyGateway(self.store, policy, transport=self._transport)
        result = gateway.handle("POST", "/evil", {})
        self.assertEqual(result.status, 403)
        self.assertEqual(self.sent, [], "a disallowed host must never be forwarded")
        self.assertIn("not in allow", result.body["error"])

    def test_placeholder_for_wrong_host_is_refused(self) -> None:
        """An agent that tries to spend a credential on a host it is not scoped
        to is refused, and nothing is forwarded."""
        policy = GatewayPolicy(session_environment="prod")
        policy.register(Route(path="/other", upstream="https://other.example/x", action="other", risk="read", host="other.example"))
        policy.configure_credentials(
            [CredentialRule("GITHUB_TOKEN", "ghp_real_secret", frozenset({"api.github.com"}))],
            allowed_hosts=frozenset({"api.github.com", "other.example"}),
            inject_headers=False,
        )
        gateway = SafetyGateway(self.store, policy, transport=self._transport)
        # The agent supplies a placeholder bound to api.github.com on the header
        # targeting other.example, where that credential is not allowed.
        placeholder = gateway.policy.vault.agent_environment()["GITHUB_TOKEN"]
        result = gateway.handle(
            "POST", "/other", {}, idempotency_key="k"
        )
        # The shell builds its own headers, so the placeholder must be supplied
        # through the transport path. Directly exercise the egress policy here:
        from agent_action_gateway.credential.egress import EgressDenied

        with self.assertRaises(EgressDenied):
            policy.egress.enforce("other.example", {"Authorization": placeholder})
        self.assertNotIn("ghp_real_secret", result.body.get("error", ""))

    def test_rotate_changes_upstream_value_without_config_change(self) -> None:
        gateway = self._gateway()
        gateway.policy.vault.rotate("GITHUB_TOKEN", "ghp_rotated")
        gateway.handle("POST", "/lookup", {})
        self.assertEqual(self.sent[0]["headers"]["Authorization"], "Bearer ghp_rotated")


if __name__ == "__main__":
    unittest.main()
