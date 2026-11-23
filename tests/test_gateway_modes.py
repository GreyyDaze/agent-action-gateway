"""Gateway has two modes: custody-only (enforcement elsewhere) and legacy."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from agent_action_gateway.credential.credentials import CredentialRule
from agent_action_gateway.integrations.gateway import GatewayPolicy, Route, SafetyGateway
from agent_action_gateway.storage.traces import TraceStore


class GatewayModeTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.store = TraceStore(Path(self._tmp.name) / "runtime.db")
        self.sent: list[dict] = []

    def _transport(self, upstream, payload, headers):
        self.sent.append({"headers": dict(headers)})
        return 200, {"ok": True}

    def _policy(self) -> GatewayPolicy:
        policy = GatewayPolicy(session_environment="prod")
        policy.register(
            Route(
                path="/deploy",
                upstream="https://api.github.com/deploy",
                action="deploy",
                risk="destructive",
                host="api.github.com",
            )
        )
        return policy

    def test_custody_mode_does_not_enforce_approval(self) -> None:
        """In custody mode the gateway injects but does not hold for approval —
        the wrapped tool owns policy. A key-bound destructive call forwards."""
        policy = self._policy()
        policy.configure_credentials(
            [CredentialRule("TOKEN", "real-secret", frozenset({"api.github.com"}), header="Authorization")],
            allowed_hosts=frozenset({"api.github.com"}),
            enforce_policy=False,
        )
        self.assertFalse(policy.enforcement_enabled)
        gateway = SafetyGateway(self.store, policy, transport=self._transport)
        result = gateway.handle("POST", "/deploy", {"revision": 100})
        self.assertEqual(result.status, 200)
        self.assertEqual(len(self.sent), 1)
        self.assertEqual(self.sent[0]["headers"]["Authorization"], "Bearer real-secret")

    def test_legacy_mode_still_holds_without_approval(self) -> None:
        """Legacy mode keeps the gateway as the sole policy door, so a
        destructive call with no approval is refused. Nothing is forwarded."""
        policy = self._policy()  # enforcement_enabled defaults True
        self.assertTrue(policy.enforcement_enabled)
        gateway = SafetyGateway(self.store, policy, transport=self._transport)
        result = gateway.handle("POST", "/deploy", {"revision": 100})
        self.assertEqual(result.status, 403)
        self.assertTrue(result.body.get("needs_approval"))
        self.assertEqual(self.sent, [])

    def test_custody_mode_retains_caller_scoping(self) -> None:
        """Authentication/route scoping is custody, not policy: it stays even
        when enforcement is off."""
        policy = self._policy()
        policy.configure_credentials(
            [CredentialRule("TOKEN", "real-secret", frozenset({"api.github.com"}))],
            allowed_hosts=frozenset({"api.github.com"}),
        )
        gateway = SafetyGateway(self.store, policy, transport=self._transport)
        vk, master = gateway.resolve_caller("limited")
        self.assertIsNone(vk)
        self.assertFalse(master)


if __name__ == "__main__":
    unittest.main()
