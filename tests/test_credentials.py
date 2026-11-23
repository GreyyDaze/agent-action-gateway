"""Credential custody: the agent sees placeholders, the proxy holds real secrets."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
import urllib.request
from pathlib import Path
from unittest import mock

from safety_layer.credential.credentials import (
    PLACEHOLDER_PREFIX,
    CredentialError,
    CredentialNotAllowed,
    CredentialRule,
    EnvSecretResolver,
    HttpSecretResolver,
    PlaceholderVault,
)
from safety_layer.credential.egress import (
    EgressDenied,
    EgressPolicy,
    forbidden_ip,
    safe_host,
)


class ResolverTest(unittest.TestCase):
    def test_env_resolver_reads_a_variable(self) -> None:
        with mock.patch.dict(os.environ, {"TOKEN": "real-secret"}):
            self.assertEqual(EnvSecretResolver().resolve("TOKEN"), "real-secret")

    def test_env_resolver_missing_is_an_error(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(CredentialError):
                EnvSecretResolver().resolve("TOKEN")

    def test_file_resolver_refuses_world_readable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "secret"
            path.write_text("real-secret")
            path.chmod(0o644)
            with self.assertRaises(CredentialError):
                EnvSecretResolver().resolve(f"file:{path}")

    def test_file_resolver_accepts_0600(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "secret"
            path.write_text("real-secret")
            path.chmod(0o600)
            self.assertEqual(EnvSecretResolver().resolve(f"file:{path}"), "real-secret")

    def test_http_resolver_walks_kv_v2_shape(self) -> None:
        def transport(request: urllib.request.Request, timeout: float) -> bytes:
            self.assertEqual(request.get_header("X-vault-token"), "vault-token")
            return json.dumps({"data": {"data": {"value": "from-vault"}}}).encode()

        with mock.patch.dict(os.environ, {"VAULT_TOKEN": "vault-token"}):
            resolver = HttpSecretResolver(
                "https://vault.example/v1/secret", "VAULT_TOKEN", transport=transport
            )
            self.assertEqual(resolver.resolve("github"), "from-vault")


class VaultTest(unittest.TestCase):
    def setUp(self) -> None:
        self.vault = PlaceholderVault.from_rules(
            [
                CredentialRule("GITHUB_TOKEN", "ghp_real", frozenset({"api.github.com"})),
                CredentialRule(
                    "AWS_KEY",
                    "aws-real",
                    frozenset({"sts.amazonaws.com"}),
                    header="Authorization",
                ),
            ]
        )

    def test_agent_environment_contains_only_placeholders(self) -> None:
        env = self.vault.agent_environment()
        self.assertEqual(set(env), {"GITHUB_TOKEN", "AWS_KEY"})
        for value in env.values():
            self.assertTrue(value.startswith(PLACEHOLDER_PREFIX))
            self.assertNotIn("ghp_real", value)
            self.assertNotIn("aws-real", value)

    def test_swap_replaces_placeholder_for_allowed_host(self) -> None:
        placeholder = self.vault.agent_environment()["GITHUB_TOKEN"]
        result = self.vault.swap({"Authorization": f"Bearer {placeholder}"}, "api.github.com")
        self.assertEqual(result["Authorization"], "Bearer ghp_real")

    def test_swap_refuses_placeholder_for_other_host(self) -> None:
        placeholder = self.vault.agent_environment()["GITHUB_TOKEN"]
        with self.assertRaises(CredentialNotAllowed):
            self.vault.swap({"Authorization": f"Bearer {placeholder}"}, "evil.example")

    def test_unknown_token_left_alone(self) -> None:
        result = self.vault.swap({"X-Trace": "ordinary-value"}, "api.github.com")
        self.assertEqual(result["X-Trace"], "ordinary-value")

    def test_rotate_keeps_placeholder_stable_and_changes_value(self) -> None:
        before = self.vault.agent_environment()["GITHUB_TOKEN"]
        self.vault.rotate("GITHUB_TOKEN", "ghp_rotated")
        after = self.vault.agent_environment()["GITHUB_TOKEN"]
        self.assertEqual(after, before)
        result = self.vault.swap({"Authorization": before}, "api.github.com")
        self.assertEqual(result["Authorization"], "ghp_rotated")

    def test_expired_credential_refused(self) -> None:
        self.vault.rotate("GITHUB_TOKEN", "ghp_real", expires_at=1.0)
        placeholder = self.vault.agent_environment()["GITHUB_TOKEN"]
        with self.assertRaises(CredentialError):
            self.vault.swap({"Authorization": placeholder}, "api.github.com", now=2.0)

    def test_injected_adds_header_for_header_mode(self) -> None:
        result = self.vault.injected({}, "sts.amazonaws.com")
        self.assertEqual(result["Authorization"], "Bearer aws-real")

    def test_injected_does_not_add_header_for_wrong_host(self) -> None:
        result = self.vault.injected({}, "api.github.com")
        self.assertNotIn("Authorization", result)


class EgressTest(unittest.TestCase):
    def test_forbidden_ips(self) -> None:
        for address in ("127.0.0.1", "10.0.0.5", "169.254.169.254", "::1", "192.168.1.1"):
            self.assertTrue(forbidden_ip(address), address)
        self.assertFalse(forbidden_ip("140.82.112.3"))

    def test_safe_host_rejects_metadata_via_dns(self) -> None:
        self.assertFalse(safe_host("api.example.com", dns=lambda _: ["169.254.169.254"]))

    def test_safe_host_rejects_localhost(self) -> None:
        self.assertFalse(safe_host("localhost"))
        self.assertFalse(safe_host("metadata.google.internal"))

    def test_policy_allows_only_listed_host(self) -> None:
        vault = PlaceholderVault.from_rules(
            [CredentialRule("TOKEN", "real", frozenset({"api.github.com"}))]
        )
        policy = EgressPolicy(vault, frozenset({"api.github.com"}))
        self.assertTrue(policy.decide("api.github.com").allowed)
        self.assertFalse(policy.decide("evil.example").allowed)

    def test_policy_releases_secret_only_to_allowed_host(self) -> None:
        vault = PlaceholderVault.from_rules(
            [CredentialRule("TOKEN", "real", frozenset({"api.github.com"}))]
        )
        policy = EgressPolicy(vault, frozenset({"api.github.com", "evil.example"}))
        placeholder = vault.agent_environment()["TOKEN"]
        headers = policy.enforce("api.github.com", {"Authorization": placeholder})
        self.assertEqual(headers["Authorization"], "real")
        with self.assertRaises(EgressDenied):
            policy.enforce("evil.example", {"Authorization": placeholder})

    def test_audit_never_contains_the_secret(self) -> None:
        seen: list[dict] = []
        vault = PlaceholderVault.from_rules(
            [CredentialRule("TOKEN", "super-secret-value", frozenset({"api.github.com"}))]
        )
        policy = EgressPolicy(vault, frozenset({"api.github.com"}), audit=seen.append)
        placeholder = vault.agent_environment()["TOKEN"]
        policy.decide("api.github.com", {"Authorization": placeholder})
        self.assertEqual(len(seen), 1)
        self.assertNotIn("super-secret-value", json.dumps(seen))

    def test_forbidden_destination_refused_even_if_listed(self) -> None:
        vault = PlaceholderVault.from_rules([])
        policy = EgressPolicy(vault, frozenset({"169.254.169.254"}))
        self.assertFalse(policy.decide("169.254.169.254").allowed)


if __name__ == "__main__":
    unittest.main()
