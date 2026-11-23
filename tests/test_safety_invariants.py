"""Regression tests for the defects found in the architecture review.

Each test pins a specific failure that shipped in a previous revision, so the
defect cannot be reintroduced silently.
"""

from __future__ import annotations

import re
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from agent_action_gateway.audit.receipts import (
    UnresolvableReceiptError,
    execute_side_effect,
    resolve_unknown,
)
from agent_action_gateway.guards.redaction import redact
from agent_action_gateway.observability.dashboard import build_server
from agent_action_gateway.policy.locks import ApprovalStore
from agent_action_gateway.proofs.fakes import MockEffectProvider
from agent_action_gateway.storage.traces import TraceStore


class ReceiptRecoveryTargetTest(unittest.TestCase):
    """An uncertain side effect must be resolvable, never a KeyError.

    The resolver previously read `arguments["deployment_id"]`, so any approved
    payload that did not literally carry an deployment_id crashed crash recovery.
    """

    def test_recovery_works_for_payload_without_a_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = TraceStore(Path(directory) / "runtime.db")
            provider = MockEffectProvider(dedupe=True)
            execute_side_effect(
                store, provider, "run-1", "step-1", {"revision": 400}, "DEP-100"
            )
            # Simulate the crash window: the effect happened but the local
            # record never advanced past `unknown`.
            with store.connection() as connection:
                connection.execute(
                    "UPDATE receipts SET state='unknown', provider_ref=NULL"
                )

            resolved = resolve_unknown(store, provider)
            self.assertEqual(resolved, 1)
            self.assertEqual(store.unknown_receipts(), [])

    def test_recovery_reports_a_missing_target_instead_of_crashing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = TraceStore(Path(directory) / "runtime.db")
            # A receipt with no replayable target at all must fail loudly; a
            # blind retry would be the exactly-once violation we exist to stop.
            store.create_receipt("run-1", "step-1", "external_action", {"revision": 400})
            with self.assertRaises(UnresolvableReceiptError):
                resolve_unknown(store, MockEffectProvider(dedupe=True))


class RedactionPreservesEvidenceTest(unittest.TestCase):
    """Redaction must remove credentials, never the identifiers we rely on."""

    def test_run_ids_survive_redaction(self) -> None:
        run_id = str(uuid.uuid4())
        self.assertEqual(redact(run_id), run_id)

    def test_provider_references_and_intent_keys_survive(self) -> None:
        intent_key = f"run-1:{uuid.uuid4()}"
        self.assertEqual(redact(intent_key), intent_key)
        self.assertEqual(
            redact({"provider_ref": "mock-" + "a1b2c3" * 8}),
            {"provider_ref": "mock-" + "a1b2c3" * 8},
        )

    def test_nested_uuid_payload_is_intact(self) -> None:
        payload = {"run_id": str(uuid.uuid4()), "nested": [{"id": str(uuid.uuid4())}]}
        self.assertEqual(redact(payload), payload)

    def test_known_credential_shapes_are_still_redacted(self) -> None:
        for secret in (
            "AIza" + "A" * 35,
            "sk-" + "B" * 32,
            "ghp_" + "C" * 36,
            "AKIA" + "D" * 16,
            "xoxb-123456789012-abcdefghijkl",
        ):
            with self.subTest(secret=secret[:8]):
                self.assertEqual(redact(secret), "[REDACTED_SECRET]")

    def test_key_based_and_pii_redaction_still_apply(self) -> None:
        self.assertEqual(redact({"api_key": "anything"}), {"api_key": "[REDACTED_SECRET]"})
        self.assertEqual(redact({"email": "a@b.com"}), {"email": "[REDACTED_PII]"})
        self.assertEqual(redact("contact a@b.com"), "contact [REDACTED_EMAIL]")
        self.assertEqual(redact("Bearer abc.def"), "Bearer [REDACTED_SECRET]")


class DashboardApprovalBoundaryTest(unittest.TestCase):
    """The approval queue is the human trust boundary; POSTs must not be forgeable.

    Any website the operator visits could previously POST an approval form and
    authorize a destructive action, because the endpoints had no CSRF token, no
    origin check, and no security headers.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.db = Path(self._tmp.name) / "runtime.db"
        self.approvals = ApprovalStore(TraceStore(self.db))
        # Each test gets its own approval so one test cannot consume another's.
        self.approval = self.approvals.request(
            "rollback",
            {"deployment_id": "DEP-100", "revision": 400},
            datetime.now(UTC) + timedelta(hours=1),
        )
        self.server, handler = build_server(str(self.db), "127.0.0.1", 0)
        self.token = handler.access_token
        self.port = self.server.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self._tmp.cleanup()

    def _csrf_token(self) -> str:
        request = urllib.request.Request(self.base + "/")
        request.add_header("Authorization", f"Bearer {self.token}")
        html = urllib.request.urlopen(request, timeout=10).read().decode()
        return re.search(r"name='csrf_token' value='([^']+)'", html).group(1)

    def _post(self, fields: dict[str, str], origin: str | None = None) -> int:
        request = urllib.request.Request(
            self.base + "/approvals/approve",
            data=urllib.parse.urlencode(fields).encode(),
            method="POST",
        )
        if origin is not None:
            request.add_header("Origin", origin)
        request.add_header("Authorization", f"Bearer {self.token}")
        try:
            return urllib.request.urlopen(request, timeout=10).status
        except urllib.error.HTTPError as exc:
            return exc.code

    def _get(self, *, authenticated: bool = True) -> str:
        request = urllib.request.Request(self.base + "/")
        if authenticated:
            request.add_header("Authorization", f"Bearer {self.token}")
        return urllib.request.urlopen(request, timeout=10).read().decode()

    def test_approval_form_embeds_a_csrf_token(self) -> None:
        self.assertIn("csrf_token", self._get())

    def test_unauthenticated_read_is_refused(self) -> None:
        """No token, no evidence. CSRF alone does not stop a local process."""
        with self.assertRaises(urllib.error.HTTPError) as raised:
            self._get(authenticated=False)
        self.assertEqual(raised.exception.code, 401)

    def test_unauthenticated_api_state_is_refused(self) -> None:
        with self.assertRaises(urllib.error.HTTPError) as raised:
            urllib.request.urlopen(self.base + "/api/state", timeout=10)
        self.assertEqual(raised.exception.code, 401)

    def test_unauthenticated_post_is_refused(self) -> None:
        """A stolen CSRF token is useless without the dashboard token too."""
        request = urllib.request.Request(
            self.base + "/approvals/approve",
            data=urllib.parse.urlencode(
                {
                    "approval_id": self.approval.approval_id,
                    "approver": "attacker",
                    "csrf_token": self._csrf_token(),
                }
            ).encode(),
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as raised:
            urllib.request.urlopen(request, timeout=10)
        self.assertEqual(raised.exception.code, 401)
        self.assertEqual(
            self.approvals.get(self.approval.approval_id).decision, "pending"
        )

    def test_cross_origin_post_is_rejected(self) -> None:
        status = self._post(
            {"approval_id": self.approval.approval_id, "approver": "attacker"},
            origin="http://evil.example",
        )
        self.assertEqual(status, 403)
        self.assertEqual(self.approvals.get(self.approval.approval_id).decision, "pending")

    def test_post_without_token_is_rejected(self) -> None:
        status = self._post(
            {"approval_id": self.approval.approval_id, "approver": "attacker"}
        )
        self.assertEqual(status, 403)
        self.assertEqual(self.approvals.get(self.approval.approval_id).decision, "pending")

    def test_valid_token_from_foreign_origin_is_rejected(self) -> None:
        status = self._post(
            {
                "approval_id": self.approval.approval_id,
                "approver": "attacker",
                "csrf_token": self._csrf_token(),
            },
            origin="http://evil.example",
        )
        self.assertEqual(status, 403)
        self.assertEqual(self.approvals.get(self.approval.approval_id).decision, "pending")

    def test_responses_carry_security_headers(self) -> None:
        response = urllib.request.urlopen(
            urllib.request.Request(
                self.base + "/", headers={"Authorization": f"Bearer {self.token}"}
            ),
            timeout=10,
        )
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertIn("Content-Security-Policy", response.headers)

    def test_legitimate_same_origin_approval_is_accepted(self) -> None:
        status = self._post(
            {
                "approval_id": self.approval.approval_id,
                "approver": "human-operator",
                "csrf_token": self._csrf_token(),
            },
            origin=self.base,
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            self.approvals.get(self.approval.approval_id).decision, "approved"
        )


class GateExitContractTest(unittest.TestCase):
    """Three outcomes need three exit codes.

    argparse also exits 2, so UNCERTAIN moved to 3 to keep "regressed",
    "could not tell", and "typed wrong" distinguishable in CI.
    """

    def test_exit_codes_are_distinct_and_do_not_collide_with_argparse(self) -> None:
        from agent_action_gateway.gate_cli import EXIT_FAIL, EXIT_PASS, EXIT_UNCERTAIN

        self.assertEqual(EXIT_PASS, 0)
        self.assertEqual(EXIT_FAIL, 1)
        self.assertEqual(EXIT_UNCERTAIN, 3)
        self.assertNotEqual(EXIT_UNCERTAIN, 2)  # argparse usage-error code


class NoLoadBearingAssertsTest(unittest.TestCase):
    """Runtime invariants must not disappear under `python -O`."""

    def test_source_contains_no_bare_asserts(self) -> None:
        import agent_action_gateway

        root = Path(agent_action_gateway.__file__).resolve().parent
        offenders: list[str] = []
        for module in sorted(root.glob("*.py")):
            for number, line in enumerate(
                module.read_text(encoding="utf-8").splitlines(), start=1
            ):
                if line.strip().startswith("assert "):
                    offenders.append(f"{module.name}:{number}")
        self.assertEqual(offenders, [], f"bare asserts found: {offenders}")


class DeadCodeTest(unittest.TestCase):
    """The duplicated stop-rule policy must not be reintroduced.

    runtime.evaluate_tool_result duplicated stop_rules.decide_tool_result
    branch for branch, leaving two copies of the core policy, one unreachable.
    """

    def test_duplicated_decider_is_gone(self) -> None:
        import agent_action_gateway.policy.stop_rules as stop_rules

        self.assertFalse(hasattr(stop_rules, "decide_tool_result"))


if __name__ == "__main__":
    unittest.main()


class PaymentRedactionTest(unittest.TestCase):
    """Payment and identity data must not persist in the clear.

    The original finding was that key-based PII redaction worked but payment
    fields were stored in plaintext, which contradicted our own spec.
    """

    # Fields from the original finding. All must be redacted.
    FINDING_FIELDS = (
        ("card_number", "4111111111111111"),
        ("card", "5555555555554444"),
        ("pan", "4012888888881881"),
        ("cvv", "123"),
        ("cvc", "456"),
        ("cvv2", "789"),
        ("iban", "GB33BUKB20201555555555"),
        ("account_number", "12345678901"),
        ("full_name", "Jane Doe"),
        ("first_name", "Jane"),
        ("last_name", "Doe"),
        ("ssn", "123-45-6789"),
        ("phone", "+15551234567"),
        ("address", "1 Main Street"),
    )

    def test_every_finding_field_is_redacted(self) -> None:
        for field, value in self.FINDING_FIELDS:
            with self.subTest(field=field):
                redacted = redact({field: value})[field]
                self.assertNotEqual(redacted, value, f"{field} leaked in plaintext")
                self.assertTrue(redacted.startswith("[REDACTED"))

    def test_card_numbers_are_redacted_inside_free_text(self) -> None:
        self.assertNotIn("4111111111111111", redact("pay with 4111 1111 1111 1111 now"))

    def test_identifiers_survive_redaction(self) -> None:
        """The counter-test. Over-redaction destroys the evidence traces exist for."""
        run_id = str(uuid.uuid4())
        intent_key = f"run-1:{uuid.uuid4()}"
        provider_ref = "mock-" + "a1b2c3" * 6
        deployment_ref = "dep_3ABCdefGHIjklmnop"
        for payload in (
            {"run_id": run_id},
            {"intent_key": intent_key},
            {"provider_ref": provider_ref},
            {"deployment_ref": deployment_ref},
        ):
            for key, value in payload.items():
                with self.subTest(key=key):
                    self.assertEqual(redact(payload)[key], value, f"{key} was over-redacted")

    def test_uuids_with_long_digit_runs_are_not_mistaken_for_cards(self) -> None:
        """Regression: these came from random UUIDs and were partly redacted.

        About one in 650 random UUIDs held a digit run next to a hex letter that
        passed the card check. The test that found it failed roughly once in a
        few hundred runs, so the cases are fixed here.
        """
        for identifier in (
            "run-1:b2048720-9382-469d-8492-d9a420339dba",
            "run-1:c1455778-9859-40e0-9f92-32f0d428eca2",
            "run-1:24938316-2473-4d73-aad8-68ce851a40eb",
        ):
            with self.subTest(identifier=identifier):
                self.assertEqual(redact(identifier), identifier)

    def test_a_card_next_to_punctuation_is_still_redacted(self) -> None:
        for text in ("card: 4111111111111111.", "(4111 1111 1111 1111)", "pan=4111-1111-1111-1111;"):
            with self.subTest(text=text):
                self.assertNotIn("4111", redact(text))

    def test_non_card_digit_runs_are_not_treated_as_cards(self) -> None:
        """A long identifier that fails Luhn is evidence, not a card."""
        self.assertEqual(redact("order-0000000001234567890"), "order-0000000001234567890")

    def test_luhn_validation(self) -> None:
        from agent_action_gateway.guards.redaction import luhn_valid

        self.assertTrue(luhn_valid("4111111111111111"))
        self.assertFalse(luhn_valid("4111111111111112"))
        self.assertFalse(luhn_valid("123"))
