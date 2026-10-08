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
from datetime import datetime, timedelta, timezone
from pathlib import Path

from safety_layer.dashboard import build_server
from safety_layer.locks import ApprovalStore
from safety_layer.mock_provider import MockPaymentProvider
from safety_layer.receipts import (
    UnresolvableReceiptError,
    execute_side_effect,
    resolve_unknown,
)
from safety_layer.store import TraceStore
from safety_layer.trace import redact


class ReceiptRecoveryTargetTest(unittest.TestCase):
    """R-11: an uncertain side effect must be resolvable, never a KeyError.

    The resolver previously read `arguments["order_id"]`, so any approved
    payload that did not literally carry an order_id crashed crash recovery.
    """

    def test_recovery_works_for_payload_without_order_id(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = TraceStore(Path(directory) / "runtime.db")
            provider = MockPaymentProvider(dedupe=True)
            execute_side_effect(
                store, provider, "run-1", "step-1", {"amount": 400}, "ORD-100"
            )
            # Simulate the crash window: the effect happened but the local
            # record never advanced past `unknown`.
            with store._connect() as connection:
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
            store.create_receipt("run-1", "step-1", "external_action", {"amount": 400})
            with self.assertRaises(UnresolvableReceiptError):
                resolve_unknown(store, MockPaymentProvider(dedupe=True))


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


class NoFabricatedVerdictTest(unittest.TestCase):
    """A completed run has not been evaluated and must never claim PASS.

    The old path compared a hardcoded score of 1.0 against a threshold of 0.8 and
    persisted PASS for every successful run, manufacturing durable evidence that
    no evaluation produced.
    """

    def test_completed_run_is_not_recorded_as_pass(self) -> None:
        from safety_layer.runtime import run

        with tempfile.TemporaryDirectory() as directory:
            store = TraceStore(Path(directory) / "runtime.db")
            result = run(lambda task: "done", "a task", store)
            self.assertEqual(result["status"], "completed")
            self.assertNotEqual(result["run_status"], "PASS")
            verdicts = [v["verdict"] for v in store.snapshot()["gate_verdicts"]]
            self.assertNotIn("PASS", verdicts)
            self.assertIn("NOT_EVALUATED", verdicts)

    def test_failed_run_is_recorded_as_failed(self) -> None:
        from safety_layer.runtime import run

        def boom(task: str) -> str:
            raise RuntimeError("nope")

        with tempfile.TemporaryDirectory() as directory:
            store = TraceStore(Path(directory) / "runtime.db")
            result = run(boom, "a task", store)
            self.assertEqual(result["run_status"], "FAIL")


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
            "refund",
            {"order_id": "ORD-100", "amount": 400},
            datetime.now(timezone.utc) + timedelta(hours=1),
        )
        self.server = build_server(str(self.db), "127.0.0.1", 0)
        self.port = self.server.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self._tmp.cleanup()

    def _csrf_token(self) -> str:
        html = urllib.request.urlopen(self.base + "/", timeout=10).read().decode()
        return re.search(r"name='csrf_token' value='([^']+)'", html).group(1)

    def _post(self, fields: dict[str, str], origin: str | None = None) -> int:
        request = urllib.request.Request(
            self.base + "/approvals/approve",
            data=urllib.parse.urlencode(fields).encode(),
            method="POST",
        )
        if origin is not None:
            request.add_header("Origin", origin)
        try:
            return urllib.request.urlopen(request, timeout=10).status
        except urllib.error.HTTPError as exc:
            return exc.code

    def _get(self) -> str:
        return urllib.request.urlopen(self.base + "/", timeout=10).read().decode()

    def test_approval_form_embeds_a_csrf_token(self) -> None:
        self.assertIn("csrf_token", self._get())

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
        response = urllib.request.urlopen(self.base + "/", timeout=10)
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
        from safety_layer.gate_cli import EXIT_FAIL, EXIT_PASS, EXIT_UNCERTAIN

        self.assertEqual(EXIT_PASS, 0)
        self.assertEqual(EXIT_FAIL, 1)
        self.assertEqual(EXIT_UNCERTAIN, 3)
        self.assertNotEqual(EXIT_UNCERTAIN, 2)  # argparse usage-error code


class NoLoadBearingAssertsTest(unittest.TestCase):
    """Runtime invariants must not disappear under `python -O`."""

    def test_source_contains_no_bare_asserts(self) -> None:
        import safety_layer

        root = Path(safety_layer.__file__).resolve().parent
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
        import safety_layer.stop_rules as stop_rules

        self.assertFalse(hasattr(stop_rules, "decide_tool_result"))


if __name__ == "__main__":
    unittest.main()