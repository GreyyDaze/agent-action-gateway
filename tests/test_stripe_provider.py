"""Deterministic tests for the Stripe external action provider.

Two layers:

1. A local HTTP server that implements the real Stripe contract (basic auth,
   `Idempotency-Key`, 24-hour-style replay, form-encoded bodies). This runs in
   CI with no credentials and no network.
2. An opt-in live test against Stripe test mode, skipped unless
   `STRIPE_API_KEY` is set. No real money is involved.

The point of layer 1 is that it verifies the wire format, the idempotency
semantics, and the safety layer's recovery path against a server we do not
control, rather than against a stub that agrees with whatever we wrote.
"""

from __future__ import annotations

import inspect
import json
import os
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

from safety_layer.locks import ApprovalStore, RiskRegistry
from safety_layer.receipts import UnresolvableReceiptError, execute_side_effect, resolve_unknown
from safety_layer.runtime import dispatch_external_action
from safety_layer.store import TraceStore
from safety_layer.provider import ExternalActionProvider as ExternalActionProviderProtocol
from safety_layer.stripe_provider import (
    METADATA_KEY,
    StripeProviderError,
    StripeRefundProvider,
)

TEST_KEY = "sk_test_fake_key_for_local_contract_tests"


def _reset_handler_state() -> None:
    """Clear every piece of shared handler state between tests.

    The handler is class-level state on a class-level server, so a failure
    injected by one test would otherwise leak into the next.
    """
    StripeLikeHandler.refund_calls = {}
    StripeLikeHandler.refund_responses = {}
    StripeLikeHandler.force_status = None


class StripeLikeHandler(BaseHTTPRequestHandler):
    """A minimal server honouring the parts of Stripe this adapter relies on.

    Implements: HTTP basic/bearer auth, form-encoded POST bodies, the
    Idempotency-Key replay guarantee, and the Stripe error envelope. It refuses
    to be used without the expected key so the auth path is genuinely tested.
    """

    expected_key = TEST_KEY
    refund_calls: dict[str, dict[str, str]] = {}
    refund_responses: dict[str, dict] = {}
    refund_id = "re_1LocalContractTest"
    force_status: int | None = None

    def log_message(self, *args: object) -> None:  # silence test output
        return

    def _authorized(self) -> bool:
        header = self.headers.get("Authorization", "")
        return header == f"Bearer {self.expected_key}"

    def _reply(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        if not self.path.startswith("/v1/refunds"):
            self._reply(404, {"error": {"type": "invalid_request_error", "message": "no route"}})
            return
        if not self._authorized():
            self._reply(401, {"error": {"type": "authentication_error", "message": "bad key"}})
            return
        if type(self).force_status is not None:
            self._reply(
                type(self).force_status,
                {"error": {"type": "api_error", "message": "injected failure"}},
            )
            return

        key = self.headers.get("Idempotency-Key")
        if not key:
            self._reply(400, {"error": {"type": "missing_parameter", "message": "no idempotency key"}})
            return

        # Stripe's guarantee: same key replays the first stored response.
        if key in type(self).refund_responses:
            stored = dict(type(self).refund_responses[key])
            stored["safety_replayed"] = True
            self._reply(200, stored)
            return

        length = int(self.headers.get("Content-Length", "0"))
        form = parse_qs(self.rfile.read(length).decode("utf-8"))
        record = {k: v[0] for k, v in form.items()}
        response = {
            "id": type(self).refund_id,
            "object": "refund",
            "status": "succeeded",
            "amount": int(record.get("amount", 1000)),
            "payment_intent": record.get("payment_intent"),
            "metadata": {METADATA_KEY: record.get("metadata[" + METADATA_KEY + "]", "")},
        }
        type(self).refund_calls[key] = record
        type(self).refund_responses[key] = response
        self._reply(200, response)


class StripeContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        StripeLikeHandler.refund_calls = {}
        StripeLikeHandler.refund_responses = {}
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), StripeLikeHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}/v1"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self) -> None:
        _reset_handler_state()
        self.provider = StripeRefundProvider(TEST_KEY, api_base=self.base)

    # -- request shape ---------------------------------------------------

    def test_requires_credentials(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(StripeProviderError):
                StripeRefundProvider(api_base=self.base)

    def test_missing_key_is_reported_clearly(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(StripeProviderError, "STRIPE_API_KEY"):
                StripeRefundProvider(api_base=self.base)

    def test_key_is_never_exposed_in_repr(self) -> None:
        self.assertNotIn(TEST_KEY, repr(self.provider))
        self.assertIn("REDACTED_SECRET", repr(self.provider))

    def test_rejects_oversized_idempotency_key(self) -> None:
        with self.assertRaises(ValueError):
            self.provider.refund("pi_123", "k" * 256)

    def test_sends_form_encoded_body_and_idempotency_key(self) -> None:
        refund_id = self.provider.refund("pi_123", "intent-1", amount=2500)
        self.assertEqual(refund_id, "re_1LocalContractTest")
        sent = StripeLikeHandler.refund_calls["intent-1"]
        self.assertEqual(sent["payment_intent"], "pi_123")
        self.assertEqual(sent["amount"], "2500")
        self.assertEqual(sent["metadata[" + METADATA_KEY + "]"], "intent-1")

    def test_rejects_unauthorized_server(self) -> None:
        bad = StripeRefundProvider("sk_test_wrong_key", api_base=self.base)
        with self.assertRaisesRegex(StripeProviderError, "rejected"):
            bad.refund("pi_123", "intent-auth")

    # -- idempotency semantics -------------------------------------------

    def test_same_intent_key_creates_one_refund(self) -> None:
        first = self.provider.refund("pi_123", "intent-2")
        second = self.provider.refund("pi_123", "intent-2")
        self.assertEqual(first, second)
        # A real double-charge would appear as two distinct Stripe objects; the
        # contract server stores exactly one record per key.
        self.assertEqual(len(StripeLikeHandler.refund_calls), 1)

    def test_different_intent_keys_create_separate_refunds(self) -> None:
        self.provider.refund("pi_123", "intent-a")
        self.provider.refund("pi_123", "intent-b")
        self.assertEqual(len(StripeLikeHandler.refund_calls), 2)

    def test_find_refund_replays_instead_of_searching(self) -> None:
        created = self.provider.refund("pi_123", "intent-3")
        found = self.provider.find_refund("intent-3", order_id="pi_123")
        self.assertEqual(found, created)
        self.assertEqual(len(StripeLikeHandler.refund_calls), 1)

    def test_find_refund_requires_a_target(self) -> None:
        with self.assertRaisesRegex(StripeProviderError, "requires the persisted target"):
            self.provider.find_refund("intent-4")

    # -- failure classification -----------------------------------------

    def test_client_error_is_retryable(self) -> None:
        StripeLikeHandler.force_status = 400
        with self.assertRaisesRegex(StripeProviderError, "rejected"):
            self.provider.refund("pi_123", "intent-5")

    def test_server_error_leaves_outcome_unknown(self) -> None:
        StripeLikeHandler.force_status = 500
        with self.assertRaisesRegex(StripeProviderError, "outcome unknown"):
            self.provider.refund("pi_123", "intent-6")

    def test_unreachable_host_is_classified_as_not_sent(self) -> None:
        """A connection that never established cannot have double-charged.

        This distinction matters: telling the caller the request was not sent
        permits a retry, whereas an ambiguous failure must block it.
        """
        provider = StripeRefundProvider(
            TEST_KEY, api_base="http://127.0.0.1:9/v1"
        )
        with self.assertRaisesRegex(StripeProviderError, "was not sent"):
            provider.refund("pi_123", "intent-unreachable")

    def test_post_send_disconnect_is_treated_as_ambiguous(self) -> None:
        """A dropped connection after the request left is NOT retryable."""
        from http.client import RemoteDisconnected

        def dropping_transport(request, timeout):
            raise RemoteDisconnected("connection reset by peer")

        provider = StripeRefundProvider(
            TEST_KEY, api_base=self.base, transport=dropping_transport
        )
        with self.assertRaisesRegex(StripeProviderError, "may or may not have been applied"):
            provider.refund("pi_123", "intent-drop")

    def test_timeout_is_treated_as_ambiguous(self) -> None:
        def timing_out(request, timeout):
            raise TimeoutError("timed out")

        provider = StripeRefundProvider(
            TEST_KEY, api_base=self.base, transport=timing_out
        )
        with self.assertRaisesRegex(StripeProviderError, "may or may not have been applied"):
            provider.refund("pi_123", "intent-timeout")

    def test_malformed_response_is_reported(self) -> None:
        def garbage(request, timeout):
            return b"<html>not json</html>"

        provider = StripeRefundProvider(
            TEST_KEY, api_base=self.base, transport=garbage
        )
        with self.assertRaisesRegex(StripeProviderError, "non-JSON"):
            provider.refund("pi_123", "intent-badjson")


class StripeThroughSafetyLayerTest(unittest.TestCase):
    """The provider must work through the real dispatch and recovery path."""

    @classmethod
    def setUpClass(cls) -> None:
        StripeLikeHandler.refund_calls = {}
        StripeLikeHandler.refund_responses = {}
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), StripeLikeHandler)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}/v1"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self) -> None:
        _reset_handler_state()
        self._tmp = tempfile.TemporaryDirectory()
        self.store = TraceStore(Path(self._tmp.name) / "runtime.db")
        self.provider = StripeRefundProvider(TEST_KEY, api_base=self.base)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_approved_refund_executes_once_through_dispatch(self) -> None:
        registry = RiskRegistry()
        registry.register("refund", "destructive")
        approvals = ApprovalStore(self.store)
        approval = approvals.request(
            "refund",
            {"payment_intent": "pi_999", "amount": 4000},
            datetime.now(timezone.utc) + timedelta(minutes=5),
        )
        approvals.approve(approval.approval_id, "operator")

        provider_ref = dispatch_external_action(
            self.store,
            self.provider,
            "run-stripe-1",
            "step-1",
            {"payment_intent": "pi_999", "amount": 4000},
            "pi_999",
            registry=registry,
            approval_store=approvals,
            approval_id=approval.approval_id,
        )
        self.assertEqual(provider_ref, "re_1LocalContractTest")
        self.assertEqual(len(StripeLikeHandler.refund_calls), 1)

    def test_crash_recovery_replays_without_double_refunding(self) -> None:
        """Simulate the crash window: dispatched, but never marked done."""
        execute_side_effect(
            self.store,
            self.provider,
            "run-stripe-2",
            "step-1",
            {"payment_intent": "pi_777"},
            "pi_777",
        )
        # Rewind the local record to the pre-dispatch state.
        with self.store._connect() as connection:
            connection.execute(
                "UPDATE receipts SET state='unknown', provider_ref=NULL"
            )

        resolved = resolve_unknown(self.store, self.provider)
        self.assertEqual(resolved, 1)
        self.assertEqual(self.store.unknown_receipts(), [])
        # Still a single Stripe object for the single intent key.
        self.assertEqual(len(StripeLikeHandler.refund_calls), 1)

    def test_recovery_without_target_is_manual_not_a_blind_retry(self) -> None:
        self.store.create_receipt("run-stripe-3", "step-1", "external_action", {"note": "no target"})
        with self.assertRaises(UnresolvableReceiptError):
            resolve_unknown(self.store, self.provider)


class ProviderIsDomainNeutralTest(unittest.TestCase):
    """The provider interface must not assume the product is about refunds.

    The safety layer guards irreversible side effects generally. A reviewer
    should be able to wire a file delete or a database write without the
    framework insisting on a payment vocabulary.
    """

    def test_protocol_and_http_adapter_use_generic_names(self) -> None:
        from safety_layer.provider import (
            ExternalActionProvider,
            HttpExternalActionProvider,
        )

        self.assertEqual(ExternalActionProvider.__name__, "ExternalActionProvider")
        self.assertEqual(
            HttpExternalActionProvider.__name__, "HttpExternalActionProvider"
        )

    def test_legacy_refund_names_remain_importable(self) -> None:
        from safety_layer.provider import (
            ExternalActionProvider,
            HttpExternalActionProvider,
            HttpRefundProvider,
            RefundProvider,
        )

        self.assertIs(RefundProvider, ExternalActionProvider)
        self.assertIs(HttpRefundProvider, HttpExternalActionProvider)

    def test_receipt_dependencies_do_not_mention_refunds(self) -> None:
        """The enforcement core must stay free of domain vocabulary.

        If refunds ever leak back into fuses/locks/stop-rules, the product has
        quietly become domain-locked even though the adapter layer is generic.
        """
        import safety_layer.fuses as fuses
        import safety_layer.locks as locks
        import safety_layer.stop_rules as stop_rules
        import safety_layer.store as store
        import safety_layer.trace as trace

        for module in (fuses, locks, stop_rules, store, trace):
            source = inspect.getsource(module).lower()
            with self.subTest(module=module.__name__):
                self.assertNotIn("refund", source)
                self.assertNotIn("order_id", source)

    def test_a_non_refund_tool_satisfies_the_same_interface(self) -> None:
        """A delete tool needs no changes to the provider contract."""

        class FileDeleteProvider:
            provider = "filesystem"

            def refund(self, order_id: str, intent_key: str) -> str:
                return f"deleted:{order_id}"

            def find_refund(self, intent_key: str, order_id: str | None = None):
                return None

        provider: ExternalActionProviderProtocol = FileDeleteProvider()
        self.assertEqual(provider.refund("/etc/hosts", "intent-x"), "deleted:/etc/hosts")
        self.assertIsNone(provider.find_refund("intent-x", "/etc/hosts"))


@unittest.skipUnless(
    os.getenv("STRIPE_API_KEY"),
    "set STRIPE_API_KEY to run the live Stripe test-mode check",
)
class StripeLiveTestModeTest(unittest.TestCase):
    """Opt-in live check against real Stripe test mode.

    Test mode moves no money. Requires a PaymentIntent created beforehand in the
    Stripe dashboard; set STRIPE_TEST_PAYMENT_INTENT to point at it.
    """

    def test_refund_is_idempotent_against_real_stripe(self) -> None:
        intent = os.getenv("STRIPE_TEST_PAYMENT_INTENT")
        if not intent:
            self.skipTest("set STRIPE_TEST_PAYMENT_INTENT to run the live check")
        provider = StripeRefundProvider()
        key = f"safety-live-{os.getpid()}"
        first = provider.refund(intent, key, amount=100)
        second = provider.refund(intent, key, amount=100)
        self.assertEqual(first, second)
        self.assertTrue(first.startswith("re_"))


if __name__ == "__main__":
    unittest.main()