"""Gateway tests: deny-by-default, credential custody, hold-and-release.

The upstream is a local recording server, so these assertions are exact: a
credential leaked to a trace is detectable, and an unregistered route provably
never reaches the network.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
import unittest
from datetime import UTC
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from safety_layer.interface.gateway import (
    GatewayPolicy,
    Route,
    SafetyGateway,
    build_gateway_server,
)
from safety_layer.storage.traces import TraceStore

UPSTREAM_KEY = "sk_upstream_secret_value_for_custody_test"


class RecordingUpstream(BaseHTTPRequestHandler):
    """Stand-in for a real payment API. Records what actually arrived."""

    received: list[dict] = []

    def log_message(self, *args: object) -> None:
        return

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8")
        type(self).received.append(
            {
                "authorization": self.headers.get("Authorization", ""),
                "idempotency_key": self.headers.get("Idempotency-Key", ""),
                "payload": json.loads(raw or "{}"),
            }
        )
        body = json.dumps({"id": "ch_live_1", "status": "succeeded"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class GatewayTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        RecordingUpstream.received = []
        cls.upstream = ThreadingHTTPServer(("127.0.0.1", 0), RecordingUpstream)
        threading.Thread(target=cls.upstream.serve_forever, daemon=True).start()
        cls.upstream_url = f"http://127.0.0.1:{cls.upstream.server_address[1]}/charge"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.upstream.shutdown()
        cls.upstream.server_close()

    def setUp(self) -> None:
        RecordingUpstream.received = []
        self._tmp = tempfile.TemporaryDirectory()
        self.db = Path(self._tmp.name) / "runtime.db"
        self.store = TraceStore(self.db)
        self.env = mock.patch.dict(os.environ, {UPSTREAM_KEY: "sk_upstream_secret_value_for_custody_test"})
        self.env.start()

    def tearDown(self) -> None:
        self.env.stop()
        self._tmp.cleanup()

    def _gateway(self) -> SafetyGateway:
        policy = GatewayPolicy(session_environment="prod")
        policy.register(
            Route(
                path="/charge",
                upstream=self.upstream_url,
                action="charge",
                risk="destructive",
                secret_env=UPSTREAM_KEY,
                environment="prod",
            )
        )
        return SafetyGateway(self.store, policy, transport=self._transport)

    def _transport(self, upstream, payload, headers):
        """Record through the real handler so custody is genuinely exercised."""
        request_line = f"POST {upstream} HTTP/1.1"
        del request_line
        from safety_layer.interface.gateway import _forward

        return _forward(upstream, payload, headers)

    def _approve(self, gateway: SafetyGateway, key: str = "key-1", **overrides):
        """Approval bound to the exact payload including the idempotency key.

        The gateway folds the key into what it hashes, so an approval issued
        for a different key must not pass.
        """
        from datetime import datetime, timedelta

        payload = {"amount": 100, **overrides}
        approval = gateway.approvals.request(
            "charge",
            {**payload, "_idempotency_key": key},
            datetime.now(UTC) + timedelta(minutes=5),
        )
        gateway.approvals.approve(approval.approval_id, "operator")
        return approval, payload

    # -- deny by default --------------------------------------------------

    def test_unregistered_route_is_refused(self) -> None:
        gateway = self._gateway()
        result = gateway.handle("POST", "/not-registered", {"amount": 1})
        self.assertEqual(result.status, 403)
        self.assertEqual(RecordingUpstream.received, [])

    def test_wrong_method_is_refused(self) -> None:
        gateway = self._gateway()
        result = gateway.handle("GET", "/charge", {})
        self.assertEqual(result.status, 403)
        self.assertEqual(RecordingUpstream.received, [])

    # -- credential custody ----------------------------------------------

    def test_upstream_credential_never_appears_in_traces(self) -> None:
        gateway = self._gateway()
        approval, payload = self._approve(gateway)
        gateway.handle(
            "POST", "/charge", payload,
            approval_id=approval.approval_id, idempotency_key="key-1",
        )

        self.assertEqual(len(RecordingUpstream.received), 1)
        # The upstream really did receive the key.
        self.assertIn("sk_upstream_secret_value", RecordingUpstream.received[0]["authorization"])
        # Nothing we persisted contains it.
        self.assertNotIn(
            "sk_upstream_secret_value_for_custody_test", self.db.read_bytes().decode("utf-8", "ignore")
        )

    def test_missing_credential_is_a_clear_error(self) -> None:
        gateway = self._gateway()
        approval, payload = self._approve(gateway)
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(Exception) as raised:
                gateway.handle(
                    "POST", "/charge", payload,
                    approval_id=approval.approval_id, idempotency_key="key-1",
                )
        self.assertIn("credential", str(raised.exception).lower())

    # -- hold and release -------------------------------------------------

    def test_destructive_route_without_approval_is_held(self) -> None:
        gateway = self._gateway()
        result = gateway.handle("POST", "/charge", {"amount": 100})
        self.assertEqual(result.status, 401)
        self.assertTrue(result.body.get("needs_approval"))
        self.assertEqual(RecordingUpstream.received, [], "held call must not forward")

    def test_approved_route_forwards_exactly_once(self) -> None:
        gateway = self._gateway()
        approval, payload = self._approve(gateway)
        result = gateway.handle(
            "POST", "/charge", payload,
            approval_id=approval.approval_id, idempotency_key="key-1",
        )
        self.assertEqual(result.status, 200)
        self.assertEqual(len(RecordingUpstream.received), 1)

    def test_approval_cannot_be_replayed(self) -> None:
        gateway = self._gateway()
        approval, payload = self._approve(gateway)
        gateway.handle(
            "POST", "/charge", payload,
            approval_id=approval.approval_id, idempotency_key="key-1",
        )
        second = gateway.handle(
            "POST", "/charge", payload,
            approval_id=approval.approval_id, idempotency_key="key-1",
        )
        self.assertEqual(second.status, 401)
        self.assertEqual(len(RecordingUpstream.received), 1, "replayed approval caused a second charge")

    def test_idempotency_key_is_forwarded(self) -> None:
        gateway = self._gateway()
        approval, payload = self._approve(gateway)
        gateway.handle(
            "POST", "/charge", payload,
            approval_id=approval.approval_id, idempotency_key="key-1",
        )
        self.assertEqual(RecordingUpstream.received[0]["idempotency_key"], "key-1")

    # -- environment ------------------------------------------------------

    def test_cross_environment_route_is_refused(self) -> None:
        policy = GatewayPolicy(session_environment="staging")
        policy.register(
            Route(path="/charge", upstream=self.upstream_url, action="charge",
                  risk="destructive", environment="prod")
        )
        gateway = SafetyGateway(self.store, policy)
        result = gateway.handle("POST", "/charge", {"amount": 1})
        self.assertEqual(result.status, 403)
        self.assertEqual(RecordingUpstream.received, [])

    # -- transport auth ---------------------------------------------------

    def test_http_transport_requires_a_token(self) -> None:
        import urllib.error
        import urllib.request

        server, handler = build_gateway_server(self.store, GatewayPolicy())
        handler.gateway = self._gateway()
        threading.Thread(target=server.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{server.server_address[1]}"
        try:
            request = urllib.request.Request(
                base + "/charge", data=b"{}", method="POST"
            )
            with self.assertRaises(urllib.error.HTTPError) as raised:
                urllib.request.urlopen(request, timeout=5)
            self.assertEqual(raised.exception.code, 401)
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
