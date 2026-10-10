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
import time
import unittest
import urllib.error
import urllib.request
from datetime import UTC
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from safety_layer.interface.gateway import (
    GatewayPolicy,
    Route,
    SafetyGateway,
    VirtualKey,
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
        # 403, not 401: the caller proved who it is and lacks authorisation.
        # Reusing 401 made "awaiting approval" look like "invalid key".
        self.assertEqual(result.status, 403)
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
        self.assertEqual(second.status, 403)  # awaiting approval, not a bad token
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

        os.environ["SAFETY_GATEWAY"] = "1"
        try:
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
        finally:
            del os.environ["SAFETY_GATEWAY"]


class CallerAuthTest(unittest.TestCase):
    """Who may call the gateway, and on which routes.

    The gateway holds the upstream key, so the caller is the untrusted side.
    A valid key for one route must not become a key for another, and an
    unregistered path must not be distinguishable from one the key cannot use.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.store = TraceStore(Path(self._tmp.name) / "runtime.db")
        os.environ["SAFETY_GATEWAY"] = "1"
        os.environ["TEST_MASTER_KEY"] = "master-value"
        self.addCleanup(self._cleanup)

    def _cleanup(self) -> None:
        os.environ.pop("SAFETY_GATEWAY", None)
        os.environ.pop("TEST_MASTER_KEY", None)
        self._tmp.cleanup()

    def _policy(self) -> GatewayPolicy:
        policy = GatewayPolicy(session_environment="prod", master_key_env="TEST_MASTER_KEY")
        for path, action in (("/charge", "charge"), ("/refund", "refund")):
            policy.register(
                Route(path=path, upstream="http://127.0.0.1:1" + path, action=action, risk="read")
            )
        return policy

    def _call(self, policy, path, token):
        server, handler = build_gateway_server(self.store, policy, port=0)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        request = urllib.request.Request(
            f"http://127.0.0.1:{server.server_address[1]}{path}", data=b"{}", method="POST"
        )
        if token is not None:
            request.add_header("Authorization", f"Bearer {token}")
        try:
            with self.assertRaises(urllib.error.HTTPError) as raised:
                urllib.request.urlopen(request, timeout=5)
            return raised.exception.code, raised.exception.read().decode()
        finally:
            server.shutdown()
            server.server_close()

    def test_missing_token_is_refused(self) -> None:
        self.assertEqual(self._call(self._policy(), "/charge", None)[0], 401)

    def test_unknown_token_is_refused(self) -> None:
        self.assertEqual(self._call(self._policy(), "/charge", "not-a-key")[0], 401)

    def test_virtual_key_may_not_use_a_route_it_was_not_issued_for(self) -> None:
        policy = self._policy()
        policy.virtual_keys["k"] = VirtualKey(
            key="k", name="limited", routes=frozenset({"/charge"})
        )
        code, body = self._call(policy, "/refund", "k")
        self.assertEqual(code, 403)
        self.assertIn("not authorized for route", body)

    def test_unregistered_path_is_refused_before_route_scoping(self) -> None:
        """A path that does not exist must not be distinguishable from one the
        key cannot use, or the gateway becomes a route-existence oracle."""
        policy = self._policy()
        policy.virtual_keys["k"] = VirtualKey(
            key="k", name="limited", routes=frozenset({"/charge"})
        )
        code, body = self._call(policy, "/admin", "k")
        self.assertEqual(code, 403)
        self.assertIn("route not registered", body)

    def test_revoked_key_is_refused(self) -> None:
        policy = self._policy()
        policy.virtual_keys["k"] = VirtualKey(
            key="k", name="gone", routes=frozenset({"/charge"}), revoked=True
        )
        self.assertEqual(self._call(policy, "/charge", "k")[0], 401)

    def test_expired_key_is_refused(self) -> None:
        policy = self._policy()
        policy.virtual_keys["k"] = VirtualKey(
            key="k", name="stale", routes=frozenset({"/charge"}), expires_at=time.time() - 1
        )
        self.assertEqual(self._call(policy, "/charge", "k")[0], 401)

    def test_master_key_reaches_a_route_a_limited_key_cannot(self) -> None:
        policy = self._policy()
        policy.virtual_keys["k"] = VirtualKey(
            key="k", name="limited", routes=frozenset({"/charge"})
        )
        # The upstream is closed, so a 502 proves the request was authorized and
        # forwarded rather than refused at the gateway.
        self.assertEqual(self._call(policy, "/refund", "master-value")[0], 502)

    def test_unreachable_upstream_answers_instead_of_dropping(self) -> None:
        """A dead upstream must not read as a dropped connection: the caller
        cannot tell an unread action from a completed one."""
        code, body = self._call(self._policy(), "/charge", "master-value")
        self.assertEqual(code, 502)
        self.assertIn("upstream unreachable", body)


class LiveKeyIssuanceTest(unittest.TestCase):
    """A key issued to a *running* gateway must work, and a revoked one must stop.

    The operator's sequence is: start the gateway, issue a key, hand it to an
    agent. If the running process only knows the keys it loaded at startup, the
    agent holds a key that cannot work until someone restarts the service -- and
    sees a 401 with nothing to indicate that a restart is the remedy. The same
    applies to revocation: a revoked key that keeps working is worse than one
    that never worked.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.store = TraceStore(Path(self._tmp.name) / "runtime.db")
        os.environ["SAFETY_GATEWAY"] = "1"
        os.environ["TEST_MASTER_KEY"] = "master-value"
        self.addCleanup(os.environ.pop, "SAFETY_GATEWAY", None)
        self.addCleanup(os.environ.pop, "TEST_MASTER_KEY", None)

        policy = GatewayPolicy(session_environment="prod", master_key_env="TEST_MASTER_KEY")
        policy.register(
            Route(
                path="/charge",
                upstream="http://127.0.0.1:1/charge",
                action="charge",
                risk="read",
            )
        )
        self.server, _handler = build_gateway_server(self.store, policy, port=0)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def _post(self, token: str) -> tuple[int, str]:
        request = urllib.request.Request(
            self.base + "/charge", data=b"{}", method="POST"
        )
        request.add_header("Authorization", f"Bearer {token}")
        with self.assertRaises(urllib.error.HTTPError) as raised:
            urllib.request.urlopen(request, timeout=5)
        return int(raised.exception.code), raised.exception.read().decode()

    def test_a_key_issued_after_startup_is_accepted(self) -> None:
        self.store.save_virtual_key("late-key", "late", ["/charge"], expires_at=None)
        status, body = self._post("late-key")
        # 502 means it reached the (deliberately dead) upstream: authenticated
        # and authorised. A 401 would mean the key was never picked up.
        self.assertEqual(status, 502, body)

    def test_a_revoked_key_stops_working_on_a_running_gateway(self) -> None:
        self.store.save_virtual_key("doomed", "doomed", ["/charge"], expires_at=None)
        self.assertEqual(self._post("doomed")[0], 502)

        self.assertTrue(self.store.revoke_virtual_key("doomed"))
        self.assertEqual(self._post("doomed")[0], 401)


if __name__ == "__main__":
    unittest.main()
