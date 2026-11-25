import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from agent_action_gateway.policy.locks import ApprovalStore, RiskRegistry
from agent_action_gateway.policy.safety import SafetyBlockedError, check_action
from agent_action_gateway.proofs.fakes import MockEffectProvider
from agent_action_gateway.runtime.orchestrator import dispatch_external_action
from agent_action_gateway.storage.traces import TraceStore


class ApprovalLockTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = TraceStore(Path(self.tmp.name) / "runtime.db")
        self.approvals = ApprovalStore(self.store)
        self.registry = RiskRegistry()
        self.registry.register("rollback", "destructive")
        self.registry.register("lookup_deployment", "read")
        self.registry.register("update_note", "write")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def approval(self, *, days: int = 1, state: object | None = None) -> str:
        record = self.approvals.create(
            "rollback",
            {"deployment_id": "DEP-100", "revision": 400},
            "human-1",
            datetime.now(UTC) + timedelta(days=days),
            state,
        )
        return record.approval_id

    def test_approval_request_starts_pending_with_exact_raw_payload(self) -> None:
        record = self.approvals.request(
            "rollback",
            {"deployment_id": "DEP-100", "revision": 400},
            datetime.now(UTC) + timedelta(days=1),
        )
        self.assertEqual(record.decision, "pending")
        self.assertEqual(record.arguments, {"deployment_id": "DEP-100", "revision": 400})
        self.assertIsNone(record.approver)

    def test_pending_approval_cannot_execute_before_human_approval(self) -> None:
        record = self.approvals.request(
            "rollback",
            {"deployment_id": "DEP-100", "revision": 400},
            datetime.now(UTC) + timedelta(days=1),
        )
        with self.assertRaises(SafetyBlockedError):
            check_action(
                self.approvals,
                self.registry,
                "rollback",
                record.arguments,
                approval_id=record.approval_id,
            )

    def test_human_approval_enables_exact_action(self) -> None:
        record = self.approvals.request(
            "rollback",
            {"deployment_id": "DEP-100", "revision": 400},
            datetime.now(UTC) + timedelta(days=1),
        )
        approved = self.approvals.approve(record.approval_id, "human-1")
        self.assertEqual(approved.decision, "approved")
        self.assertEqual(approved.approver, "human-1")
        self.assertEqual(
            check_action(
                self.approvals,
                self.registry,
                "rollback",
                record.arguments,
                approval_id=record.approval_id,
            ),
            "destructive",
        )

    def test_human_denial_blocks_action(self) -> None:
        record = self.approvals.request(
            "rollback",
            {"deployment_id": "DEP-100", "revision": 400},
            datetime.now(UTC) + timedelta(days=1),
        )
        self.approvals.deny(record.approval_id, "human-1")
        with self.assertRaises(SafetyBlockedError):
            check_action(
                self.approvals,
                self.registry,
                "rollback",
                record.arguments,
                approval_id=record.approval_id,
            )

    def test_unapproved_destructive_is_blocked(self) -> None:
        provider = MockEffectProvider(dedupe=True)
        with self.assertRaises(SafetyBlockedError):
            dispatch_external_action(
                self.store, provider, "run-1", "step-1",
                {"deployment_id": "DEP-100", "revision": 400}, "DEP-100",
                action="rollback",
                registry=self.registry, approval_store=self.approvals,
            )
        self.assertEqual(len(provider.rollbacks), 0)

    def test_unknown_action_defaults_to_destructive(self) -> None:
        with self.assertRaises(SafetyBlockedError):
            check_action(self.approvals, self.registry, "delete_customer", {"id": "C-1"})

    def test_tampered_payload_is_blocked(self) -> None:
        approval_id = self.approval()
        with self.assertRaises(SafetyBlockedError):
            check_action(
                self.approvals, self.registry, "rollback",
                {"deployment_id": "DEP-100", "revision": 401},
                approval_id=approval_id,
            )

    def test_expired_approval_is_blocked(self) -> None:
        approval_id = self.approval()
        with self.assertRaises(SafetyBlockedError):
            check_action(
                self.approvals, self.registry, "rollback",
                {"deployment_id": "DEP-100", "revision": 400},
                approval_id=approval_id,
                now=datetime.now(UTC) + timedelta(days=2),
            )

    def test_state_change_invalidates_approval(self) -> None:
        approval_id = self.approval(state={"deployment_status": "open"})
        with self.assertRaises(SafetyBlockedError):
            check_action(
                self.approvals, self.registry, "rollback",
                {"deployment_id": "DEP-100", "revision": 400},
                approval_id=approval_id,
                current_state={"deployment_status": "cancelled"},
            )

    def test_valid_fresh_approval_allows_external_action(self) -> None:
        approval_id = self.approval(state={"deployment_status": "open"})
        provider = MockEffectProvider(dedupe=True)
        result = dispatch_external_action(
            self.store, provider, "run-1", "step-1",
            {"deployment_id": "DEP-100", "revision": 400}, "DEP-100",
            action="rollback",
            registry=self.registry, approval_store=self.approvals,
            approval_id=approval_id, current_state={"deployment_status": "open"},
        )
        self.assertEqual(len(provider.rollbacks), 1)
        self.assertTrue(result.startswith("mock-"))

    def test_approval_is_single_use(self) -> None:
        approval_id = self.approval()
        check_action(
            self.approvals, self.registry, "rollback",
            {"deployment_id": "DEP-100", "revision": 400},
            approval_id=approval_id,
        )
        with self.assertRaises(SafetyBlockedError):
            check_action(
                self.approvals, self.registry, "rollback",
                {"deployment_id": "DEP-100", "revision": 400},
                approval_id=approval_id,
            )

    def test_safety_unavailable_fails_closed_for_write_and_destructive(self) -> None:
        self.approvals.available = False
        with self.assertRaises(SafetyBlockedError):
            check_action(self.approvals, self.registry, "update_note", {"id": "N-1"})
        with self.assertRaises(SafetyBlockedError):
            check_action(self.approvals, self.registry, "rollback", {"deployment_id": "DEP-100"})

    def test_read_still_works_when_safety_service_is_unavailable(self) -> None:
        self.approvals.available = False
        self.assertEqual(
            check_action(self.approvals, self.registry, "lookup_deployment", {"customer": "Ava"}),
            "read",
        )


if __name__ == "__main__":
    unittest.main()


class EvidenceTest(unittest.TestCase):
    def test_links_notes_and_mappings_are_normalized(self) -> None:
        from agent_action_gateway.policy.locks import normalize_evidence

        self.assertEqual(
            normalize_evidence(
                ["https://a.example/x", "just a note", {"label": "Diff", "url": "http://b.example"}]
            ),
            [
                {"label": "https://a.example/x", "url": "https://a.example/x"},
                {"label": "just a note"},
                {"label": "Diff", "url": "http://b.example"},
            ],
        )
        self.assertEqual(normalize_evidence(None), [])

    def test_bad_evidence_is_refused(self) -> None:
        from agent_action_gateway.policy.locks import MAX_EVIDENCE, normalize_evidence

        for bad in (
            "https://a.example",  # a bare string, not a list
            [{"label": "x", "url": "javascript:alert(1)"}],
            [{"label": "x", "url": "file:///etc/passwd"}],
            [{"url": "https://a.example"}],  # no label
            [{"label": "  "}],
            [123],
            ["x" * 301],
            ["note"] * (MAX_EVIDENCE + 1),
        ):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                normalize_evidence(bad)

    def test_the_session_keeps_evidence_in_the_approval_context(self) -> None:
        import tempfile
        from pathlib import Path

        from agent_action_gateway import session
        from agent_action_gateway.storage.traces import TraceStore

        with tempfile.TemporaryDirectory() as tmp:
            store = TraceStore(Path(tmp) / "t.db")
            with session(store=store) as ctx:
                approval = ctx.request_approval(
                    "db.migrate", {"v": 42}, evidence=["https://a.example/diff"]
                )
                plain = ctx.request_approval("db.migrate", {"v": 43})
            self.assertEqual(
                ApprovalStore(store).get(approval.approval_id).context["evidence"],
                [{"label": "https://a.example/diff", "url": "https://a.example/diff"}],
            )
            self.assertNotIn("evidence", ApprovalStore(store).get(plain.approval_id).context)


class FrozenEvidenceTest(unittest.TestCase):
    """Evidence frozen at approval time: a copy and a fingerprint, not a link that can move."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)

    def test_text_is_copied_with_its_fingerprint(self) -> None:
        import hashlib

        from agent_action_gateway.policy.locks import evidence_copy_matches, normalize_evidence

        diff = "-dirty = true\n+dirty = false\n"
        (item,) = normalize_evidence([{"label": "0042 diff", "text": diff}])
        self.assertEqual(item["text"], diff)
        self.assertEqual(item["sha256"], hashlib.sha256(diff.encode()).hexdigest())
        self.assertEqual(item["size"], len(diff.encode()))
        self.assertIs(evidence_copy_matches(item), True)

    def test_a_file_is_frozen_when_the_approval_is_asked_for(self) -> None:
        import hashlib

        from agent_action_gateway.policy.locks import normalize_evidence

        path = self.dir / "0042.diff"
        path.write_text("+dirty = false\n")
        (item,) = normalize_evidence([{"label": "diff", "file": path}])
        path.write_text("changed later\n")
        self.assertEqual(item["file"], "0042.diff")
        self.assertEqual(item["text"], "+dirty = false\n")
        self.assertNotEqual(item["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())

    def test_a_large_or_binary_file_keeps_only_its_fingerprint(self) -> None:
        import hashlib

        from agent_action_gateway.policy.locks import (
            MAX_FROZEN_COPY,
            evidence_copy_matches,
            normalize_evidence,
        )

        big = self.dir / "replay.webm"
        big.write_bytes(b"x" * (MAX_FROZEN_COPY + 1))
        binary = self.dir / "shot.png"
        binary.write_bytes(b"\x89PNG\xff\xfe")
        replay, shot = normalize_evidence(
            [{"label": "replay", "file": str(big)}, {"label": "shot", "file": binary}]
        )
        self.assertNotIn("text", replay)
        self.assertEqual(replay["size"], MAX_FROZEN_COPY + 1)
        self.assertEqual(replay["sha256"], hashlib.sha256(big.read_bytes()).hexdigest())
        self.assertNotIn("text", shot)
        self.assertIsNone(evidence_copy_matches(replay))

    def test_secrets_are_hidden_in_the_copy_and_the_fingerprint_is_the_originals(self) -> None:
        import hashlib

        from agent_action_gateway.policy.locks import evidence_copy_matches, normalize_evidence

        text = "curl -H 'Authorization: Bearer abcdefghijklmnopqrstuvwx' https://api"
        (item,) = normalize_evidence([{"label": "log", "text": text}])
        self.assertNotIn("abcdefghijklmnopqrstuvwx", item["text"])
        self.assertTrue(item["redacted"])
        self.assertEqual(item["sha256"], hashlib.sha256(text.encode()).hexdigest())
        self.assertIsNone(evidence_copy_matches(item))

    def test_a_copy_changed_after_approval_no_longer_matches(self) -> None:
        from agent_action_gateway.policy.locks import evidence_copy_matches, normalize_evidence

        (item,) = normalize_evidence([{"label": "diff", "text": "+a"}])
        self.assertIs(evidence_copy_matches({**item, "text": "+b"}), False)

    def test_bad_frozen_evidence_is_refused(self) -> None:
        from agent_action_gateway.policy.locks import (
            MAX_FROZEN_COPY,
            MAX_FROZEN_TOTAL,
            normalize_evidence,
        )

        for bad in (
            [{"label": "x", "text": "a", "file": "b"}],
            [{"label": "x", "text": 5}],
            [{"label": "x", "file": 5}],
            [{"label": "x", "file": str(self.dir / "missing.diff")}],
            [{"label": "x", "file": str(self.dir)}],
            [{"label": "x", "text": "a" * (MAX_FROZEN_COPY + 1)}],
            [{"label": f"x{i}", "text": "a" * MAX_FROZEN_COPY}
             for i in range(MAX_FROZEN_TOTAL // MAX_FROZEN_COPY + 1)],
            [{"label": "x", "comment": "unknown field"}],
        ):
            with self.subTest(bad=str(bad)[:60]), self.assertRaises(ValueError):
                normalize_evidence(bad)
