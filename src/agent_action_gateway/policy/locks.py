"""Approvals and risk classes: which actions need a person, and the approvals given."""
import hashlib
import json
import sqlite3
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from os import PathLike
from pathlib import Path
from typing import Any
from uuid import uuid4

from agent_action_gateway.guards.redaction import redact
from agent_action_gateway.storage.base import SqliteStore
from agent_action_gateway.storage.traces import TraceStore


class ApprovalError(RuntimeError):
    pass


class SafetyBlockedError(ApprovalError):
    """An action was refused by policy before it could reach the world.

    Raised rather than returned, because a caller that ignores a refusal is
    exactly the failure this product exists to prevent.
    """


class ApprovalUnavailableError(ApprovalError):
    pass


@dataclass(frozen=True)
class Approval:
    approval_id: str
    action: str
    arguments: dict[str, Any]
    payload_hash: str
    approver: str | None
    created_at: str
    expires_at: str
    state_hash: str | None
    decision: str
    decided_at: str | None
    consumed_at: str | None
    #: What a person needs to decide: the risk class, the session's
    #: environment and the run that asked. Empty for approvals made before
    #: this was recorded.
    context: dict[str, Any] = field(default_factory=dict)


MAX_EVIDENCE = 10
MAX_EVIDENCE_TEXT = 300
#: A frozen copy is kept up to this size (UTF-8 bytes). A larger or binary file
#: is fingerprinted only: its SHA-256 and size are kept, not its content.
MAX_FROZEN_COPY = 64 * 1024
#: All frozen copies of one approval together.
MAX_FROZEN_TOTAL = 256 * 1024


def _fingerprint_file(path: Path) -> tuple[str, int, bytes | None]:
    """SHA-256 and size of a file, plus its bytes when small enough to copy."""
    if not path.is_file():
        raise ValueError(f"evidence file not found or not a regular file: {path.name}")
    digest = hashlib.sha256()
    size = 0
    head = bytearray()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
            if len(head) <= MAX_FROZEN_COPY:
                head.extend(chunk[: MAX_FROZEN_COPY + 1 - len(head)])
    return digest.hexdigest(), size, bytes(head) if size <= MAX_FROZEN_COPY else None


def _freeze(content: bytes | None, digest: str, size: int) -> dict[str, Any]:
    """Keep what the approver saw: a fingerprint always, a copy when it is text."""
    frozen: dict[str, Any] = {"sha256": digest, "size": size}
    if content is not None:
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            return frozen
        copy = redact(text)
        frozen["text"] = copy
        if copy != text:
            # The fingerprint is of the original; the stored copy hides secrets.
            frozen["redacted"] = True
    return frozen


def normalize_evidence(items: Any) -> list[dict[str, Any]]:
    """Check, and freeze, the evidence a person should see before approving.

    Each item is a link (`"https://..."`), a note (`"migration 0042 diff"`) or a
    mapping with a `label` and any of:

    - `url`: a link (http or https). Only the link is kept.
    - `text`: content such as a diff. Frozen: a copy and its SHA-256 are kept.
    - `file`: a local file, such as a replay. Frozen when the approval is asked
      for: its SHA-256, size and name are kept, and a copy too when it is text of
      at most 64 KB. A later edit to the file no longer matches the fingerprint.
    """
    if items is None:
        return []
    if isinstance(items, (str, bytes, Mapping)) or not isinstance(items, Sequence):
        raise ValueError("evidence must be a list of links, notes or {label, ...} items")
    if len(items) > MAX_EVIDENCE:
        raise ValueError(f"at most {MAX_EVIDENCE} evidence items")
    result: list[dict[str, Any]] = []
    copied = 0
    for item in items:
        text: Any = None
        file: Any = None
        if isinstance(item, str):
            label, url = item, item if item.lower().startswith(("http://", "https://")) else ""
        elif isinstance(item, Mapping):
            unknown = set(item) - {"label", "url", "text", "file"}
            if unknown:
                raise ValueError(f"unknown evidence field(s): {', '.join(sorted(map(str, unknown)))}")
            raw_label, raw_url = item.get("label"), item.get("url") or ""
            if not isinstance(raw_label, str) or not isinstance(raw_url, str):
                raise ValueError("an evidence item needs a text label and an optional text url")
            label, url = raw_label, raw_url
            text, file = item.get("text"), item.get("file")
            if text is not None and file is not None:
                raise ValueError("an evidence item takes text or file, not both")
            if text is not None and not isinstance(text, str):
                raise ValueError("evidence text must be a string")
            if file is not None and not isinstance(file, (str, PathLike)):
                raise ValueError("evidence file must be a path")
        else:
            raise ValueError("an evidence item is a string or a {label, ...} mapping")
        label = label.strip()
        if not label:
            raise ValueError("an evidence item needs a label")
        if len(label) > MAX_EVIDENCE_TEXT or len(url) > MAX_EVIDENCE_TEXT:
            raise ValueError(f"an evidence label or url is over {MAX_EVIDENCE_TEXT} characters")
        if url and not url.lower().startswith(("http://", "https://")):
            raise ValueError("an evidence url must start with http:// or https://")
        entry: dict[str, Any] = {"label": label}
        if url:
            entry["url"] = url
        if text is not None:
            raw = text.encode("utf-8")
            if len(raw) > MAX_FROZEN_COPY:
                raise ValueError(
                    f"evidence text is over {MAX_FROZEN_COPY // 1024} KB; pass it as a file"
                )
            entry.update(_freeze(raw, hashlib.sha256(raw).hexdigest(), len(raw)))
        if file is not None:
            path = Path(file)
            digest, size, content = _fingerprint_file(path)
            entry["file"] = path.name
            entry.update(_freeze(content, digest, size))
        copied += len(str(entry.get("text") or "").encode("utf-8"))
        if copied > MAX_FROZEN_TOTAL:
            raise ValueError(f"frozen evidence is over {MAX_FROZEN_TOTAL // 1024} KB in total")
        result.append(entry)
    return result


def evidence_copy_matches(item: Mapping[str, Any]) -> bool | None:
    """Does a stored copy still match its fingerprint? None when there is nothing to compare.

    A copy with secrets hidden cannot match the original's fingerprint, so it is
    not compared either. This catches a copy changed after the approval; someone
    who can edit the database can change both, so it is not a tamper-proof seal.
    """
    text, digest = item.get("text"), item.get("sha256")
    if not isinstance(text, str) or not isinstance(digest, str) or item.get("redacted"):
        return None
    return hashlib.sha256(text.encode("utf-8")).hexdigest() == digest


def payload_hash(action: str, arguments: dict[str, Any]) -> str:
    canonical = json.dumps({"action": action, "arguments": arguments}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def state_hash(state: Any) -> str:
    canonical = json.dumps(state, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _decode_context(row: Any) -> dict[str, Any]:
    try:
        raw = row["context_json"]
    except (IndexError, KeyError):
        return {}
    try:
        value = json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        return {}
    return value if isinstance(value, dict) else {}


class ApprovalStore(SqliteStore):
    """Durable approval records for the current single-node SQLite deployment.

    Shares the runtime database file with the trace store, since approvals and
    the traces they authorize belong to one run's evidence. It holds its own
    connection rather than borrowing the trace store's private one.
    """

    store_name = "approvals"

    def __init__(self, store: "TraceStore | str | Path") -> None:
        self.store = store if isinstance(store, TraceStore) else None
        path = store.path if isinstance(store, TraceStore) else Path(store)
        self.available = True
        super().__init__(path)

    def _migrations(self):
        yield 1, [
            """
            CREATE TABLE IF NOT EXISTS approvals (
                approval_id TEXT PRIMARY KEY,
                action TEXT NOT NULL,
                arguments_json TEXT NOT NULL,
                payload_hash TEXT NOT NULL,
                approver TEXT,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                state_hash TEXT,
                decision TEXT NOT NULL,
                decided_at TEXT,
                consumed_at TEXT
            );
            """
        ]
        # Columns added after the first release.
        if self._table_exists("approvals"):
            existing = self._columns("approvals")
            additions = []
            for name, definition in (
                ("arguments_json", "TEXT"),
                ("decision", "TEXT NOT NULL DEFAULT 'approved'"),
                ("decided_at", "TEXT"),
                ("approver", "TEXT"),
            ):
                if name not in existing:
                    additions.append(
                        f"ALTER TABLE approvals ADD COLUMN {name} {definition}"
                    )
            # A pre-existing row has no recorded payload, so it cannot be
            # verified against the action being authorized. The sentinel below
            # deliberately fails the payload-hash comparison in authorize(),
            # so such an approval can never be used.
            if "arguments_json" not in existing and additions:
                additions.append(
                    "UPDATE approvals SET arguments_json = json_object('_unverifiable_legacy', payload_hash)"
                )
            yield 2, additions
        # v3: the context a person needs to decide (risk, environment, run).
        yield 3, ["ALTER TABLE approvals ADD COLUMN context_json TEXT"]

    def request(
        self,
        action: str,
        arguments: dict[str, Any],
        expires_at: datetime,
        current_state: Any | None = None,
        context: dict[str, Any] | None = None,
    ) -> Approval:
        self._require_available()
        now = datetime.now(UTC)
        if expires_at <= now:
            raise ApprovalError("approval expiry must be in the future")
        approval = Approval(
            approval_id=str(uuid4()),
            action=action,
            arguments=dict(arguments),
            payload_hash=payload_hash(action, arguments),
            approver=None,
            created_at=now.isoformat(),
            expires_at=expires_at.astimezone(UTC).isoformat(),
            state_hash=None if current_state is None else state_hash(current_state),
            decision="pending",
            decided_at=None,
            consumed_at=None,
            context=dict(context or {}),
        )
        with self.connection() as connection:
            connection.execute(
                """
                INSERT INTO approvals(
                    approval_id, action, arguments_json, payload_hash, approver,
                    created_at, expires_at, state_hash, decision, decided_at, consumed_at,
                    context_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    approval.approval_id,
                    approval.action,
                    json.dumps(approval.arguments, sort_keys=True, separators=(",", ":")),
                    approval.payload_hash,
                    approval.approver,
                    approval.created_at,
                    approval.expires_at,
                    approval.state_hash,
                    approval.decision,
                    approval.decided_at,
                    approval.consumed_at,
                    json.dumps(approval.context, sort_keys=True) if approval.context else None,
                ),
            )
        return approval

    def approve(self, approval_id: str, approver: str) -> Approval:
        self._require_available()
        if not approver.strip():
            raise ApprovalError("approver is required")
        approval = self.get(approval_id)
        if approval.decision != "pending":
            raise ApprovalError(f"approval is already {approval.decision}")
        if datetime.now(UTC) >= datetime.fromisoformat(approval.expires_at):
            raise ApprovalError("approval expired")
        with self.connection() as connection:
            cursor = connection.execute(
                """
                UPDATE approvals
                SET decision='approved', approver=?, decided_at=?
                WHERE approval_id=? AND decision='pending'
                """,
                (approver, datetime.now(UTC).isoformat(), approval_id),
            )
            if cursor.rowcount != 1:
                raise ApprovalError("approval is no longer pending")
        return self.get(approval_id)

    def deny(self, approval_id: str, approver: str) -> Approval:
        self._require_available()
        if not approver.strip():
            raise ApprovalError("approver is required")
        approval = self.get(approval_id)
        if approval.decision != "pending":
            raise ApprovalError(f"approval is already {approval.decision}")
        with self.connection() as connection:
            cursor = connection.execute(
                """
                UPDATE approvals
                SET decision='denied', approver=?, decided_at=?
                WHERE approval_id=? AND decision='pending'
                """,
                (approver, datetime.now(UTC).isoformat(), approval_id),
            )
            if cursor.rowcount != 1:
                raise ApprovalError("approval is no longer pending")
        return self.get(approval_id)

    def create(
        self,
        action: str,
        arguments: dict[str, Any],
        approver: str,
        expires_at: datetime,
        current_state: Any | None = None,
    ) -> Approval:
        """Compatibility helper for tests: request and immediately approve."""
        approval = self.request(action, arguments, expires_at, current_state)
        return self.approve(approval.approval_id, approver)

    def get(self, approval_id: str) -> Approval:
        self._require_available()
        with self.connection() as connection:
            row = connection.execute("SELECT * FROM approvals WHERE approval_id = ?", (approval_id,)).fetchone()
        if row is None:
            raise ApprovalError("approval not found")
        return self._from_row(row)

    def pending(self) -> list[Approval]:
        self._require_available()
        with self.connection() as connection:
            rows = connection.execute(
                "SELECT * FROM approvals WHERE decision='pending' ORDER BY created_at"
            ).fetchall()
        return [self._from_row(row) for row in rows]

    def waiting(self) -> list[Approval]:
        """Pending approvals that can still be given: not expired."""
        now = datetime.now(UTC)
        return [a for a in self.pending() if now < datetime.fromisoformat(a.expires_at)]

    def decided(self, limit: int = 50) -> list[Approval]:
        """Approvals a person approved or denied, newest first: who let what run."""
        self._require_available()
        with self.connection() as connection:
            rows = connection.execute(
                "SELECT * FROM approvals WHERE decision IN ('approved', 'denied') "
                "ORDER BY decided_at DESC LIMIT ?",
                (int(limit),),
            ).fetchall()
        return [self._from_row(row) for row in rows]

    def is_usable(self, approval_id: str) -> bool:
        """Whether this approval is approved, unused and not expired right now."""
        try:
            approval = self.get(approval_id)
        except ApprovalError:
            return False
        return (
            approval.decision == "approved"
            and approval.consumed_at is None
            and datetime.now(UTC) < datetime.fromisoformat(approval.expires_at)
        )

    def find_pending(self, action: str, arguments: dict[str, Any]) -> Approval | None:
        """The waiting approval for exactly this action and payload, if any."""
        return self._find(action, arguments, "decision='pending'")

    def find_usable(self, action: str, arguments: dict[str, Any]) -> Approval | None:
        """An approved, unused, unexpired approval for exactly this payload.

        Lets a caller retry the same call after a human said yes, without
        having to carry the approval id. The match is the same exact-payload,
        single-use check `authorize()` makes, so it grants nothing extra.
        """
        found = self._find(
            action, arguments, "decision='approved' AND consumed_at IS NULL"
        )
        if found is None:
            return None
        if datetime.now(UTC) >= datetime.fromisoformat(found.expires_at):
            return None
        return found

    def _find(self, action: str, arguments: dict[str, Any], where: str) -> Approval | None:
        self._require_available()
        with self.connection() as connection:
            row = connection.execute(
                f"SELECT * FROM approvals WHERE action=? AND payload_hash=? AND {where} "
                "ORDER BY created_at LIMIT 1",
                (action, payload_hash(action, arguments)),
            ).fetchone()
        return None if row is None else self._from_row(row)

    def consume(self, approval_id: str) -> None:
        self._require_available()
        consumed_at = datetime.now(UTC).isoformat()
        with self.connection() as connection:
            cursor = connection.execute(
                "UPDATE approvals SET consumed_at=? WHERE approval_id=? AND consumed_at IS NULL AND decision='approved'",
                (consumed_at, approval_id),
            )
            if cursor.rowcount != 1:
                raise ApprovalError("approval already used or not approved")

    @staticmethod
    def _from_row(row: sqlite3.Row) -> Approval:
        raw_arguments = row["arguments_json"]
        try:
            arguments = json.loads(raw_arguments) if raw_arguments else {}
        except json.JSONDecodeError:
            arguments = {}
        return Approval(
            approval_id=row["approval_id"],
            action=row["action"],
            arguments=arguments,
            payload_hash=row["payload_hash"],
            approver=row["approver"],
            created_at=row["created_at"],
            expires_at=row["expires_at"],
            state_hash=row["state_hash"],
            decision=row["decision"],
            decided_at=row["decided_at"],
            consumed_at=row["consumed_at"],
            context=_decode_context(row),
        )

    def require_available(self) -> None:
        """Public guard for callers outside this class.

        `authorize` needs the same fail-closed check as the store methods, and
        reaching into a private helper from another function in the module was
        a boundary violation.
        """
        if not self.available:
            raise ApprovalUnavailableError("approval service unavailable")

    # Retained for existing callers inside this module.
    _require_available = require_available


class RiskRegistry:
    """Closed risk vocabulary. Unknown actions are destructive by default."""

    VALID = frozenset({"read", "write", "destructive"})

    def __init__(self) -> None:
        self._risks: dict[str, str] = {}

    def register(self, action: str, risk: str) -> None:
        if risk not in self.VALID:
            raise ValueError(f"invalid risk class: {risk}")
        self._risks[action] = risk

    def classify(self, action: str) -> str:
        return self._risks.get(action, "destructive")


def authorize(
    approval_store: ApprovalStore,
    registry: RiskRegistry,
    action: str,
    arguments: dict[str, Any],
    *,
    approval_id: str | None = None,
    current_state: Any | None = None,
    now: datetime | None = None,
) -> str:
    """Authorize an action before dispatch. Every risk except `read` needs an
    approval, bound to the exact arguments and used once."""
    risk = registry.classify(action)
    if risk == "read":
        return risk

    approval_store.require_available()
    if approval_id is None:
        raise ApprovalError(f"{risk} action requires approval")

    approval = approval_store.get(approval_id)
    if approval.decision != "approved":
        raise ApprovalError("approval is not approved")
    current_time = now or datetime.now(UTC)
    if current_time >= datetime.fromisoformat(approval.expires_at):
        raise ApprovalError("approval expired")
    if approval.consumed_at is not None:
        raise ApprovalError("approval already used")
    if approval.action != action:
        raise ApprovalError("approval action mismatch")
    if approval.payload_hash != payload_hash(action, arguments):
        raise ApprovalError("approved payload changed")
    if approval.state_hash is not None and approval.state_hash != state_hash(current_state):
        raise ApprovalError("current state changed since approval")
    approval_store.consume(approval.approval_id)
    return risk
