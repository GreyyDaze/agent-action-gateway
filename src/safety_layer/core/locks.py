import hashlib
import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from ..storage.base import SqliteStore
from ..storage.traces import TraceStore


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


def payload_hash(action: str, arguments: dict[str, Any]) -> str:
    canonical = json.dumps({"action": action, "arguments": arguments}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def state_hash(state: Any) -> str:
    canonical = json.dumps(state, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


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

    def request(
        self,
        action: str,
        arguments: dict[str, Any],
        expires_at: datetime,
        current_state: Any | None = None,
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
        )
        with self.connection() as connection:
            connection.execute(
                """
                INSERT INTO approvals(
                    approval_id, action, arguments_json, payload_hash, approver,
                    created_at, expires_at, state_hash, decision, decided_at, consumed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
    """Authorize an action before dispatch; destructive approval is exact and single-use."""
    risk = registry.classify(action)
    if risk == "read":
        return risk

    approval_store.require_available()
    if approval_id is None:
        if risk == "destructive":
            raise ApprovalError("destructive action requires approval")
        return risk

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
