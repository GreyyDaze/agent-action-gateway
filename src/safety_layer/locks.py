import hashlib
import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from .store import TraceStore


class ApprovalError(RuntimeError):
    pass


class ApprovalUnavailableError(ApprovalError):
    pass


@dataclass(frozen=True)
class Approval:
    approval_id: str
    action: str
    payload_hash: str
    approver: str
    created_at: str
    expires_at: str
    state_hash: str | None


def payload_hash(action: str, arguments: dict[str, Any]) -> str:
    canonical = json.dumps({"action": action, "arguments": arguments}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def state_hash(state: Any) -> str:
    canonical = json.dumps(state, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class ApprovalStore:
    """Durable approval records for the current single-node SQLite deployment."""

    def __init__(self, store: TraceStore) -> None:
        self.store = store
        self.available = True
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        return self.store._connect()

    def _init_db(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS approvals (
                    approval_id TEXT PRIMARY KEY,
                    action TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    approver TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    state_hash TEXT
                )
                """
            )

    def create(
        self,
        action: str,
        arguments: dict[str, Any],
        approver: str,
        expires_at: datetime,
        current_state: Any | None = None,
    ) -> Approval:
        self._require_available()
        now = datetime.now(timezone.utc)
        if expires_at <= now:
            raise ApprovalError("approval expiry must be in the future")
        approval = Approval(
            approval_id=str(uuid4()),
            action=action,
            payload_hash=payload_hash(action, arguments),
            approver=approver,
            created_at=now.isoformat(),
            expires_at=expires_at.astimezone(timezone.utc).isoformat(),
            state_hash=None if current_state is None else state_hash(current_state),
        )
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO approvals(approval_id, action, payload_hash, approver, created_at, expires_at, state_hash) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    approval.approval_id,
                    approval.action,
                    approval.payload_hash,
                    approval.approver,
                    approval.created_at,
                    approval.expires_at,
                    approval.state_hash,
                ),
            )
        return approval

    def get(self, approval_id: str) -> Approval:
        self._require_available()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM approvals WHERE approval_id = ?", (approval_id,)
            ).fetchone()
        if row is None:
            raise ApprovalError("approval not found")
        return Approval(
            approval_id=row["approval_id"],
            action=row["action"],
            payload_hash=row["payload_hash"],
            approver=row["approver"],
            created_at=row["created_at"],
            expires_at=row["expires_at"],
            state_hash=row["state_hash"],
        )

    def _require_available(self) -> None:
        if not self.available:
            raise ApprovalUnavailableError("approval service unavailable")


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
    """Return the risk class or raise before the external action is dispatched."""
    risk = registry.classify(action)
    if risk == "read":
        return risk

    try:
        if approval_id is None:
            if risk == "destructive":
                raise ApprovalError("destructive action requires approval")
            approval_store._require_available()
            return risk

        approval = approval_store.get(approval_id)
    except ApprovalUnavailableError:
        raise
    except ApprovalError:
        raise

    current_time = now or datetime.now(timezone.utc)
    if current_time >= datetime.fromisoformat(approval.expires_at):
        raise ApprovalError("approval expired")
    if approval.action != action:
        raise ApprovalError("approval action mismatch")
    if approval.payload_hash != payload_hash(action, arguments):
        raise ApprovalError("approved payload changed")
    if approval.state_hash is not None and approval.state_hash != state_hash(current_state):
        raise ApprovalError("current state changed since approval")
    return risk
