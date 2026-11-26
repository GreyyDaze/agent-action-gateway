"""Agent Action Gateway: let AI agents change real systems safely.

You control what an agent can do, and you can prove what it did. The public
surface is intentionally small. A user wraps their own agent's tools (or puts the
MCP proxy between the agent and its MCP servers) and receives recorded evidence
and enforced policy; this package does not own the agent loop or the agent's
model calls.

Layout:

    policy/        pure decisions: risk, approval, budgets, stop rules, hashes
    engine/        the one enforcement pipeline
    guards/        redaction, capture policy, run status
    runtime/       run orchestration
    credential/    key custody and outbound host checks
    integrations/  MCP proxy, HTTP gateway, in-process adapters
    audit/         receipts, failure grouping, lifecycle stores
    eval/          golden set, judges, verdict engine, regression gate
    storage/       durable SQLite/Postgres persistence (leaf layer)
    observability/ dashboard and wiring check
    proofs/        verification scripts about this library, not in the CLI

Import from here rather than from submodules; the submodule layout is an
implementation detail.
"""

from agent_action_gateway.audit.receipts import OutcomeUnknown
from agent_action_gateway.policy.fuses import (
    FuseBudget,
    FuseController,
    FuseLimits,
    FuseTrippedError,
)
from agent_action_gateway.runtime.session import DEFAULT_FUSE_LIMITS, SafetySession, session

# The names below are what a consumer needs. The remaining imports stay
# reachable so that existing `from agent_action_gateway import X` calls keep working,
# but they are not advertised as part of the public surface.
__all__ = [
    "FuseLimits",
    "OutcomeUnknown",
    "SafetySession",
    "session",
]
