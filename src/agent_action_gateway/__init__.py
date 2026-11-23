"""Agent Action Gateway — prevention-first safety and evaluation for AI agents.

The public surface is intentionally small. A user wraps their own agent and
receives recorded evidence and enforced policy; the safety layer does not own
the agent loop or the agent's model calls.

Layout (old package names remain as compatibility shims):

    policy/        pure decisions: risk, approval, budgets, stop rules, hashes
    engine/        the one enforcement pipeline
    guards/        redaction, capture policy, honest status
    runtime/       run orchestration
    credential/    key custody, egress policy, proxy, TLS
    integrations/  gateway, MCP, in-process adapters
    audit/         receipts, failure grouping, lifecycle stores
    eval/          golden set, judges, verdict engine, regression gate
    storage/       durable SQLite/Postgres persistence (leaf layer)
    observability/ dashboard and wiring check
    proofs/        verification scripts, not shipped in the wheel

Import from here rather than from submodules; the submodule layout is an
implementation detail.
"""

from agent_action_gateway.policy.fuses import (
    FuseBudget,
    FuseController,
    FuseLimits,
    FuseTrippedError,
    FuseUnavailableError,
)
from agent_action_gateway.runtime.orchestrator import run
from agent_action_gateway.runtime.session import DEFAULT_FUSE_LIMITS, SafetySession, session

# The names below are what a consumer needs. The remaining imports stay
# reachable so that existing `from agent_action_gateway import X` calls keep working,
# but they are not advertised as part of the public surface.
__all__ = [
    "FuseLimits",
    "SafetySession",
    "run",
    "session",
]
