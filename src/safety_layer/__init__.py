"""Agent Safety Layer — prevention-first safety and evaluation for AI agents.

The public surface is intentionally small. A user wraps their own agent and
receives recorded evidence and enforced policy; the safety layer does not own
the agent loop or the agent's model calls.

Layout:

    core/        enforcement: fuses, approval locks, stop rules, receipts
    evidence/    redaction, capture policy, honest status, failure grouping
    storage/     durable SQLite persistence
    evaluation/  golden set, judges, verdict engine, regression gate
    providers/   external action adapters (HTTP, Stripe, test doubles)
    runtime/     run orchestration
    interface/   CLI and dashboard
    proofs/      verification scripts, not shipped in the wheel

Import from here rather than from submodules; the submodule layout is an
implementation detail.
"""

from .core.fuses import (
    FuseBudget,
    FuseController,
    FuseLimits,
    FuseTrippedError,
    FuseUnavailableError,
)
from .runtime.orchestrator import run
from .runtime.session import DEFAULT_FUSE_LIMITS, SafetySession, session

# The names below are what a consumer needs. The remaining imports stay
# reachable so that existing `from safety_layer import X` calls keep working,
# but they are not advertised as part of the public surface.
__all__ = [
    "FuseLimits",
    "SafetySession",
    "run",
    "session",
]
