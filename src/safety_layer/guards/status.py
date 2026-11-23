"""Honest run status derived from evidence.

A provider or agent success claim is not proof of a correct result, so status
is computed from recorded evidence rather than from what the agent reported.
"""


def honest_status(
    *,
    blocked: bool = False,
    suspicious: bool = False,
    unresolved: bool = False,
    error: bool = False,
) -> str:
    """Compute the observability run status from evidence, never an agent success claim."""
    if blocked:
        return "blocked"
    if suspicious or unresolved or error:
        return "degraded"
    return "ok"
