"""Minimal SDK adoption example used by the Phase 7 documentation test."""

from safety_layer import run


def agent(task: str) -> str:
    return f"handled: {task}"


result = run(agent, "look up the refund")
assert result["status"] in {"completed", "degraded"}
print(result["status"])
