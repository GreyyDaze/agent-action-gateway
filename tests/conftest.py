"""Auto-mark tests by file so suites can run by speed without editing every file.

Lanes:
- live: needs an external service (a live PostgreSQL), env-gated.
- integration: uses a database, socket, or HTTP server.
- evals: quality/evaluation/golden suites.
- unit: everything else (pure, fast).
"""
from __future__ import annotations

import pytest

LIVE = {"test_backend_agreement.py"}
INTEGRATION = {
    "test_gateway.py", "test_gateway_boundary.py", "test_gateway_modes.py",
    "test_egress_gateway.py",
    "test_mcp.py", "test_mcp_server.py", "test_dashboard.py",
    "test_sqlite_base.py", "test_trace.py", "test_trace_capture.py",
    "test_effect_claims.py", "test_receipts.py", "test_guarded_receipts.py",
    "test_retention.py", "test_backend_agreement.py",
    "test_adoption_contract.py", "test_safety_invariants.py",
}
EVALS = {
    "test_evaluation.py", "test_gate.py", "test_gemini_judge.py",
    "test_online_eval.py", "test_trajectory.py", "test_evaluator_pacing.py",
    "test_golden_set_portability.py", "test_failure_promotion.py",
    "test_failure_promotion_drill.py", "test_failure_wall.py",
    "test_silent_failures.py",
}


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    for item in items:
        name = item.path.name
        if name in LIVE:
            item.add_marker(pytest.mark.live)
        elif name in EVALS:
            item.add_marker(pytest.mark.evals)
        elif name in INTEGRATION:
            item.add_marker(pytest.mark.integration)
        else:
            item.add_marker(pytest.mark.unit)
