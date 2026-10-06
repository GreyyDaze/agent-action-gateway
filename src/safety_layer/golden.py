from .evaluation_models import GoldenCase


def seed_golden_cases() -> tuple[GoldenCase, ...]:
    cases: list[GoldenCase] = [
        GoldenCase(
            "refund-001",
            "Refund Ava's order ORD-100",
            {"order_id": "ORD-100", "status": "refunded"},
            "field-equality",
            "seed",
            rubric=("uses the requested order", "reports refunded status"),
        ),
        GoldenCase(
            "refund-002",
            "Refund Noah's order ORD-200",
            {"order_id": "ORD-200", "status": "refunded"},
            "field-equality",
            "seed",
            rubric=("uses the requested order", "reports refunded status"),
        ),
        GoldenCase(
            "tool-001",
            "Call refund for ORD-100",
            {"tool": "refund", "arguments": {"order_id": "ORD-100"}},
            "exact",
            "seed",
            catastrophic=True,
        ),
        GoldenCase(
            "tool-002",
            "Look up ORD-100",
            {"tool": "lookup_order", "arguments": {"order_id": "ORD-100"}},
            "exact",
            "seed",
        ),
        GoldenCase(
            "text-001",
            "Report the refund result",
            "refunded",
            "regex",
            "seed",
            rubric=("states that the refund completed",),
        ),
    ]
    for index in range(6, 31):
        cases.append(
            GoldenCase(
                f"refund-{index:03d}",
                f"Refund order ORD-{index:03d}",
                {"order_id": f"ORD-{index:03d}", "status": "refunded"},
                "field-equality",
                "seed",
                rubric=("uses the requested order", "reports refunded status"),
            )
        )
    return tuple(cases)


def case_count() -> int:
    return len(seed_golden_cases())
