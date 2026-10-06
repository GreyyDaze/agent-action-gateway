from dataclasses import dataclass


@dataclass(frozen=True)
class Order:
    order_id: str
    customer: str
    refund_due: bool


class MockProvider:
    """Reference provider for Phase 0; no safety guards are applied yet."""

    def __init__(self) -> None:
        self.orders = {
            "ORD-100": Order("ORD-100", "Ava", True),
            "ORD-200": Order("ORD-200", "Noah", False),
        }
        self.refunds: list[dict[str, str]] = []

    def lookup_order(self, customer: str) -> Order | None:
        return next((order for order in self.orders.values() if order.customer.lower() == customer.lower()), None)

    def refund(self, order_id: str) -> dict[str, str]:
        self.refunds.append({"order_id": order_id, "status": "refunded"})
        return self.refunds[-1]
