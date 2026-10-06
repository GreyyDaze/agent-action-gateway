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


class MockPaymentProvider:
    """Failure-injection test double. It is not the production external-action path."""

    def __init__(self, *, dedupe: bool) -> None:
        self.dedupe = dedupe
        self.refunds: list[dict[str, str]] = []

    def refund(self, order_id: str, intent_key: str) -> str:
        if self.dedupe:
            existing = next((item for item in self.refunds if item["intent_key"] == intent_key), None)
            if existing is not None:
                return existing["provider_ref"]
        provider_ref = f"mock-{len(self.refunds) + 1}"
        self.refunds.append({"intent_key": intent_key, "order_id": order_id, "provider_ref": provider_ref})
        return provider_ref

    def find_refund(self, intent_key: str) -> str | None:
        item = next((item for item in self.refunds if item["intent_key"] == intent_key), None)
        return None if item is None else item["provider_ref"]
