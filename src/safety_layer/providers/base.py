"""The interface every external action adapter implements."""
import json
from http.client import RemoteDisconnected
from typing import Protocol
from urllib.error import URLError
from urllib.request import Request, urlopen


class ExternalActionProvider(Protocol):
    """Adapter for whatever external system a proposed action targets.

    Named generically on purpose. The safety layer guards any irreversible
    side effect, not only refunds, so nothing in this contract assumes a
    payment domain. `order_id` is this package's generic name for the action's
    target: a PaymentIntent on Stripe, a file path for a delete tool, a row id
    for a database write.
    """

    def refund(self, order_id: str, intent_key: str) -> str: ...

    def find_refund(self, intent_key: str, order_id: str | None = None) -> str | None:
        """Report whether the effect already happened for this intent key.

        `order_id` is the target the receipt persisted, passed so providers
        whose reconciliation needs it (for example one that replays an
        idempotent request) can be queried without a lookup-by-key endpoint.
        Providers that reconcile by key alone may ignore it.
        """


class HttpExternalActionProvider:
    """Generic HTTP boundary to an external tool.

    Expects a provider that exposes a lookup-by-key endpoint, for example
    `GET /refunds/{intent_key}`. Providers without one (Stripe among them)
    reconcile differently; see docs/receipt-guarantees.md.
    """

    def __init__(self, base_url: str, timeout: float = 5.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def refund(self, order_id: str, intent_key: str) -> str:
        payload = json.dumps({"order_id": order_id, "intent_key": intent_key}).encode()
        request = Request(
            f"{self.base_url}/refunds",
            data=payload,
            headers={"Content-Type": "application/json", "Idempotency-Key": intent_key},
            method="POST",
        )
        with urlopen(request, timeout=self.timeout) as response:
            return json.loads(response.read())["provider_ref"]

    def find_refund(self, intent_key: str, order_id: str | None = None) -> str | None:
        request = Request(f"{self.base_url}/refunds/{intent_key}", method="GET")
        try:
            with urlopen(request, timeout=self.timeout) as response:
                return json.loads(response.read())["provider_ref"]
        except (URLError, RemoteDisconnected):
            return None


# Backwards-compatible aliases. The package is not yet published, but the
# refund-specific names appeared in the SDK surface, so they keep working.
RefundProvider = ExternalActionProvider
HttpRefundProvider = HttpExternalActionProvider
