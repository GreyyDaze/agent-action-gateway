import json
from http.client import RemoteDisconnected
from typing import Protocol
from urllib.error import URLError
from urllib.request import Request, urlopen


class RefundProvider(Protocol):
    def refund(self, order_id: str, intent_key: str) -> str: ...
    def find_refund(self, intent_key: str) -> str | None: ...


class HttpRefundProvider:
    """Production boundary between the safety layer and an external HTTP tool."""

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

    def find_refund(self, intent_key: str) -> str | None:
        request = Request(f"{self.base_url}/refunds/{intent_key}", method="GET")
        try:
            with urlopen(request, timeout=self.timeout) as response:
                return json.loads(response.read())["provider_ref"]
        except (URLError, RemoteDisconnected):
            return None
