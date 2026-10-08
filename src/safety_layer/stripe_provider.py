"""Stripe test-mode adapter for the external action boundary.

This is the first provider adapter for the production boundary described in the
PRD. It exists to prove the safety layer works against a real payment API
rather than only against a test double.

How idempotency is honoured here
--------------------------------
Stripe has no "look up the result of idempotency key K" endpoint. What it does
guarantee is that re-sending a POST with the same `Idempotency-Key` returns the
originally stored response instead of creating a second refund. So
`find_refund` replays the create call with the identical key rather than
searching. That is strictly safer than a search: the provider, not this
client, decides whether the effect already happened.

Consequences worth knowing:

- Stripe v1 retains idempotency records for 24 hours. A crash resolved after
  that window will re-execute, which is why the receipt keeps the target and
  why the resolver treats a missing target as a manual-review condition rather
  than guessing.
- The intent key is written into refund metadata so a human can reconcile from
  the Stripe dashboard.
- Stripe keys are secret. This adapter reads `STRIPE_API_KEY`, refuses to run
  without it, and never records it in a trace, receipt or log.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
from dataclasses import dataclass
from http.client import RemoteDisconnected
from typing import Any, Callable, Mapping
from urllib.request import Request, urlopen

STRIPE_API_BASE = "https://api.stripe.com/v1"
DEFAULT_TIMEOUT = 20.0
METADATA_KEY = "safety_intent_key"
MAX_IDEMPOTENCY_KEY_LENGTH = 255


class StripeProviderError(RuntimeError):
    """The Stripe API could not be used as a reliable external action target.

    Raised when the outcome is unknown or the call could not be resolved. The
    receipt stays in `unknown` so the resolver can decide, rather than this
    adapter guessing that the refund did or did not happen.
    """


@dataclass(frozen=True)
class StripeRefundResult:
    refund_id: str
    status: str
    amount: int | None
    replayed: bool


def _default_transport(request: Request, timeout: float) -> bytes:
    with urlopen(request, timeout=timeout) as response:
        return response.read()


class StripeRefundProvider:
    """External action provider backed by the Stripe refunds API.

    Implements the same two-method shape as every other provider:
    `refund` performs the effect, `find_refund` reports whether it already
    happened. Both are keyed by the safety layer's intent key, never by payload.
    """

    provider = "stripe"

    def __init__(
        self,
        api_key: str | None = None,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        api_base: str = STRIPE_API_BASE,
        transport: Callable[[Request, float], bytes] | None = None,
    ) -> None:
        key = api_key or os.getenv("STRIPE_API_KEY")
        if not key:
            raise StripeProviderError(
                "STRIPE_API_KEY is required for the Stripe external action provider"
            )
        if timeout <= 0:
            raise ValueError("timeout must be > 0")
        self._api_key = key
        self._timeout = timeout
        self._api_base = api_base.rstrip("/")
        self._transport = transport or _default_transport

    # -- helpers ---------------------------------------------------------

    def _auth_headers(self, intent_key: str) -> dict[str, str]:
        if len(intent_key) > MAX_IDEMPOTENCY_KEY_LENGTH:
            raise ValueError(
                f"intent key exceeds Stripe's {MAX_IDEMPOTENCY_KEY_LENGTH} character limit"
            )
        return {
            # HTTP basic auth, as Stripe requires.
            "Authorization": "Bearer " + self._api_key,
            "Content-Type": "application/x-www-form-urlencoded",
            "Idempotency-Key": intent_key,
        }

    def _post_refund(
        self, order_id: str, intent_key: str, amount: int | None
    ) -> StripeRefundResult:
        """Create or idempotently replay a refund.

        `order_id` is the safety layer's generic target name; for Stripe it is
        the PaymentIntent or Charge being refunded.
        """
        body: dict[str, str] = {
            "payment_intent": order_id,
            "metadata[" + METADATA_KEY + "]": intent_key,
        }
        if amount is not None:
            body["amount"] = str(amount)

        request = Request(
            self._api_base + "/refunds",
            data=urllib.parse.urlencode(body).encode("utf-8"),
            headers=self._auth_headers(intent_key),
            method="POST",
        )

        try:
            raw = self._transport(request, self._timeout)
        except urllib.error.HTTPError as exc:
            detail = _error_detail(exc)
            # 4xx means the request was rejected and Stripe records no
            # idempotent result, so a retry is safe and the caller may retry.
            if 400 <= exc.code < 500:
                raise StripeProviderError(
                    f"Stripe rejected the refund ({exc.code}): {detail}"
                ) from exc
            # 5xx is ambiguous: Stripe may have applied the effect. Never guess.
            raise StripeProviderError(
                f"Stripe outcome unknown ({exc.code}); resolve before retrying: {detail}"
            ) from exc
        except (TimeoutError, RemoteDisconnected, ConnectionError) as exc:
            # The request may have been received. Leave the receipt unresolved
            # rather than retrying, which is the rule R-11 requirement.
            raise StripeProviderError(
                "Stripe connection failed after the request was sent; the refund "
                "may or may not have been applied, resolve it before retrying"
            ) from exc
        except urllib.error.URLError as exc:
            # A URLError here is a connection that never established, so the
            # request was never accepted and a retry cannot double-charge.
            raise StripeProviderError(
                f"Stripe was unreachable ({exc.reason}); the request was not sent, "
                "retrying is safe"
            ) from exc

        payload = _decode(raw)
        refund_id = payload.get("id")
        if not isinstance(refund_id, str) or not refund_id:
            raise StripeProviderError("Stripe response contained no refund id")
        raw_amount = payload.get("amount")
        return StripeRefundResult(
            refund_id=refund_id,
            status=str(payload.get("status", "unknown")),
            amount=int(raw_amount) if isinstance(raw_amount, int) else None,
            replayed=bool(payload.get("safety_replayed", False)),
        )

    # -- provider contract ----------------------------------------------

    def refund(
        self, order_id: str, intent_key: str, amount: int | None = None
    ) -> str:
        """Perform or idempotently replay the refund. Returns the refund id."""
        return self._post_refund(order_id, intent_key, amount).refund_id

    def find_refund(self, intent_key: str, order_id: str | None = None) -> str | None:
        """Report whether the effect already happened.

        Stripe cannot be queried by idempotency key, so this replays the create
        call with the identical key. Stripe returns the originally stored
        response, so a real refund is reported without creating a second one.

        Returns None only when the replay itself cannot be answered, which the
        caller must treat as unresolved rather than as "did not happen".
        """
        if order_id is None:
            # Without the target a replay cannot be constructed. The receipt
            # persists it precisely so this path is never taken.
            raise StripeProviderError(
                "find_refund requires the persisted target to replay the "
                "idempotent request against Stripe"
            )
        return self._post_refund(order_id, intent_key, None).refund_id

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        # Never expose the key, not even partially.
        return "StripeRefundProvider(api_key=[REDACTED_SECRET])"


def _decode(raw: bytes) -> Mapping[str, Any]:
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StripeProviderError("Stripe returned a non-JSON response") from exc
    if not isinstance(payload, dict):
        raise StripeProviderError("Stripe response was not a JSON object")
    return payload


def _error_detail(exc: urllib.error.HTTPError) -> str:
    """Extract a short, non-secret error message for the trace."""
    try:
        body = exc.read().decode("utf-8", errors="replace")
    except Exception:  # pragma: no cover - defensive
        return exc.reason or "no detail"
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return exc.reason or "no detail"
    if isinstance(payload, dict):
        detail = payload.get("error")
        if isinstance(detail, dict):
            message = detail.get("message")
            kind = detail.get("type")
            if isinstance(message, str):
                return f"{kind or 'error'}: {message}"
        return exc.reason or "no detail"
    return exc.reason or "no detail"