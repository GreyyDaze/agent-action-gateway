from typing import Any

from .provider import RefundProvider
from .store import TraceStore


def execute_side_effect(
    store: TraceStore,
    provider: RefundProvider,
    run_id: str,
    step_id: str,
    arguments: dict[str, Any],
    order_id: str,
) -> str:
    receipt = store.create_receipt(run_id, step_id, "external_action", arguments)
    if receipt.state != "unknown":
        raise RuntimeError(f"unexpected receipt state: {receipt.state}")
    try:
        provider_ref = provider.refund(order_id, receipt.intent_key)
    except TimeoutError:
        raise
    except Exception:
        store.mark_failed(receipt.intent_key)
        raise
    store.mark_done(receipt.intent_key, provider_ref)
    return provider_ref


def resolve_unknown(store: TraceStore, provider: RefundProvider) -> int:
    resolved = 0
    for receipt in store.unknown_receipts():
        provider_ref = provider.find_refund(receipt.intent_key)
        if provider_ref is not None:
            store.mark_resolved(receipt.intent_key, provider_ref)
            resolved += 1
            continue
        provider_ref = provider.refund(receipt.arguments["order_id"], receipt.intent_key)
        store.mark_done(receipt.intent_key, provider_ref)
        resolved += 1
    return resolved
