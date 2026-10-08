from typing import Any

from .provider import ExternalActionProvider
from .store import TraceStore


ORDER_ID_KEY = "order_id"


class UnresolvableReceiptError(RuntimeError):
    """A receipt cannot be resolved because it lacks a replayable target.

    Rule R-11 requires an uncertain side effect to be resolved before any
    retry. Without a durable target the retry cannot be dispatched safely, so
    this must fail loudly rather than guess.
    """


def execute_side_effect(
    store: TraceStore,
    provider: ExternalActionProvider,
    run_id: str,
    step_id: str,
    arguments: dict[str, Any],
    order_id: str,
) -> str:
    # The replay target is persisted separately from the caller-supplied
    # arguments. Relying on arguments["order_id"] made recovery depend on the
    # caller's payload shape, which crashed the resolver for any other payload.
    durable_arguments = dict(arguments)
    durable_arguments.setdefault(ORDER_ID_KEY, order_id)
    receipt = store.create_receipt(
        run_id, step_id, "external_action", durable_arguments
    )
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


def resolve_unknown(store: TraceStore, provider: ExternalActionProvider) -> int:
    resolved = 0
    for receipt in store.unknown_receipts():
        # The persisted target is checked before anything is asked of the
        # provider. Without it neither reconciliation nor a safe replay is
        # possible, so this is a manual-review condition, not a retry.
        order_id = receipt.arguments.get(ORDER_ID_KEY)
        if not order_id:
            raise UnresolvableReceiptError(
                f"receipt {receipt.intent_key} has no persisted {ORDER_ID_KEY}; "
                "resolve it manually instead of retrying an uncertain side effect"
            )
        # The target is passed through so a provider that reconciles by
        # replaying its idempotent request can be answered without a
        # lookup-by-key endpoint.
        provider_ref = provider.find_refund(receipt.intent_key, order_id)
        if provider_ref is not None:
            store.mark_resolved(receipt.intent_key, provider_ref)
            resolved += 1
            continue
        provider_ref = provider.refund(order_id, receipt.intent_key)
        store.mark_done(receipt.intent_key, provider_ref)
        resolved += 1
    return resolved
