"""Durable receipts, so a retried action cannot happen twice."""
from typing import Any

from ..providers.base import ExternalActionProvider
from ..storage.traces import TraceStore

TARGET_KEY = "target"


class UnresolvableReceiptError(RuntimeError):
    """A receipt cannot be resolved because it lacks a replayable target.

    An uncertain side effect must be resolved with the provider before any
    retry. Without a durable target the retry cannot be dispatched safely, so
    this fails loudly rather than guessing.
    """


def execute_side_effect(
    store: TraceStore,
    provider: ExternalActionProvider,
    run_id: str,
    step_id: str,
    arguments: dict[str, Any],
    target: str,
) -> str:
    # The replay target is persisted separately from the caller-supplied
    # arguments, so recovery never depends on the caller's payload shape.
    durable_arguments = dict(arguments)
    durable_arguments.setdefault(TARGET_KEY, target)
    receipt = store.create_receipt(
        run_id, step_id, "external_action", durable_arguments
    )
    if receipt.state != "unknown":
        raise RuntimeError(f"unexpected receipt state: {receipt.state}")
    try:
        provider_ref = provider.execute(target, receipt.intent_key)
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
        target = receipt.arguments.get(TARGET_KEY)
        if not target:
            raise UnresolvableReceiptError(
                f"receipt {receipt.intent_key} has no persisted {TARGET_KEY}; "
                "resolve it manually instead of retrying an uncertain side effect"
            )
        # The target is passed through so a provider that reconciles by
        # replaying its idempotent request can be answered without a
        # lookup-by-key endpoint.
        provider_ref = provider.find(receipt.intent_key, target)
        if provider_ref is not None:
            store.mark_resolved(receipt.intent_key, provider_ref)
            resolved += 1
            continue
        provider_ref = provider.execute(target, receipt.intent_key)
        store.mark_done(receipt.intent_key, provider_ref)
        resolved += 1
    return resolved
