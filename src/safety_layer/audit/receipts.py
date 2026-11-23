"""Durable receipts, so a retried action cannot happen twice."""
from __future__ import annotations

from typing import Any

from safety_layer.integrations.adapters.base import ExternalActionProvider
from safety_layer.policy.fingerprint import fingerprint
from safety_layer.storage.traces import TraceStore

TARGET_KEY = "target"


class UnresolvableReceiptError(RuntimeError):
    """A receipt cannot be resolved because it lacks a replayable target.

    An uncertain side effect must be resolved with the provider before any
    retry. Without a durable target the retry cannot be dispatched safely, so
    this fails loudly rather than guessing.
    """


class EffectInFlight(RuntimeError):
    """The effect was claimed by another attempt that has not finished.

    This is the honest state. A crash between claiming and completing leaves
    the receipt `pending`, and whether the action landed is genuinely unknown.
    Raising is correct: executing again risks a duplicate, and reporting
    success risks a lie. `resolve_unknown()` is how a human settles it.
    """


class RetryableEffect(RuntimeError):
    """The effect was claimed before and failed, so it may be tried again.

    Distinct from `EffectInFlight` because the outcome is known: the previous
    attempt did not land, so a retry is safe.
    """


def claim_effect(
    store: TraceStore,
    run_id: str,
    step_id: str,
    action: str,
    arguments: dict[str, Any],
    *,
    scope: str = "",
    identity_fields: tuple[str, ...] = (),
) -> tuple[Any, bool]:
    """Claim an effect before executing it.

    Returns `(receipt, owned)`. `owned` is true only for the caller that created
    the receipt, which is the single caller permitted to execute the effect.

    This needs no provider. The effect key is derived from the action and its
    arguments, so two claims of the same effect collide in the database no
    matter which run, process or host they came from.
    """
    effect_key = fingerprint(
        action, arguments, scope=scope, identity_fields=identity_fields
    )
    return store.claim_receipt(effect_key, run_id, step_id, action, arguments)


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
