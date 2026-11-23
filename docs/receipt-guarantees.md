# Receipt Guarantees

## Production path

Receipts are stored in SQLite (WAL mode) on a single host, or in PostgreSQL across hosts. The storage boundary is durable and transactional, and both backends keep the same receipt invariants.

The external action boundary is HTTP. The provider receives the same intent key used by the receipt and exposes a verification query for recovery.

## Receipt lifecycle

```text
unknown
  |
  +--> external action
  |       |
  |       +--> success -> done
  |       +--> uncertain/crash -> unknown
  |
  +--> recovery query
          |
          +--> found -> resolved
          +--> not found -> retry same intent key -> done
```

The receipt is written before dispatch. The intent key is `run_id:step_id`, so a retry represents the same intent rather than a new request.

## Provider guarantees

| Provider capability | Guarantee |
|---|---|
| Idempotency + verification | Effectively-once for the supported intent-key path |
| Verification without provider dedupe | At-most-once from our retry logic, with provider verification before retry |
| No verification mechanism | Not supported for automatic retry; manual resolution is required |

We do not claim exactly-once execution when the external system cannot support or verify it.

## Action-class compensation

| Action class | Recovery policy |
|---|---|
| Send/refund with verification | Forward-fix by resolving the same intent |
| Reversible action | Compensate if the provider confirms the original action |
| Irreversible action | Manual resolution queue |

Approval for destructive actions is a separate lock. Receipts only make the side-effect lifecycle durable and recoverable.

## Replay honesty

A replay is only considered comparable when the run records the model, prompt, and tool versions available to the evaluator. If the required version is unavailable, the result is `unprovable`, not a fabricated green result.

## Provider adapters

The external action boundary is a two-method protocol, `ExternalActionProvider`:

```python
execute(target, intent_key) -> provider_ref
find(intent_key, target=None) -> provider_ref | None
```

`target` is whatever the action acts on: a PaymentIntent on Stripe, a file
path for a delete tool, a row id for a database write. Nothing in the safety layer assumes
a payment domain, and unregistered actions are treated as destructive
regardless of what they do.

Adapters may ignore `order_id` when they can reconcile by key alone. The older
The provider interface uses generic method names (`execute`, `find`); no refund-specific names remain.

| Adapter | Status | Reconciliation strategy |
|---|---|---|
| `HttpExternalActionProvider` | generic HTTP, requires a lookup-by-key endpoint | `GET /refunds/{intent_key}` |
| `StripeRefundProvider` | Stripe test mode | replays the create request with the same `Idempotency-Key` |
| `MockPaymentProvider` | test double only | in-memory lookup |

### Why the Stripe adapter replays instead of searching

Stripe has no "look up the result of idempotency key K" endpoint. It does
guarantee that re-sending a POST with the same `Idempotency-Key` returns the
originally stored response instead of creating a second refund.

So `StripeRefundProvider.find` replays the create call rather than
searching. This is strictly safer than a search would be: the provider, not this
client, decides whether the effect already happened.

Two consequences are documented rather than papered over:

- Stripe v1 retains idempotency records for **24 hours**. A crash resolved after
  that window will re-execute. This is why the receipt persists its target: the
  resolver can always reconstruct the replay.
- A receipt with no persisted target cannot be reconciled or replayed. The
  resolver raises `UnresolvableReceiptError` and requires manual review rather
  than retrying an uncertain side effect.

### Failure classification

The distinction that matters is whether the request reached Stripe.

| Failure | Classification | Retry allowed |
|---|---|---|
| 4xx response | rejected, no effect | yes |
| Connection never established | request not sent | yes |
| 5xx response | ambiguous | no, resolve first |
| Timeout after sending | ambiguous | no, resolve first |
| Connection dropped after sending | ambiguous | no, resolve first |

Anything ambiguous leaves the receipt in `unknown` for `resolve_unknown`.

### Test coverage

`tests/test_stripe_provider.py` runs a local HTTP server implementing the real
Stripe contract (auth, form-encoded bodies, `Idempotency-Key` replay, the error
envelope), so the wire format and idempotency semantics are exercised against a
server this project does not control, with no credentials and no network.

A live Stripe test-mode test is included and skipped unless `STRIPE_API_KEY` and
`STRIPE_TEST_PAYMENT_INTENT` are set. Test mode moves no money.
