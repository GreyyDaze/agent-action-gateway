# Receipt Guarantees

A receipt is the durable record that a side effect was attempted. It is what
lets the gateway promise that the same effect happens once, even after a crash,
a restart, or a second worker.

## Storage

Receipts are stored in SQLite (WAL mode) on a single host, or in PostgreSQL
across hosts. Both backends keep the same invariants, and the claim below is a
single transactional insert on either.

## What "the same effect" means

Each guarded destructive call is identified by an **effect key**: a fingerprint
of the action name and its arguments, plus an optional `effect_scope`. It does
not include the run, the process or the host. So these all produce the same
key, and only the first one executes:

- a retry after a crash
- a second worker picking up the same job
- the same request sent twice

Argument order, float drift and similar accidents do not change the key. Two
options change what counts as the same effect:

| Option | Use |
|---|---|
| `effect_scope="tenant-a"` | keep two tenants' identical actions apart |
| `identity_fields=("service", "title")` | only these arguments define the effect; others may change between retries |

## Lifecycle

The receipt is claimed **before** the action is sent:

```text
claim (insert receipt, state pending)
  |
  +-- someone else already holds it
  |     +-- their attempt finished  -> return their result (DEDUPLICATED)
  |     +-- their attempt failed    -> the effect did not land; may try again
  |     +-- still pending           -> outcome unknown; refuse (EffectInFlight)
  |
  +-- this caller owns it
        +-- action succeeds        -> done, result recorded
        +-- action raises          -> failed; a later attempt may retry
        +-- process dies mid-call  -> stays pending; outcome unknown
```

A receipt left `pending` is the honest state after a crash: nobody knows
whether the action landed. Running it again risks a duplicate, and reporting
success risks a lie, so the gateway refuses both until it is resolved.

## Resolving an unknown outcome

`resolve_unknown()` asks the provider whether the effect already happened,
using the intent key it was sent with:

| Provider capability | Guarantee |
|---|---|
| Idempotency key and a lookup by key | effectively once: the provider settles it |
| Lookup by key, no idempotency | at most once: checked before any retry |
| Neither | no automatic retry; a person resolves it |

We do not claim exactly-once execution when the external system cannot support
or verify it. A receipt with no persisted target cannot be replayed; the
resolver raises `UnresolvableReceiptError` and asks for manual review rather
than guessing.

## Provider interface

For actions that need their own recovery logic, implement
`ExternalActionProvider`:

```python
execute(target, intent_key) -> provider_ref
find(intent_key, target=None) -> provider_ref | None
```

`target` is whatever the action acts on: a deployment, a file path, a row id.
`find` answers whether an uncertain action already happened, and is the only
part specific to your system.

| Adapter | Reconciliation |
|---|---|
| `HttpExternalActionProvider` | `POST /effects` to act, `GET /effects/{intent_key}` to look up |
| your own | whatever your system offers: a lookup by key, or replaying an idempotent request |

### Which failures may be retried

The question is whether the request could have reached the provider.

| Failure | Classification | Retry allowed |
|---|---|---|
| 4xx response | rejected, no effect | yes |
| Connection never established | request not sent | yes |
| 5xx response | ambiguous | no, resolve first |
| Timeout after sending | ambiguous | no, resolve first |
| Connection dropped after sending | ambiguous | no, resolve first |

Anything ambiguous leaves the receipt `pending` for `resolve_unknown`.

## Recovery by action type

| Action type | Recovery |
|---|---|
| Idempotent with lookup | finish by resolving the same intent |
| Reversible | compensate once the provider confirms the original action |
| Irreversible, no lookup | manual resolution |

Approval for destructive actions is a separate lock. Receipts only make the
side-effect lifecycle durable and recoverable.

## How this is verified

`make proof` runs the crash-safety suites against a local HTTP service:

- **crash safety:** 1,000 jobs, each crashed at a random point; no effect is
  applied twice
- **duplicate suppression:** one effect claimed by 1,000 different runs, each
  crashed at a random point; exactly one side effect lands

CI runs them on every push, and at the full 1,000 jobs every night.

## Replay honesty

A replay is only comparable when the run recorded the model, prompt and tool
versions. If a required version is unavailable, the result is `unprovable`, not
a fabricated green result.
