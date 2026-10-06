# Phase 1 Receipt Guarantees

## Production path

Phase 1 uses SQLite in WAL mode as the production persistence stack for the current self-hosted, single-node product. The storage boundary is durable and transactional. A future multi-node deployment can add PostgreSQL without changing receipt invariants.

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

Phase 2 adds the destructive-action approval lock. Phase 1 only makes the side-effect lifecycle durable and recoverable.

## Replay honesty

A replay is only considered comparable when the run records the model, prompt, and tool versions available to the evaluator. If the required version is unavailable, the result is `unprovable`, not a fabricated green result.
