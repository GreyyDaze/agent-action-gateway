# SDK Integration

The SDK is the small boundary between an existing agent and the safety layer.

## 3-line adoption

```python
from safety_layer import run

result = run(agent, task)
print(result["status"])
```

The application still owns `agent`, its model, its provider, and its model loop.

## Package layout

```
safety_layer/
├── core/        deterministic enforcement: fuses, locks, stop rules, receipts
├── evidence/    redaction, capture policy, honest status, failure grouping
├── storage/     SQLite persistence, one connection policy and migration strategy
├── evaluation/  golden set, judges, verdict engine, regression gate
│   └── providers/  hosted evaluation judges (optional)
├── providers/   external action adapters: HTTP, Stripe, test doubles
├── runtime/     run orchestration, the session and tool guard
├── interface/   CLI commands, the local dashboard, the HTTP gateway
└── proofs/      verification scripts and manual drills
```

The package ships all of these. Import from `safety_layer` itself; the
submodule layout is an implementation detail and may change.

## Ownership boundary

```text
YOUR APPLICATION
    |
    | agent(task)
    v
EXTERNAL AGENT + ITS LLM
    |
    | proposed work/action
    v
SAFETY LAYER
    |
    +-- deterministic runtime checks
    +-- approvals / locks
    +-- receipts / recovery
    +-- budgets / loop controls
    +-- traces / evidence
    +-- optional evaluation gate
```

The safety layer does not require ownership of the external agent's LLM provider.

The optional LLM judge belongs only to evaluation. It must not become the authority for safety policy, destructive approval, receipt state, budgets, or deterministic gate rules.

## What `run()` does

There are two entry points, and they do different things. Confusing them is how
an adopter ends up unprotected while believing otherwise.

### `session()` — the enforced path

`session()` is where enforcement lives. Tools handed to the agent come from the
session, so the agent never holds the raw function and cannot route around the
policy.

| Control | Where it runs |
|---|---|
| Risk classification (unknown = destructive) | on every call |
| Step / time / spend budgets | before dispatch, on every call |
| Cross-environment blocking | before dispatch |
| Destructive approval (payload digest, expiry, single use) | before dispatch |
| Durable receipt and idempotency | around dispatch |
| Stop rules on the result | after dispatch |
| Trace and honest status | every call |

#### Using a session

```python
from safety_layer import session

with session() as ctx:
    refund = ctx.tool(refund_fn, action="refund", risk="destructive")
    result = ctx.run(agent, task, tools={"refund": refund})
```

| Method | Purpose |
|---|---|
| `session(store=..., environment=..., limits=...)` | open a session; every argument has a working default |
| `ctx.tool(fn, action=..., risk=...)` | wrap a function so every call is checked. `risk` defaults to `destructive` |
| `ctx.run(agent, task, tools={...})` | run an agent with the guarded tools it may use |
| `ctx.request_approval(action, arguments)` | create an approval bound to those exact arguments |
| `ctx.approve(id, approver)` / `ctx.deny(id, approver)` | decide a pending approval |
| `ctx.pending_approvals()` | list approvals waiting on a person |

A guarded tool returns a dict rather than raising, so an agent can read what
happened and correct itself:

| Key | Meaning |
|---|---|
| `status` | `allowed` or `blocked` |
| `decision` | `ALLOW`, `APPROVAL`, `FUSE`, `ENVIRONMENT`, `DISPATCH`, or a result-check name |
| `result` | the tool's return value, or `None` when refused |
| `error` | why it was refused, when refused |
| `missing` | required fields the result did not contain |
| `needs_approval` | true when the refusal is resolved by getting an approval |
| `risk` | the risk class applied |

Default budgets are 50 steps, 600 seconds and $2.00 per session. Override them
with `limits=FuseLimits(...)`.

The approval flow:

```python
approval = ctx.request_approval("refund", {"order_id": "ORD-100", "amount": 400})
ctx.approve(approval.approval_id, "operator")

refund(order_id="ORD-100", amount=400, approval_id=approval.approval_id)  # allowed
refund(order_id="ORD-100", amount=500, approval_id=approval.approval_id)  # blocked: payload changed
```

An approval is bound to the exact arguments, expires, and is consumed on use.

### `run()` — the observation path

`run(agent, task)` records a trace and returns a result. It reports
`"enforcement": "observe"`.

**It does not authorize, budget, or receipt anything.** An agent that reaches a
payment API directly through `run()` is not stopped, because `run()` was never
given the tools.

> Tools not obtained from a session are not enforced. That is true by
> construction rather than by omission, and it is the one sentence that matters.

The SDK wrapper is not a universal agent framework.

## Result status

Runtime status and evaluation verdict are different concepts.

- Runtime status describes what happened during the run.
- Gate verdict describes whether an evaluation result is trustworthy and acceptable.

Gate verdicts are:

| Verdict | Meaning | CLI exit code |
|---|---|---:|
| PASS | evidence supports the candidate | 0 |
| FAIL | a confirmed regression was detected | 1 |
| UNCERTAIN | the gate could not establish a trustworthy verdict | 3 |
| usage error | the command line itself was wrong | 2 |

`UNCERTAIN` is intentionally non-zero for CI. An untrustworthy evaluation must not silently pass. It is also **not** a false regression and must not be added to the false-alarm ledger as a FAIL.

`UNCERTAIN` uses 3 rather than 2 because 2 is what `argparse` exits with on a
usage error. Keeping them distinct means CI logs can tell "the change regressed"
(1) apart from "the gate could not tell" (3) and "you typed it wrong" (2).

A **single run** is not an evaluation and does not produce PASS or FAIL. `run()`
records `NOT_EVALUATED` for a completed run and `FAIL` only when the agent
raised. Quality verdicts come exclusively from `safety gate check`, which
compares a candidate against a recorded baseline.

## Provider boundary

The external agent may use any model provider. Its provider is outside this project's control.

The evaluation path may use the supported hosted judge providers defined by the PRD. Provider identity and model metadata are recorded without recording credentials.

Evaluation/proof runs are pinned to their configured provider/model. They must not silently change provider during a comparison.

### External action providers

The external tool boundary is the `ExternalActionProvider` interface:

```python
execute(target, intent_key) -> provider_ref
find(intent_key, target=None) -> provider_ref | None
```

`target` is whatever the action acts on, so the same interface guards a
payment refund, a file delete, or a database write. `execute` performs the
action and returns a reference the provider knows it by. `find` answers
whether an uncertain action already landed, and is the only part a provider
must implement in a way specific to its own system. Unregistered actions
default to destructive regardless of domain.

| Adapter | Use |
|---|---|
| `HttpExternalActionProvider` | any HTTP tool exposing a lookup-by-key endpoint |
| `StripeRefundProvider` | Stripe test mode; reconciles by replaying the idempotent request |
| `MockPaymentProvider` | test double only |

See `docs/receipt-guarantees.md` for reconciliation strategies, the failure
classification that decides whether a retry is safe, and the Stripe 24-hour
idempotency limit.

Provider outages, authentication errors, and rate limits must surface as evaluation availability problems, not as safety-policy bypasses.

## Credentials

Provider API keys are configuration, not trace data.

Keys may be supplied through environment variables or local developer secret configuration. They must never be written to:

- traces;
- receipts;
- regression cases;
- evaluation artifacts;
- normal runtime records.

## What is enforced, and when

These run inside a `session()`, in this order, before any tool reaches the
outside world:

| Check | Behaviour |
|---|---|
| Required input missing | stop |
| Critical input ambiguous | ask, or block in headless mode |
| Suspiciously empty lookup | cross-check with a second source, then flag |
| Cross-environment action | block |
| Budget exhausted | stop before the action is sent |
| Repeated action making no progress | stop |
| Destructive action without approval | block |
| Approval expired | block |
| Payload changed after approval | block |
| Safety service unavailable for a write | block; reads continue |
| Side effect outcome unknown | resolve with the provider before retrying |
| Duplicate request for the same intent | deduplicate according to the provider |
| Required evidence missing | report the run as degraded |
| A catastrophic case fails in the gate | FAIL regardless of the average |
| Judge or baseline incompatible | UNCERTAIN |

None of this needs configuration. The defaults are the safe side: an action
whose risk class was never declared is treated as destructive.

`docs/PRD.md` is the normative contract.

## Current limitations

The SDK does not claim:

- universal hallucination prevention;
- exactly-once execution when the external provider cannot support idempotency or reconciliation;
- automatic root-cause attribution for every production failure;
- replacement of human approval for high-impact actions;
- control over the external agent's LLM calls;
- a universal agent framework.

These are scope boundaries, not hidden implementation gaps.

## Dashboard security

The dashboard binds `127.0.0.1` by default and is a single-operator local tool.
It has no user accounts and no authentication, so it must not be exposed on a
shared network.

The approval queue is the human trust boundary of the product, so approval
writes are protected specifically:

- every approval form carries a per-process CSRF token, compared with
  `secrets.compare_digest`;
- a POST carrying a cross-site `Origin` header is rejected with 403;
- responses set `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`
  and a restrictive `Content-Security-Policy`.

CSRF tokens and the origin allowlist are per server process, so restarting the
dashboard invalidates in-flight forms. That is intentional.

## Verification

From outside the repository, after installing the package:

```bash
python -c 'from safety_layer import run; print(run(lambda task: f"handled: {task}", "smoke"))'
safety --help
safety proof --jobs 1000
```

For the full acceptance workflow, use the recorded proof in `docs/history/release-proof.md`.
