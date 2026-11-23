# SDK Integration

The SDK is the small boundary between an existing agent and the safety layer.

## 3-line adoption

```python
from agent_action_gateway import run

result = run(agent, task)
print(result["status"])
```

The application still owns `agent`, its model, its provider, and its model loop.

## Package layout

```
agent_action_gateway/
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

The package ships all of these. Import from `agent_action_gateway` itself; the
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
from agent_action_gateway import session

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
raised. Quality verdicts come exclusively from `agent-gateway gate check`, which
compares a candidate against a recorded baseline.

## Provider boundary

The external agent may use any model provider. Its provider is outside this project's control.

The evaluation path may use the supported hosted judge providers. Provider identity and model metadata are recorded without recording credentials.

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


## Current limitations

The SDK does not claim:

- universal hallucination prevention;
- exactly-once execution when the external provider cannot support idempotency or reconciliation;
- automatic root-cause attribution for every production failure;
- replacement of human approval for high-impact actions;
- control over the external agent's LLM calls;
- a universal agent framework.

These are scope boundaries, not hidden implementation gaps.

## What gets recorded

Every trace row keeps the task (`input`) and what the tool returned
(`output`), redacted before it is written. Neither of those is the model
exchange, so a session can record it separately:

~~~python
with session() as ctx:
    completion = call_your_model(prompt)
    ctx.record_model_exchange(
        prompt, completion.text,
        tokens_in=usage.prompt_tokens, tokens_out=usage.completion_tokens,
        cost_usd=usage.cost, latency_ms=usage.elapsed_ms,
    )
~~~

The SDK does not own your model call, so it cannot see this by itself. If you
do not call it, the exchange columns stay NULL — which means *not captured*,
not *empty*. An audit that reads a NULL as zero spend would be wrong.

Prompts and completions go through the same recursive redaction as every other
field, so a card number, email, bearer token or IBAN in either is replaced
before it reaches disk. You do not need to sanitise before handing them over.

**Growth and retention.** Prompts are typically several times larger than tool
results, so a run that records exchanges makes `trace_events` grow much faster.

`agent-gateway prune` discards the payloads when you decide to:

~~~bash
agent-gateway prune --db data/runtime.db --older-than 30 --keep-latest 10 --dry-run
~~~

It clears the prompt and completion and **leaves the row**, with its action,
timing, cost and outcome intact, stamped `exchange_state=pruned`. A later reader
can tell "captured and since discarded" from "never captured" -- three states
rather than a NULL that could mean either. Receipts are never touched.

Nothing prunes automatically. A silent retention policy is a silent deletion of
evidence, so this is a command a person typed, and running it with neither
`--older-than` nor `--keep-latest` is refused rather than treated as "prune
everything". On SQLite the file is also `VACUUM`ed so the space is actually
returned; PostgreSQL reclaims it on its own.

## Self-correction

Retrying is the highest-leverage thing an agent can do, and the easiest way to
turn a safety limit into a suggestion. A loop that retries will eventually get
past a cap by asking often enough. So `retrying()` is asymmetric on purpose:

~~~python
refund = ctx.retrying(ctx.tool(refund_fn, action="refund", risk="destructive"), attempts=2)
~~~

| Outcome | Behaviour |
|---|---|
| Allowed | Retried up to `attempts` times |
| **Blocked** | **Never retried** |

A refusal means policy said no, not that the call was unlucky. Retrying it burns
budget, and on a destructive route it is the guard being probed rather than
obeyed. The refusal check runs *before* the transient check, so a refusal that
claims to be transient is still not retried.

What counts as transient is deliberately narrow: an explicit `transient: true`,
or a 5xx in the tool's own return. Anything unrecognised goes straight back to
you, because retrying an unknown failure is how a budget disappears.

A held action never reaches the tool at all, so there is usually nothing to
retry. The retry guard matters for the case where a tool reports a refusal from
its own provider *after* being called — the refusal is still honoured.

Repeated identical calls to one guarded action are stopped by the existing
no-progress guard regardless of retry settings. Two independent bounds.

## Sampling your recorded runs

The offline gate compares your evaluation cases against a baseline. It cannot
tell you whether the runs arriving from production have degraded, because those
runs were never evaluated.

~~~bash
agent-gateway gate online --db data/runtime.db --sample 0.2
~~~

**It reports; it does not block.** Promotion to a failing exit code requires
`--promote`, so turning it on is a visible decision rather than a default nobody
chose. The reasoning is specific: an online judge is stochastic and unproven
against a human, and a gate that fires on noise gets switched off within a week
-- which loses the signal entirely.

Pass `--seed` and the same runs are selected every time, so a report can be
reproduced instead of argued about. A sample too small to support a conclusion
says so and returns success, because too little data is not a pass and not a
failure.

Runs a human already held are reported as held rather than degraded, and any
case where a human mark and the scorer disagree is listed. A judge that quietly
disagrees with a person is a broken judge, and hiding that is how it stays
broken.

## MCP

Production agents reach tools through the Model Context Protocol rather than by
importing a library. A LangGraph or OpenAI Agents SDK agent has no Python
function here to wrap, so without an MCP surface this library is simply not in
the path.

`interface/mcp.py` is that surface. It is a **policy layer, not a transport**:
it converts a `GatewayPolicy` into MCP-shaped tool definitions and routes every
`call_tool` through the same `SafetyGateway.handle` the HTTP gateway uses.

~~~python
from agent_action_gateway.integrations.mcp import MCPToolBridge, tool_definitions

bridge = MCPToolBridge.from_policy(store, policy)
tools = tool_definitions(policy)      # register these with your MCP library
result = bridge.call_tool("charge", {"amount": 100}, approval_id=approval_id)
~~~

There is no second policy path, so arriving over MCP instead of HTTP buys the
caller nothing: identical trace rows, identical receipts, identical refusals.
`tests/test_mcp.py` asserts that by performing the same action through both
doors and comparing what was written.

No MCP SDK is imported. A dependency on someone else's release schedule would
make the enforcement path non-stdlib for every adopter, and a protocol
implementation here would be untested against the real specification. Pair this
with whichever MCP library you already use.

## Database backends

`--db` takes a filesystem path (SQLite) or a `postgres://` URL (PostgreSQL). The
schema and the migrations are declared once and run on either.

A `postgres://` URL needs `psycopg`, which is an optional extra:

    pip install 'agent-action-gateway[postgres]'

`tests/test_backend_agreement.py` runs every store check against both engines and
compares the answers. When `AGENT_GATEWAY_TEST_POSTGRES` is not set, the PostgreSQL half
skips loudly rather than passing quietly.

Writes remain single-writer-per-row. PostgreSQL removes the single-host ceiling;
it does not turn this into a distributed lock service.

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
python -c 'from agent_action_gateway import run; print(run(lambda task: f"handled: {task}", "smoke"))'
agent-gateway --help
agent-gateway check --db data/runtime.db
```

`agent-gateway check` reports on your own integration. Evidence about this library is
published in the CI badge; regenerate it from a source checkout with `make proof`.
