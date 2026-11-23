# SDK Guide

The SDK is how an agent gets its tools. Your application still owns the agent,
its model and its loop; the SDK only decides what each tool call may do, and
records what happened.

## The session

Every guarded tool comes from a session. The agent receives the wrapped
function, never the raw one, so it cannot route around the checks.

```python
from agent_action_gateway import session

with session(environment="prod") as ctx:
    drop = ctx.tool(drop_table, action="db.drop_table", risk="destructive")
    read = ctx.tool(run_query, action="db.query", risk="read")
    result = ctx.run(agent, task, tools={"drop_table": drop, "query": read})
```

| Method | Purpose |
|---|---|
| `session(store=..., environment=..., limits=...)` | open a session; every argument has a safe default |
| `ctx.tool(fn, action=..., risk=...)` | wrap a function so every call is checked; `risk` defaults to `destructive` |
| `ctx.run(agent, task, tools={...})` | run an agent with the guarded tools it may use |
| `ctx.request_approval(action, arguments)` | create an approval bound to those exact arguments |
| `ctx.approve(id, approver)` / `ctx.deny(id, approver)` | decide a pending approval |
| `ctx.pending_approvals()` | list approvals waiting on a person |
| `ctx.retrying(tool, attempts=...)` | retry transient failures, never refusals (see below) |
| `ctx.record_model_exchange(...)` | record a prompt and completion against the run |

`environment` is one of `dev`, `staging` or `prod` (default `dev`). A tool can
declare where it acts with `target_environment=`; a session cannot reach a
different environment.

### Risk classes

| Risk | Default behaviour |
|---|---|
| `read` | allowed, still budgeted and recorded |
| anything else, or not declared | treated as destructive: needs a fresh approval for the exact arguments |

### What a guarded call returns

A guarded tool returns a dict rather than raising, so the agent can read what
happened and adjust:

| Key | Meaning |
|---|---|
| `status` | `allowed` or `blocked` |
| `decision` | `ALLOW`, `APPROVAL`, `FUSE`, `ENVIRONMENT`, `DISPATCH`, `DEDUPLICATED`, or a result-check name |
| `result` | the tool's return value, or `None` when refused |
| `error` | why it was refused, when refused |
| `missing` | required fields the result did not contain |
| `needs_approval` | true when an approval would resolve the refusal |
| `risk` | the risk class applied |

## Approvals

```python
approval = ctx.request_approval("db.drop_table", {"table": "users"})
ctx.approve(approval.approval_id, "on-call engineer")

drop(table="orders", approval_id=approval.approval_id)  # blocked: approval was for "users"
drop(table="users", approval_id=approval.approval_id)   # allowed
```

An approval is bound to the exact arguments, expires (15 minutes by default),
and works once.

## The intent key: doing an effect once

Each destructive call gets an `intent_key`: a stable identifier for *what the
action is*, not for which run attempted it. A retry after a crash, a second
worker, or the same request sent twice all produce the same key, and only the
first one runs. Later attempts return the recorded result with
`decision: DEDUPLICATED`.

If your function has an `intent_key` parameter (or `**kwargs`), the session
passes the key in. Hand it to your provider as its idempotency key:

```python
def drop_table(table: str, intent_key: str = "") -> dict:
    return db_admin.drop(table, idempotency_key=intent_key)
```

A function without that parameter still cannot run twice: the gateway blocks
the second call either way. The parameter matters for the crash case: if the
process dies *during* the call, a provider that knows the key can say whether
the effect already happened. Without it, the outcome is marked unknown and left
for a person to resolve rather than guessed.

Two options adjust what counts as "the same effect":

```python
# Two tenants must not suppress each other.
ctx.tool(write_config, action="config.write", effect_scope="tenant-a")

# Only these arguments define the effect; others may change between retries.
ctx.tool(open_ticket, action="ticket.open", identity_fields=("service", "title"))
```

See [receipt-guarantees.md](receipt-guarantees.md) for exactly what "once"
means, and when it cannot be guaranteed.

## Limits

Default limits are 50 steps, 600 seconds and $2.00 of model and tool cost per
session. Calling the same action with the same arguments three times without
progress is also stopped. Override them:

```python
from agent_action_gateway import FuseLimits, session

with session(limits=FuseLimits(max_steps=20, max_wall_seconds=120, max_dollars=0.50)) as ctx:
    ...
```

## What is checked, and in what order

Every call through a guarded tool passes these checks before anything reaches
the outside world:

| Check | Behaviour |
|---|---|
| Required input missing | stop |
| Critical input ambiguous | ask, or block when no one can answer |
| Suspiciously empty lookup | cross-check with a second source, then flag |
| Different environment | block |
| Limit reached | stop before the action is sent |
| Same action repeated with no progress | stop |
| Destructive action without approval | block |
| Approval expired, used, or for different arguments | block |
| Safety store unavailable for a write | block; reads continue |
| Effect already applied | return the recorded result; do not run again |
| Outcome of an earlier attempt unknown | block until it is resolved |
| Required evidence missing from the result | report the run as degraded |

None of this needs configuration. An action whose risk was never declared is
treated as destructive.

## Retrying

Retrying is the easiest way to turn a limit into a suggestion: a loop that
retries will eventually get past a cap by asking often enough. So `retrying()`
is asymmetric on purpose:

```python
restart = ctx.retrying(ctx.tool(restart_service, action="service.restart"), attempts=2)
```

| Outcome | Behaviour |
|---|---|
| Allowed but transient failure | retried up to `attempts` times |
| **Blocked** | **never retried** |

A refusal means policy said no, not that the call was unlucky. What counts as
transient is deliberately narrow: an explicit `transient: true`, or a 5xx in
the tool's own result.

## What gets recorded

Every call is recorded, allowed or blocked, with its input and output redacted
before it is written. The SDK does not own your model call, so record the model
exchange yourself if you want it in the audit:

```python
completion = call_your_model(prompt)
ctx.record_model_exchange(
    prompt, completion.text,
    tokens_in=usage.prompt_tokens, tokens_out=usage.completion_tokens,
    cost_usd=usage.cost, latency_ms=usage.elapsed_ms,
)
```

Redaction is applied on write, so tokens, keys, emails and other personal data
are replaced before anything reaches disk. A value you did not record stays NULL,
which means *not captured*, not *empty*.

### Keeping the store small

Prompts grow the store quickly. `agent-gateway prune` discards prompt and
completion payloads when you decide to, and keeps the rows:

```bash
agent-gateway prune --db data/runtime.db --older-than 30 --keep-latest 10 --dry-run
```

Each row keeps its action, timing, cost and outcome, marked
`exchange_state=pruned`, so "discarded" stays distinguishable from "never
recorded". Receipts are never touched. Nothing prunes automatically, and a
prune with neither `--older-than` nor `--keep-latest` is refused.

## MCP

Many agents reach tools through the Model Context Protocol instead of importing
a library. `agent-gateway mcp-serve` serves your configured routes as MCP tools
over stdio, with no MCP SDK required:

```bash
agent-gateway mcp-serve --config routes.json --db gateway.db
```

Every `tools/call` goes through the same policy as the HTTP gateway, so
arriving over MCP buys the caller nothing: the same records, the same receipts,
the same refusals. To register the tools with an MCP library you already use:

```python
from agent_action_gateway.integrations.mcp import MCPToolBridge, tool_definitions

bridge = MCPToolBridge.from_policy(store, policy)
tools = tool_definitions(policy)   # register these with your MCP library
result = bridge.call_tool("deploy", {"service": "api"}, approval_id=approval_id)
```

## Custom action providers

For actions that need their own recovery logic, implement this interface:

```python
execute(target, intent_key) -> provider_ref
find(intent_key, target=None) -> provider_ref | None
```

`execute` performs the action and returns the provider's reference for it.
`find` answers whether an uncertain action already happened, and is the only
part specific to your system. `HttpExternalActionProvider` implements it for any
HTTP service with a lookup-by-key endpoint.

## Release gate verdicts

| Verdict | Meaning | Exit code |
|---|---|---:|
| PASS | the candidate is at least as good as the baseline | 0 |
| FAIL | a confirmed regression, or a failed catastrophic case | 1 |
| UNCERTAIN | the gate could not reach a trustworthy verdict | 3 |
| usage error | the command line was wrong | 2 |

`UNCERTAIN` is non-zero so CI does not pass silently, and it uses 3 so logs can
tell "the change regressed" (1) from "you typed it wrong" (2).

A single run is not an evaluation. Quality verdicts come only from
`agent-gateway gate check`, which compares a candidate against a recorded
baseline.

### Sampling recorded runs

```bash
agent-gateway gate online --db data/runtime.db --sample 0.2 --seed 7
```

This samples recorded runs and reports on them. **It does not block** unless
you pass `--promote`. With `--seed`, the same runs are selected every time, and
a sample too small to support a conclusion says so.

## Storage

`--db` takes a file path (SQLite) or a `postgresql://` URL (PostgreSQL, with
`pip install 'agent-action-gateway[postgres]'`). The schema and migrations are
declared once and run on both. `tests/test_backend_agreement.py` runs the store
checks on both engines and compares the answers; without
`AGENT_GATEWAY_TEST_POSTGRES` set, the PostgreSQL half skips visibly.

## Dashboard security

The dashboard binds to `127.0.0.1` by default and is meant for one operator.

- Every route needs the access token printed at start-up, as `?token=` or an
  `Authorization: Bearer` header.
- Approval forms carry a per-process CSRF token, and a POST from another
  site's `Origin` is rejected.
- The Content-Security-Policy allows no scripts; the page runs no JavaScript.

Restarting the dashboard invalidates tokens and in-flight forms on purpose.

## Observation only: `run()`

`agent_action_gateway.runtime.orchestrator.run(agent, task)` records a trace
and **enforces nothing**: tools the agent reaches directly are not checked. It
exists for recording an agent before you wrap its tools. For protection, use
`session()`.

## Limits of the SDK

The SDK does not:

- prevent hallucinations or judge whether a plan is correct;
- guarantee exactly-once execution when the provider has no idempotency key
  and no way to look up an earlier attempt;
- replace human approval for high-impact actions;
- control the agent's model calls;
- keep a key away from an agent that runs in the same process. For that, run
  the gateway as a separate service: see
  [gateway-deployment.md](gateway-deployment.md).
