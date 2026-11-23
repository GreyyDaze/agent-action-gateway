# Agent Action Gateway

[![CI](https://github.com/GreyyDaze/agent-action-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/GreyyDaze/agent-action-gateway/actions/workflows/ci.yml)

**Let AI agents change real systems safely. You control what they can do, and
you can prove what they did.**

## The problem

To change production, an AI agent needs a key: an API token, a database
password, a cloud credential. Today the agent usually holds that key itself.

So when the agent is confused, wrong, or tricked by a prompt injection, nothing
stands between its decision and the damage. It can delete a database, run the
same change twice after a timeout, or loop until the bill is huge. Afterwards, nobody can
say exactly what happened.

Most guardrails run inside the agent's own process. If the agent goes wrong,
the guardrail goes wrong with it.

## The idea

Move the key out of the agent, and put a gateway in the middle:

~~~text
BEFORE   agent ─────────────────────────►  production
         [holds the key]

AFTER    agent ───►  Agent Action Gateway  ───►  production
                     [holds the key, checks every action, records everything]
~~~

The agent still does its work. But every action passes one checkpoint that it
cannot go around.

## Control: the agent can only do what you allow

| Problem | What the gateway does |
|---|---|
| The agent holds the key | The gateway holds the key. The agent gets a placeholder that is useless anywhere else. |
| Risky actions have no checkpoint | A destructive action waits for a human to approve **that exact action**. Approving one action does not approve a different one, and an approval works only once. |
| A retry repeats the action | Each real-world effect happens **once**, even after a crash, a restart, or a second worker retries it. |
| The agent runs away | Limits on steps, time and spend stop it. Repeating the same call with no progress is stopped too. |
| The agent reaches the wrong place | A session for `dev` or `staging` cannot reach `prod`. |
| Someone skips the gateway | `agent-gateway check` finds tools and code paths that bypass it. |

## Prove: you can show what happened

| Problem | What the gateway does |
|---|---|
| Nobody can tell what happened | Every attempt, allowed or blocked, is recorded with secrets hidden, and shown in a dashboard. |
| Nobody knows if the agent got better or worse | A release gate tests each new agent version against your own cases before you ship it. |

## Measured, not claimed

These numbers come from proof suites that CI runs on every push, and at the
full 1,000 jobs every night. Reproduce them with `make proof`.

| Guarantee | Result |
|---|---|
| One effect, retried after crashes | **1 side effect** from 1,000 crashed retries, with a crash at a random point each time |
| Crash safety | **0 duplicates** across 1,000 crash jobs |
| Approval safety | **0 destructive actions** ran without a valid, fresh approval |
| Release gate | a planted regression is caught; unchanged code raises no false alarm |

## Install

Python 3.11 or newer. The library has no third-party dependencies.

~~~bash
pip install agent-action-gateway
~~~

Optional extras: `[postgres]` for PostgreSQL, `[yaml]` for YAML route files.

## Quick start

Wrap your tool. Give the agent the wrapped version, never the raw function.

~~~python
from agent_action_gateway import session

def drop_table(table: str, intent_key: str = "") -> dict:
    # Your real code goes here. `intent_key` identifies this effect: pass it to
    # your provider as an idempotency key, so a retry cannot apply it twice.
    return {"dropped": table}

with session(environment="prod") as ctx:
    drop = ctx.tool(drop_table, action="db.drop_table", risk="destructive")

    drop(table="users")                       # blocked: needs approval

    approval = ctx.request_approval("db.drop_table", {"table": "users"})
    ctx.approve(approval.approval_id, "on-call engineer")
    drop(table="orders", approval_id=approval.approval_id)  # blocked: approval was for "users"
    drop(table="users", approval_id=approval.approval_id)   # allowed, and only once
~~~

To run a whole agent, pass the wrapped tools to it:

~~~python
result = ctx.run(agent, task, tools={"drop_table": drop})
result["status"]   # "blocked" if any action was refused
~~~

Safe defaults, with no configuration:

- an action with no declared risk is treated as **destructive**
- destructive actions need a **fresh approval bound to the exact arguments**
- a run is limited to **50 steps, 10 minutes and $2 of model and tool cost** (change it with `limits=FuseLimits(...)`)
- a session that is not `prod` cannot reach `prod`

## Keep the key out of the agent

The quick start protects every call that goes through a wrapped tool. To make
sure the agent **cannot read the key at all**, run the gateway as a separate
service. Your agent then talks to the gateway, and only the gateway holds the
real secret.

~~~bash
agent-gateway gateway      --config routes.json --db gateway.db     # HTTP gateway
agent-gateway egress-serve --config routes.json --port 8888         # outbound proxy
agent-gateway mcp-serve    --config routes.json --db gateway.db     # guarded tools over MCP
~~~

With the outbound proxy, the agent holds only a placeholder. The proxy swaps it
for the real secret, and only for the hosts you allow:

~~~json
{
  "credentials": [
    {
      "secret_name": "GITHUB_TOKEN",
      "secret_env": "file:/run/secrets/github_token",
      "allowed_hosts": ["api.github.com"],
      "header": "Authorization"
    }
  ]
}
~~~

This protection holds **only when the gateway runs across a boundary the agent
cannot cross**: a separate container, user or host. `deploy/` has Docker
Compose, Kubernetes and systemd setups. Check your setup from the agent's side:

~~~bash
agent-gateway gateway doctor --config routes.json   # check this host
make verify-boundary                                # try to escape, from the agent's position
~~~

See [docs/gateway-deployment.md](docs/gateway-deployment.md) for what each setup
guarantees, and what it does not.

## See and prove what happened

~~~bash
agent-gateway check --app myproject/agent.py   # is every tool wrapped?
agent-gateway check --db data/runtime.db       # did any recorded action skip the gateway?
agent-gateway wall  --db data/runtime.db       # group the failures you recorded
agent-gateway path  --db data/runtime.db       # how did each run get its result?
agent-gateway prune --db data/runtime.db --older-than 30 --dry-run
~~~

The dashboard shows one run from top to bottom: each step, the effects and
their receipts, approvals waiting, budget used, and gate history.

~~~bash
python -m agent_action_gateway.observability.dashboard --db data/runtime.db
~~~

It needs the access token it prints at start-up, and it runs no JavaScript.

### Release gate

Test a new agent version against your own cases before you ship it:

~~~bash
agent-gateway gate check --lane push --candidate-version v2 --candidate-file answers.json
~~~

Deterministic checks run first. An LLM judge is optional, and the gate can
measure how reliable that judge is before you trust it. A case marked
`catastrophic` fails the release on its own, whatever the average score is.
Exit codes: `0` pass, `1` fail, `2` uncertain.

## Storage

`--db` takes a file path for SQLite (one host) or a `postgresql://` URL for
PostgreSQL (several hosts or gateway replicas). Both run the same code, and a
test checks that they give the same results.

## What it does not do

- It does **not** decide whether the agent's plan is correct.
- It does **not** stop hallucinations.
- It does **not** replace human approval for high-impact actions; it enforces it.
- It cannot apply an effect exactly once if your provider has no idempotency
  key and no way to check whether the effect already happened.
- Run inside the agent's own process, it cannot keep the key away from the
  agent. That needs the separate gateway described above.

Deferred work and non-goals are listed in [ROADMAP.md](ROADMAP.md).

## Documentation

- [SDK guide](docs/sdk.md): the session, tools, approvals and limits in detail
- [Gateway deployment](docs/gateway-deployment.md): the key boundary and setups
- [Architecture](docs/architecture.md): how the package is organized
- [Receipt guarantees](docs/receipt-guarantees.md): what "once" means, exactly
- [Run path signals](docs/trajectory-signals.md): what `agent-gateway path` reports
- [Evaluation boundary](docs/evaluation-boundary.md): what the release gate decides
- [Security policy](SECURITY.md)

## Development

~~~bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
make verify     # lint, type check, full test suite
make proof      # reproduce every number in "Measured, not claimed"
~~~

## License

MIT
