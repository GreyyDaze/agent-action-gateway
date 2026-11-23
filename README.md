# Agent Action Gateway

[![CI](https://github.com/GreyyDaze/agent-action-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/GreyyDaze/agent-action-gateway/actions/workflows/ci.yml) [![PyPI](https://img.shields.io/pypi/v/agent-action-gateway.svg)](https://pypi.org/project/agent-action-gateway/) [![Python](https://img.shields.io/pypi/pyversions/agent-action-gateway.svg)](https://pypi.org/project/agent-action-gateway/)

Prevention-first safety and evaluation layer for AI agents.

**Core rule:** AI proposes. Deterministic code verifies and enforces. Humans approve high-impact actions.

## The problem

An AI agent can change production. It needs a credential to do that.

The credential lives in the agent's process. So the agent holds standing
access, all the time, with nothing between it and production.

Every policy layer shipped today runs **inside the same process as the agent
it is meant to restrain**. Microsoft's own architecture documentation says so
and lists it as a known limitation:

> "The policy engine and the agents it governs run in the same Python process…
> Provides application-level governance, not OS kernel-level isolation."

If the agent is compromised, the policy is compromised with it.

## What this does

Put the credential somewhere the agent cannot reach:

~~~text
BEFORE     agent ──────────────────────────────►  production
                                                 [credential]

AFTER      agent ───►  safety layer ───►  production
                     [holds the credential,
                      grants one scoped job]
~~~

The agent still does its work. But if it is confused, wrong, or manipulated,
the most it can do is the one job it was given — and every attempt is
recorded.

## Who this is for

**The on-call engineer whose AI agent is allowed to change production.**

Not "enterprises." One person. They get paged, they own the risk, and they are
the last line of defence between a confused agent and an outage.

Their problem, stated plainly: they have to trust an agent they cannot verify,
using a credential they cannot control, with no record they can defend.

| They cannot… | Because… | So this provides |
|---|---|---|
| verify the reasoning | the model is a black box | judge + calibration |
| verify the exact change | they see "an action happened" | payload-bound approvals, dashboard |
| control what it does | the agent holds the credential | gateway, virtual keys |
| know it happened once | a crash loses that fact | receipts, effect claims |
| stop it at 3am | nobody is watching | fuses, failure wall |
| defend it afterwards | "I think it was fine" | traces, receipts, retention |
| trust it tomorrow | a PR can remove the wall | bypass detection, proofs |

## What you can measure

~~~text
Before:  unknown
After:   0 destructive actions executed without approval
         1 side effect across 1,000 crashed retries
         100% of attempts recorded, redacted, and defensible
~~~

Both numbers are reproducible:

~~~bash
make proof
# CRASH SAFETY: 0 dupes / 1000 crash jobs
# DUPLICATE SUPPRESSION: 1 side effect / 1000 crashed retries
~~~

The second number is the one that is usually claimed and not measured. One
effect, claimed a thousand times from a thousand different runs, with a crash
injected at a random point each time, must produce exactly one side effect.

## What this does not do

Stated up front because the difference matters:

- it does **not** decide whether the agent's diagnosis is *correct*
- it does **not** replace human approval for high-impact actions
- it does **not** prevent hallucination
- it is **not** an observability platform or a general MCP transport

It is a control layer for agent actions. Judging whether the action was a good
idea stays your engineer's job.

## Install

Python 3.11+:

~~~bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python -m pip install ".[dev]"
~~~

The package exposes the `agent-gateway` CLI.

## Adoption

Your agent obtains its tools from a session. It never receives the raw
functions, so there is nothing to bypass — for tools it obtained that way. Code
your own agent reaches directly is outside this guarantee, and
`agent-gateway check --app` is how you find it.

~~~python
from agent_action_gateway import session

with session() as ctx:
    refund = ctx.tool(refund_fn, action="refund", risk="destructive")
    lookup = ctx.tool(lookup_fn, action="lookup", risk="read")
    result = ctx.run(agent, task, tools={"refund": refund, "lookup": lookup})
~~~

Every call crosses the same pipeline, in this order:

~~~text
risk class → budgets → environment → approval → receipt → dispatch → result checks → trace
~~~

On by default, with no configuration:

- unknown actions are treated as **destructive**
- destructive actions need a **fresh approval bound to the exact payload**
- runs are bounded by **step, time and spend** limits
- **cross-environment** calls are refused
- the same side effect **cannot happen twice**, across runs, restarts or workers
- side effects get a **durable receipt**, so a crash cannot double-apply

### The same effect cannot happen twice

The guarantee is keyed on *what an action is*, not on which run attempted it.
A retry after a crash, a second worker, and the same request issued twice all
claim the same effect, and only the first claimant executes:

~~~python
patch = ctx.tool(
    patch_deployment,
    action="patch.deployment",
    risk="destructive",              # omit and it defaults to this anyway
    target="shop-api",
    target_environment="prod",
    required_fields=("namespace", "app", "memory_limit"),
)
~~~

Two knobs exist because identical arguments do not always mean an identical
effect:

~~~python
# Two tenants must not suppress each other.
ctx.tool(write, action="write.config", effect_scope="tenant-a")

# A body that may be edited between retries is not a new effect.
ctx.tool(issue, action="create_issue", identity_fields=("owner", "title"))
~~~

No per-API code is required. This used to be true — you needed a provider class
for every irreversible action, which is why most adopters had no duplicate
protection at all.

### See it run

~~~bash
python docs/examples/sre_agent.py
~~~

A Kubernetes incident agent reads a cluster, tries to patch production with no
approval, is refused, gets approved by a human, applies the patch — and then a
**restart** retries the same patch and does not apply it twice.

~~~text
agent said:     refused: destructive action requires approval
run status:     blocked
enforcement:    enforced
after approval: allowed
after restart:  allowed (DEDUPLICATED)

blocked evidence rows: 2
receipts: 2 for 2 distinct patches
~~~

Both example files are executed by CI, so they cannot drift from this page.

Full SDK boundary, limitations, and gate exit semantics: `docs/sdk.md`.

### Observation only: `run()`

~~~python
from agent_action_gateway import run

result = run(agent, task)
result["enforcement"]   # "observe"
~~~

`run()` records a trace. It does **not** authorize anything — tools it does not
know about are not enforced. Use `session()` when you want protection.

## Scoring how a run got there

`agent-gateway wall` groups what broke. `agent-gateway path` answers a different question:
did the run get there safely, or did it reach the right answer by trying
something it should not have first?

~~~bash
agent-gateway path --db data/runtime.db
~~~

It reports the signals defined in `docs/trajectory-signals.md` — a held
destructive action, a tripped budget, a no-progress loop, excessive hops, a
declared action that never happened. Verbosity is deliberately not a signal: a
long path is not automatically a bad one, and a score nobody can argue with is
worse than none.

It reports and never gates. Nothing about an existing verdict changes.

## Choosing a database

The `--db` flag takes a path or a `postgres://` URL:

~~~bash
agent-gateway path --db data/runtime.db                              # SQLite
agent-gateway path --db postgresql://user:pw@host/db --format json   # PostgreSQL
~~~

Both run the same code. `tests/test_backend_agreement.py` asserts that, running
each check twice and comparing the results, rather than claiming it.

PostgreSQL needs the `psycopg` package: `pip install 'agent-action-gateway[postgres]'`.

| | SQLite | PostgreSQL |
|---|---|---|
| Good for | one host, one writer | several hosts or gateway replicas |
| Setup | nothing | a database |
| Concurrency | single host | across hosts |

## Keeping the store small

Recording prompts makes `trace_events` grow quickly. `agent-gateway prune`
discards the payloads on your say-so and keeps the rows:

~~~bash
agent-gateway prune --db data/runtime.db --older-than 30 --dry-run
~~~

Nothing prunes on its own — a silent retention policy is a silent deletion of
evidence. Each row survives, marked `exchange_state=pruned`, so "discarded" stays
distinguishable from "never recorded". See `docs/sdk.md`.

## CLI

~~~bash
agent-gateway check --app myproject.agent:build     # is your agent actually wrapped?
agent-gateway run "Process the refund for Ava"       # run the bundled demo
agent-gateway gate check --lane push --candidate-version v1 --candidate-file answers.json
agent-gateway wall --db data/runtime.db             # group the failures you recorded
~~~

Every command prints a `SCOPE:` line first, saying what it is reporting on.
Each one takes your code, your cases, your database or your config as input.

### `agent-gateway check` — is your agent actually wrapped?

The library's own suites prove the enforcement path works. They cannot show
whether *your* application routes actions through it, so this command inspects
yours:

~~~bash
agent-gateway check --app myproject/agent.py     # static scan of your code
agent-gateway check --db data/runtime.db        # audit of actions you recorded
~~~

It reports tools wrapped with `ctx.tool`, direct provider imports, and provider
calls made outside a wrapper, each with a file and line. Exit code `0` when
everything passes, `1` otherwise, `--format json` for CI.

A database with nothing in it reports `INCONCLUSIVE`, not `PASS`: an action
that bypassed the layer leaves no trace, so an empty database cannot show that
nothing is unguarded.

### Reproducing this library's own verification

Framework self-verification is **not** a command in the installed CLI, because
it reports on this library rather than on you. Evidence about the library lives
in the CI badge above and in `docs/history/release-proof.md`. To regenerate it
from a source checkout:

~~~bash
make proof        # or: python -m agent_action_gateway.proofs.proof --jobs 1000
make chaos        # or: python -m agent_action_gateway.proofs.chaos --jobs 1000
~~~

This runs the deterministic crash-recovery proof and the remaining verification suites. It prints one labeled result per safety guarantee and exits non-zero on failure.

For individual verification suites:

~~~bash
python -m agent_action_gateway.chaos --jobs 1000
pytest -q tests/test_approvals.py
pytest -q tests/test_evaluation.py tests/test_gate.py
pytest -q tests/test_stop_rules.py
pytest -q tests/test_fuses.py
pytest -q tests/test_failure_wall.py tests/test_silent_failures.py tests/test_failure_promotion_drill.py tests/test_trace.py
~~~

Semantic-judge calibration needs a provider credential. The deterministic gate tests run without one; the hosted judge path is documented separately below.

For the dashboard:

~~~bash
python -m agent_action_gateway.observability.dashboard --db data/runtime.db --host 127.0.0.1 --port 8000
~~~

## What the system enforces

**Stops bad actions** — every one of these can refuse or bound a call:

- **Stop-and-ask:** missing or ambiguous required state can block before action.
- **Approval locks:** destructive actions require fresh approval bound to the exact payload.
- **Fuses:** step, time, spend, and loop limits stop unsafe continuation.
- **Effect claims:** the same side effect cannot execute twice, across runs, restarts, or workers.
- **Receipts:** side effects have durable lifecycle state and provider-aware idempotency handling.
- **Trace evidence:** important actions, approvals, failures, and suspicious results are retained with redaction.
- **Failure Wall:** failures are grouped deterministically by error type, failing step, and configuration fingerprint.

**Proves it worked:**

- **Evaluation gate:** deterministic checks run first; semantic judging is optional and returns PASS, FAIL, or UNCERTAIN.
- **Trajectory scoring:** reports whether a run reached its answer by a path it should not have taken. Reports, never gates.
- **Bypass detection:** `agent-gateway check --app` and `--db` find code and recorded runs that never crossed the layer.
- **Judge calibration:** tests whether your judge is any good, rather than trusting it.

The external agent and its model provider are not owned by this project.

### Bringing your own cases

The evaluation layer has no built-in knowledge of any domain. Cases are data:
a task, the expected answer, and how to compare them.

| Field | Meaning |
|---|---|
| `case_id` | unique name for the case |
| `task` | what to give the agent |
| `expected` | the correct answer, in whatever shape your tools return |
| `check_type` | `exact`, `field-equality`, `regex`, or `rubric` |
| `catastrophic` | if true, failing this case fails the build whatever the average |
| `rubric` | criteria used only when a hosted judge is configured |

A golden set needs at least 10 cases and at least one catastrophic case; there
is no upper limit. The bundled `golden-v1.json` is a worked example using
refunds, not a template you are expected to keep.

## SDK integration boundary

The SDK entry point is intentionally small:

~~~python
from agent_action_gateway import run

result = run(agent, task)
print(result["status"])
~~~

The `agent` callable is owned by your application. The safety layer receives the task, applies its deterministic runtime controls, records evidence, and evaluates the run. It does not own the agent's LLM provider or model loop.

The current SDK is a lightweight wrapper around the existing runtime, not a universal agent framework. See `docs/sdk.md` for the supported boundary and current limitations.

## Gateway: holding a credential your agent must not have

For upstreams you cannot wrap in-process — internal services, cluster APIs,
anything behind a login — the gateway is a separate service that holds the
upstream key and forwards the call. This is the part that survives a
compromised agent, and it is the reason the rest of the pipeline is worth
having.

~~~bash
agent-gateway gateway --config routes.json --db gateway.db
~~~

The property this buys is conditional, and the condition is the whole point:
**it holds only when the gateway runs as its own service, across a boundary your
agent cannot cross.** In your agent's own process, your agent reads the same
environment the key came from.

Two boundaries are required — your agent must not be able to *read* the key, and
must not be able to *reach* the provider. A vault is not one of them; it is
rotation and audit. `deploy/` ships a compose file, a systemd unit and
Kubernetes manifests for each tier, none of which contain an `agent` service,
because your agent is your code.

~~~bash
agent-gateway gateway doctor --config routes.json   # this host
make verify-boundary                        # from the agent's position
~~~

`make verify-boundary` exits non-zero when it cannot run. A check that did not
happen is not a pass. See `docs/gateway-deployment.md` for what each tier
guarantees and, just as importantly, what it does not.

## Scope and honest limits

The current release scope is explicit:

- the 8 deferred edge cases are recorded in `ROADMAP.md`;
- the 8 🟢 non-goal constraints from the Part 4 triage are recorded there;
- broader PRD constraints remain authoritative and are not removed by the roadmap.

This tool does **not** claim:

- exactly-once execution for providers without idempotency or reconciliation;
- complete model-hallucination prevention;
- automatic root-cause attribution for every production failure;
- automatic replacement of human approval for high-impact actions;
- ownership of the external agent's LLM calls;
- a large enterprise observability platform.

Deferred work is tracked in `ROADMAP.md`. The PRD and build plan remain the source of truth for requirements and development history.

## Dashboard

Start the self-hosted dashboard against the same runtime database:

~~~bash
python -m agent_action_gateway.observability.dashboard --db data/runtime.db --host 127.0.0.1 --port 8000
~~~

It shows one run top to bottom, in the order the operator needs it:

- **Header** — run id, status, and whether the run was *enforced* or merely
  *observed*. Those are different claims and the page does not blur them.
- **Timeline** — every step with its status, cost, latency, tokens, and the
  full input/output on expand.
- **Side-effect receipts** — one row per effect, with its state. A receipt
  left `pending` means the outcome is genuinely unknown, and the page says so
  at the top rather than burying it.
- **Approvals waiting** — the queue, with approve/deny.
- **Budget** — steps, spend, elapsed, fuse state.
- **Gate history** — verdict, score, threshold.

It is server-rendered HTML and CSS with **no JavaScript**. The
Content-Security-Policy sets `default-src 'none'` with no `script-src`, so
nothing can execute here. That is a deliberate security property, and it is
why every panel uses native `<details>` rather than a client-side filter.

The JSON state is also available at `/api/state`.

## Fresh-install proof

From a clean checkout:

~~~bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python -m pip install ".[dev]"
pytest -q
python -m agent_action_gateway --help
~~~

The release acceptance target is:

~~~text
fresh install -> full suite green -> all proof numbers reproducible
~~~

The final human acceptance step is a cold README walkthrough in a clean machine or sandbox. See `docs/history/release-proof.md`.

## Framework evidence

*The table below is evidence about **this library**, not about your integration.*

| Guarantee | Proof |
|---|---|
| **Adoption contract** | guarded tools are the only path; unapproved actions never execute |
| **Crash safety** | `0 dupes / 1,000 crash jobs` |
| **Duplicate suppression** | `1 side effect / 1,000 crashed retries` — one effect claimed by 1,000 different runs, crash injected at a random point each time, derived from the effect key rather than from a test double |
| **Approval safety** | `0 destructive executions without valid fresh approval` |
| **Regression gate** | calibration `6/6 = 100%`; good candidate `PASS, score=1.0000`; catastrophic candidate `FAIL, score=0.9667`; unchanged proof `10/10, false-fails=0`; cost `$0.0004` / `0.8840 min` |
| **Stop rules** | defined ambiguity traps caught, zero false stops on the legitimate suite |
| **Budgets and loops** | zero budget overruns in the concurrency proof; loop detection passes |
| **Failure wall** | planted silent-wrong cases flagged; deterministic groups separate equivalent and distinct signatures |

The exact proof output belongs to the verification commands. Do not treat a green unit test as a stronger claim than the proof it actually runs.

The complete recorded evidence is in `docs/history/release-proof.md`.

## Architecture

~~~text
USER REQUEST
    |
    v
EXTERNAL AI AGENT
    |
    | proposed action
    v
SAFETY LAYER
    |-- stop rules
    |-- fuses / budgets
    |-- risk + approval locks
    |-- effect claim  ─── same action, same key, anywhere
    |
    +---- BLOCK / ASK / DEDUPLICATED
    |
    +---- ALLOW
            |
            v
   GATEWAY  ──── holds the credential the agent must not have
            |
            v
       TOOL / PROVIDER
            |
            v
       RECEIPT + TRACE
            |
            v
       DASHBOARD
            |
            v
      EVALUATION / GATE
            |
       PASS / FAIL / UNCERTAIN
~~~

The effect claim is the load-bearing step. It is what makes the rest mean
something: a refusal is only worth having if the agent could not have gone
around it, and a retry is only safe if the system can tell it apart from the
first attempt.

Deterministic enforcement stays in the runtime. The optional LLM judge is
confined to evaluation where deterministic checks cannot grade open-ended
meaning.
