# Agent Safety Layer

Prevention-first safety and evaluation layer for AI agents.

**Core rule:** AI proposes. Deterministic code verifies and enforces. Humans approve high-impact actions.

## Install

Python 3.11+:

~~~bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python -m pip install ".[dev]"
~~~

The package exposes the `safety` CLI.

## Adoption

Your agent obtains its tools from a session. It never receives the raw
functions, so there is nothing to bypass.

~~~python
from safety_layer import session

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
- side effects get a **durable receipt**, so a crash cannot double-charge

Run `python docs/examples/quickstart.py` to watch an unapproved refund get
refused, then permitted once approved. That same file is executed by CI, so it
cannot drift from this page.

Full SDK boundary, limitations, and gate exit semantics: `docs/sdk.md`.

### Observation only: `run()`

~~~python
from safety_layer import run

result = run(agent, task)
result["enforcement"]   # "observe"
~~~

`run()` records a trace. It does **not** authorize anything — tools it does not
know about are not enforced. Use `session()` when you want protection.

## CLI

~~~bash
safety run "Process the refund for Ava"
safety chaos --jobs 1000
safety gate check --lane push --candidate-version v1 --candidate-file tests/fixtures/evaluation-good-candidate.json
safety wall --db data/runtime.db
~~~

The commands are thin interfaces over the existing implementation. Safety policy is not duplicated in the CLI.

### Reproduce the verification proofs

From the repository root after installation:

~~~bash
safety proof --jobs 1000
~~~

This runs the deterministic crash-recovery proof and the remaining verification suites. It prints one labeled result per safety guarantee and exits non-zero on failure.

For individual verification suites:

~~~bash
python -m safety_layer.chaos --jobs 1000
pytest -q tests/test_approvals.py
pytest -q tests/test_evaluation.py tests/test_gate.py
pytest -q tests/test_stop_rules.py
pytest -q tests/test_fuses.py
pytest -q tests/test_failure_wall.py tests/test_silent_failures.py tests/test_failure_promotion_drill.py tests/test_trace.py
~~~

Semantic-judge calibration needs a provider credential. The deterministic gate tests run without one; the hosted judge path is documented separately below.

For the dashboard:

~~~bash
python -m safety_layer.interface.dashboard --db data/runtime.db --host 127.0.0.1 --port 8000
~~~

## What the system enforces

- **Stop-and-ask:** missing or ambiguous required state can block before action.
- **Approval locks:** destructive actions require fresh approval bound to the exact payload.
- **Fuses:** step, time, spend, and loop limits stop unsafe continuation.
- **Receipts:** side effects have durable lifecycle state and provider-aware idempotency handling.
- **Trace evidence:** important actions, approvals, failures, and suspicious results are retained with redaction.
- **Failure Wall:** failures are grouped deterministically by error type, failing step, and configuration fingerprint.
- **Evaluation gate:** deterministic checks run first; semantic judging is optional and returns PASS, FAIL, or UNCERTAIN.

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

## Verification results

| Guarantee | Proof |
|---|---|
| **Crash safety** | `0 dupes / 1,000 crash jobs` |
| **Approval safety** | `0 destructive executions without valid fresh approval` |
| **Regression gate** | calibration `6/6 = 100%`; good candidate `PASS, score=1.0000`; catastrophic candidate `FAIL, score=0.9667`; unchanged proof `10/10, false-fails=0`; cost `$0.0004` / `0.8840 min` |
| **Stop rules** | defined ambiguity traps caught, zero false stops on the legitimate suite |
| **Budgets and loops** | zero budget overruns in the concurrency proof; loop detection passes |
| **Failure wall** | planted silent-wrong cases flagged; deterministic groups separate equivalent and distinct signatures |

The exact proof output belongs to the verification commands. Do not treat a green unit test as a stronger claim than the proof it actually runs.

The complete recorded evidence is in `docs/history/release-proof.md`.

## SDK integration boundary

The SDK entry point is intentionally small:

~~~python
from safety_layer import run

result = run(agent, task)
print(result["status"])
~~~

The `agent` callable is owned by your application. The safety layer receives the task, applies its deterministic runtime controls, records evidence, and evaluates the run. It does not own the agent's LLM provider or model loop.

The current SDK is a lightweight wrapper around the existing runtime, not a universal agent framework. See `docs/sdk.md` for the supported boundary and current limitations.

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

Start the self-hosted dashboard against the same SQLite runtime database:

~~~bash
python -m safety_layer.interface.dashboard --db data/runtime.db --host 127.0.0.1 --port 8000
~~~

The dashboard currently exposes:
- persisted trace events and evidence per run;
- pending approval queue with approve/deny actions;
- gate verdict history;
- persisted fuse counters when a run supplies a fuse.

The JSON state is also available at `/api/state`.

## Fresh-install proof

From a clean checkout:

~~~bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python -m pip install ".[dev]"
pytest -q
python -m safety_layer --help
~~~

The release acceptance target is:

~~~text
fresh install -> full suite green -> all proof numbers reproducible
~~~

The final human acceptance step is a cold README walkthrough in a clean machine or sandbox. See `docs/history/release-proof.md`.

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
    |-- idempotency / receipts
    |
    +---- BLOCK / ASK
    |
    +---- ALLOW
            |
            v
       TOOL / PROVIDER
            |
            v
       RECEIPT + TRACE
            |
            v
      EVALUATION / GATE
            |
       PASS / FAIL / UNCERTAIN
            |
            v
       REGRESSION CASE
~~~

Deterministic enforcement stays in the runtime. The optional LLM judge is confined to evaluation where deterministic checks cannot grade open-ended meaning.
