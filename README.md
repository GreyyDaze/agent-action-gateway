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

## 3-line adoption

Wrap an existing callable without rewriting the agent:

~~~python
from safety_layer import run

result = run(agent, task)
print(result["status"])
~~~

The wrapper records the run through the existing runtime, trace, receipt, and evaluation path. The external agent remains outside the safety layer.

## CLI

~~~bash
safety run "Process the refund for Ava"
safety chaos --jobs 1000
safety gate check --lane push --candidate-version v1 --candidate-file tests/fixtures/phase3-good-candidate.json
safety wall --db data/runtime.db
~~~

The commands are thin interfaces over the existing implementation. Safety policy is not duplicated in the CLI.

For the dashboard:

~~~bash
python -m safety_layer.dashboard --db data/runtime.db --host 127.0.0.1 --port 8000
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

## Proofs from Phases 1–6

Run the phase-specific tests to reproduce the repository's proof evidence:

| Phase | Proof |
|---|---|
| P1 | `0 dupes / 1,000 crash jobs` |
| P2 | `0 destructive executions without valid fresh approval` |
| P3 | injected regression is red; unchanged-run false-alarm proof |
| P4 | defined ambiguity traps caught with zero false stops on the legitimate suite |
| P5 | zero budget overruns in the concurrency proof; loop detection passes |
| P6 | planted silent-wrong cases flagged; deterministic failure groups separate equivalent and distinct signatures |

The exact proof output belongs to the phase test/proof commands. Do not treat a green unit test as a stronger claim than the proof it actually runs.

## Scope and honest limits

This tool does **not** claim:

- exactly-once execution for providers without idempotency or reconciliation;
- complete model-hallucination prevention;
- automatic root-cause attribution for every production failure;
- automatic replacement of human approval for high-impact actions;
- ownership of the external agent's LLM calls;
- a large enterprise observability platform.

Deferred work remains in `docs/PRD.md` and `docs/build-plan.md`.

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

The Phase 7 acceptance target is:

~~~text
fresh install -> full suite green -> phase proof numbers reproducible
~~~

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
