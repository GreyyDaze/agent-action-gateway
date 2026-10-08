# SDK Integration

The SDK is the small boundary between an existing agent and the safety layer.

## 3-line adoption

```python
from safety_layer import run

result = run(agent, task)
print(result["status"])
```

The application still owns `agent`, its model, its provider, and its model loop.

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

`run(agent, task)` enters the existing runtime path and returns the run result.

The runtime is responsible for the controls already implemented in the project:

- stop-and-ask rules;
- destructive-action approval;
- receipt and idempotency handling;
- step/time/spend/loop controls;
- trace evidence and suspicious-result flags;
- evaluation/gate evidence where configured.

The exact action boundary remains the application's integration responsibility. The SDK wrapper is not a universal agent framework.

## Result status

Runtime status and evaluation verdict are different concepts.

- Runtime status describes what happened during the run.
- Gate verdict describes whether an evaluation result is trustworthy and acceptable.

Gate verdicts are:

| Verdict | Meaning | CLI exit code |
|---|---|---:|
| PASS | evidence supports the candidate | 0 |
| FAIL | a confirmed regression was detected | 1 |
| UNCERTAIN | the gate could not establish a trustworthy verdict | 2 |

`UNCERTAIN` is intentionally non-zero for CI. An untrustworthy evaluation must not silently pass. It is also **not** a false regression and must not be added to the false-alarm ledger as a FAIL.

## Provider boundary

The external agent may use any model provider. Its provider is outside this project's control.

The evaluation path may use the supported hosted judge providers defined by the PRD. Provider identity and model metadata are recorded without recording credentials.

Evaluation/proof runs are pinned to their configured provider/model. They must not silently change provider during a comparison.

Provider outages, authentication errors, and rate limits must surface as evaluation availability problems, not as safety-policy bypasses.

## Credentials

Provider API keys are configuration, not trace data.

Keys may be supplied through environment variables or local developer secret configuration. They must never be written to:

- traces;
- receipts;
- regression cases;
- evaluation artifacts;
- normal runtime records.

## Rule reference

The SDK sits at the external-agent boundary. The deterministic rules remain defined by the project specification:

- R-01: missing required state -> stop;
- R-02: ambiguous critical input -> ask/queue;
- R-03: suspicious empty lookup -> cross-check/flag;
- R-04: cross-environment action -> block;
- R-05: exhausted budget -> stop before dispatch;
- R-06: detected loop -> stop;
- R-07: destructive action without approval -> block;
- R-08: expired approval -> block;
- R-09: changed approved payload -> block;
- R-10: safety service unavailable for write -> fail-closed;
- R-11: uncertain side effect -> resolve before retry;
- R-12: duplicate intent -> dedupe according to provider semantics;
- R-13: required evidence missing -> degraded/uncertain;
- R-14: catastrophic regression case -> FAIL;
- R-15: incompatible judge/baseline -> UNCERTAIN.

See `docs/problem-breakdown.md` for the edge cases and `docs/PRD.md` for the normative product contract.

## Current limitations

The SDK does not claim:

- universal hallucination prevention;
- exactly-once execution when the external provider cannot support idempotency or reconciliation;
- automatic root-cause attribution for every production failure;
- replacement of human approval for high-impact actions;
- control over the external agent's LLM calls;
- a universal agent framework.

These are scope boundaries, not hidden implementation gaps.

## Verification

From outside the repository, after installing the package:

```bash
python -c 'from safety_layer import run; print(run(lambda task: f"handled: {task}", "smoke"))'
safety --help
safety proof --jobs 1000
```

For the full acceptance workflow, use the Phase 7 proof document.
