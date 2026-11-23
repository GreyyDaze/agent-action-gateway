# Roadmap and Scope Boundaries

This document records work deliberately deferred from the current release and
the explicit non-goals. It does not add requirements to the runtime.

## Deferred work

| Deferred item | Current behavior | Revisit when |
|---|---|---|
| Semantic matching beyond name mapping | a name-mapping table | real integrations show tool or field mismatches the table cannot safely cover |
| Independent budgets and attribution for nested agents | nested actions share the parent run's tree-wide budget | multi-agent integrations need per-child limits or attribution |
| Resource-level locks across runs | locks are scoped to a run | concurrent runs need protection for the same real-world resource |
| Long-range causal links in traces | linear traces plus step annotations | failure investigation needs links between distant steps |
| Automatic failure ownership and routing | ownership can remain `unknown` | production use needs automatic routing |
| Attributing a quality drop to a provider or model change | the gate reports the drop with cause unknown | provider or model drift needs automatic attribution |
| Automatic per-change canary or bisect | the gate blocks the batch; bisect is manual | deploys need one change isolated from a batch automatically |
| Automatic coverage-gap filling | the gate reports coverage against the task taxonomy | coverage gaps need automatic discovery |

### Revisit rule

Deferred work is not pulled in for convenience. It needs a concrete trigger:
real adoption, a validation result, or a safety invariant the current
implementation cannot satisfy.

## Non-goals

These are constraints, not unfinished features.

| Non-goal | Position |
|---|---|
| Model self-confidence as a safety signal | never gate on self-reported confidence; use observable evidence |
| Treating per-step success as independent probability | compounding-error math is illustrative only and does not drive the design |
| Using budgets to detect progress toward the wrong goal | wrong-goal detection belongs to intent checks and evaluation |
| Automatic attribution of provider-side causes | provider responses and versions are stored when available; attribution is not automatic |
| Treating a successful replay as proof the original failure was false | the original trace remains evidence even when replay is green |
| Treating one configuration's failure as a global failure | the configuration fingerprint is part of the failure grouping key |
| Optimizing the gate around a single judge score | diversify judges and keep periodic human spot checks |
| Putting latency or cost regressions in the quality gate | they belong in a separate metric lane |
