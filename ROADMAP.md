# Roadmap and Scope Boundaries

This document records the work intentionally deferred from the current v1 scope and the explicit non-goals. It does not add requirements to the runtime.

The source of truth remains `docs/PRD.md`, `docs/build-plan.md`, and the initial triage in `docs/problem-breakdown.md`.

## Deferred work: 8 items

These are the eight 🟡 items in the current Part 4 triage.

| ID | Deferred item | Current v1 behavior | Revisit condition |
|---|---|---|---|
| E1.4 | Semantic matching beyond name mapping | v1 uses a name-mapping table | Revisit when public validation shows semantic tool/field mismatches that the mapping table cannot safely cover |
| E2.7 | Independent nested-agent budgets and attribution | nested actions use the parent run's tree-wide budget | Revisit after Phase 8, or earlier if multi-agent integration needs per-child limits/attribution |
| E3.11 | Resource-level locks across runs | locks are scoped to a run | Revisit when concurrent runs need protection for the same real-world resource |
| E4.6 | Long-range causal edges | linear traces plus step annotations | Revisit when failure investigation needs causal links across distant steps |
| E4.8 | Automatic failure ownership/routing | ownership can remain `unknown`; no automatic assignment | Revisit when public validation or production use requires automatic routing |
| E5.4 | Provider-model change attribution | gate can report a drop with cause unknown | Revisit when provider/model drift needs automatic attribution |
| E5.5 | Automatic per-change canary/bisect | v1 blocks the batch and uses manual bisect | Revisit when deploys need automatic isolation of one change from a batch |
| E5.6 | Automatic coverage-gap filling | gate reports coverage against the task taxonomy | Revisit when coverage gaps need automatic discovery/filling |

**Recorded scope date:** these items are preserved from the current problem-breakdown triage. E2.7 has an explicit 2026-10-06 disposition; the other items inherit the dated triage document rather than inventing separate decision dates.

### Revisit rule

Deferred work must not be pulled into v1 by convenience. A concrete trigger must appear in public validation, real adoption, or a safety invariant that the current implementation cannot satisfy. Otherwise the item stays deferred.

## Non-goals: 8 explicit constraints

These are the eight 🟢 items in the current Part 4 triage. They are constraints or explicit v1 exclusions, not unfinished features.

| ID | Non-goal | v1 position |
|---|---|---|
| E1.7 | Model self-confidence as a safety signal | Never gate safety on self-reported model confidence; use observable evidence |
| E2.4 | Treating per-step success as independent probability | The compounding math is illustrative only and does not drive runtime design |
| E2.9 | Using fuses to detect progress toward the wrong goal | Wrong-goal detection belongs to intent checks and evaluation, not the fuse |
| E4.5 | Automatic attribution of provider-side causes | Store provider response/version evidence when available; attribution is not automatic |
| E4.7 | Treating successful replay as proof that the original failure was false | The original trace remains evidence even when replay is green |
| E4.9 | Treating one customer's configuration failure as a global failure | Configuration fingerprint is part of the Failure Wall grouping key |
| E5.7 | Optimizing the gate around a single judge score | Use judge diversification and periodic human spot checks |
| E5.9 | Putting latency/cost quality regressions into the v1 quality gate | Keep a separate metric lane for later |

## Scope honesty

The broader PRD contains additional non-goal language and safety constraints. This roadmap does not delete those requirements. The eight-item count above is specifically the 🟢 Part 4 triage contract used by Phase 7.

The eight deferred items and eight non-goals therefore remain traceable to the original edge-case taxonomy instead of becoming an invented feature backlog.
