# Architecture (current)

This is the source of truth for the package layout. Older plans and handoffs
live in `docs/history/` and are kept for provenance only.

## Layers and dependency direction

Dependencies point **downward only**:

```
  cli / integrations / observability
             |
             v
        engine + runtime
             |
             v
   policy + guards + credential
             |
             v
       audit + storage        (leaf — imports nothing above)
```

`policy/` is pure decision logic (no I/O). `engine/` is the one enforcement
pipeline, called by the wrapper, HTTP and MCP doors. `credential/` owns secret
custody and egress. `integrations/` are thin adapters. `storage/` is the leaf.

## Package map

| Package | Job |
|---|---|
| `policy/` | pure rules: risk, approval, budgets, stop rules, hashes |
| `engine/` | `enforce()` — the single checking pipeline |
| `guards/` | redaction, capture policy, honest status |
| `runtime/` | session, orchestrator, records |
| `credential/` | placeholder vault, resolvers, egress, proxy, TLS |
| `integrations/` | gateway, MCP, in-process adapters (old `providers/`) |
| `audit/` | receipts, failure wall, lifecycle stores |
| `eval/` | golden set, judges, verdict engine, regression gate, online |
| `storage/` | SQLite/Postgres persistence (leaf) |
| `observability/` | dashboard, wiring check |
| `config/` | defaults and the single config loader |
| `proofs/` | verification scripts, not shipped in the wheel |

## Compatibility

Old import paths (`core/`, `evidence/`, `interface/`, `providers/`,
`evaluation/`, and the old storage submodules) remain as thin re-export shims.
Existing code and tests keep working; new code imports from the canonical
packages above. The console scripts (`agent-gateway`, `gate`) point at the new paths.

## Configuration

The library ships **example config templates** only (`deploy/routes.example.json`,
`deploy/routes.credentials.example.json`). An adopting engineer writes their own
config in their own project — their hosts, keys, risks and limits — and the
library reads it. No live policy data is owned by this repo.

## Testing

Test lanes are assigned by `tests/conftest.py` (no per-file edits):

```bash
make test-unit          # pure, fast
make test-integration   # DB / sockets / servers
make test-evals         # quality suites
make verify             # lint + mypy + full suite
```

The safety core is additionally checked by **mutation** with `mutmut` (`make mutation`).
mutmut automatically mutates all safety code (`policy/`, `engine/`, `audit/`,
`credential/`, `guards/`) and reports a score plus any surviving mutants — a
behavior change no test detected, which coverage cannot see. Config in
`pyproject.toml` under `[tool.mutmut]`. It runs nightly in CI
(`.github/workflows/nightly.yml`), not on every commit. mutmut is dev-only; the
running product stays stdlib-only.

```bash
python -m pytest -q        # full suite
python -m ruff check .
python -m mypy
make proof
```
