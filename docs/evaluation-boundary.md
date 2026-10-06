# Evaluation Boundary

The evaluation path has two distinct mechanisms.

candidate output -> case check type -> deterministic judge or product-controlled LLM judge -> score

## Rules

1. Deterministic checks run first and do not call an LLM judge.
2. A rubric case requires an explicitly configured product-controlled judge.
3. The external agent's LLM is never used as the evaluation judge.
4. Safety enforcement and gate verdict logic remain deterministic.
5. Judge model and prompt metadata are recorded with the evaluation result.
6. A deterministic-check implementation change requires a judge-version bump so existing baselines cannot be silently compared.
7. Rubric cases will be added only when a deterministic check cannot answer the evaluation question.

The current golden-v1 set uses only deterministic checks. No LLM provider is required for the current gate.
