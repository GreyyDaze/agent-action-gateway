# Evaluation Boundary

The evaluation path has two distinct mechanisms.

candidate output -> case check type -> deterministic judge or product-controlled rubric judge -> decision -> gate

## Judge decision contract

Every judge returns:

- label: `pass` or `fail`
- score: number from 0 to 1
- confidence: number from 0 to 1
- rationale: non-empty explanation
- provider: non-secret provider identifier
- model: configured model identifier
- judge version
- prompt version
- latency and estimated cost when a hosted provider supplies them

## Rules

1. Deterministic checks run first and do not call an LLM judge.
2. A rubric case requires an explicitly configured product-controlled judge.
3. The external agent's LLM is never used as the evaluation judge.
4. Safety enforcement and gate verdict logic remain deterministic.
5. Judge provider, model, prompt, and judge version are explicit and recorded.
6. A deterministic-check implementation change requires a judge-version bump so existing baselines cannot be silently compared.
7. Rubric cases will be used only when deterministic checks cannot answer the evaluation question.
8. Missing judge configuration must produce uncertainty or a configuration error, never a fabricated PASS.
9. Evaluation/proof runs must use one fixed provider/model configuration. Provider fallback is not allowed inside proof comparisons.

The current golden-v1 set contains deterministic and rubric cases. The rubric cases require the explicit product-controlled judge boundary before a live hosted provider can be used.
