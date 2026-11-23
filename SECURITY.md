# Security Policy

## Reporting a vulnerability

Please report security issues privately rather than opening a public issue.

Use GitHub's **Security → Report a vulnerability** on this repository, or email
the maintainer. Include:

- what the issue is and which component is affected
- a minimal reproduction, ideally as a test
- the impact you believe it has

You can expect an acknowledgement within a few days and a fix or a plan
within a reasonable time. We will credit you in the advisory unless you would
rather stay anonymous.

Please give us a reasonable window to ship a fix before disclosing publicly.

## What this project defends

This library exists to stop irreversible side effects from happening without
approval. Its own attack surface is therefore mostly in the places where it
holds authority:

- **Approval endpoints.** The dashboard can approve destructive actions, so it
  requires a per-process token on every route, plus CSRF and origin checks. It
  binds to `127.0.0.1` by default and refuses a non-loopback bind without an
  explicit token.
- **Credential custody.** The gateway reads upstream keys from its own
  environment and never returns them to a caller or writes them to a trace.
- **Secret and PII handling.** Traces are redacted before persistence: keys,
  tokens, payment card numbers (Luhn-validated), IBANs, SSNs and contact
  details. Identifiers such as run ids and idempotency keys are deliberately
  preserved, because destroying them would break the evidence the traces exist
  to provide.
- **Approval binding.** An approval is bound to a payload digest and consumed on
  use. A tampered payload is rejected, and a replayed approval is refused.

## Known limitations

Stated plainly, because a security tool that overstates itself is worse than
one that does not exist:

- **Enforcement is opt-in by construction.** A tool obtained outside a
  `safety.session()` is not enforced. The agent never receives the raw
  function, so there is nothing to bypass — but that only holds for tools handed
  over by the session.
- **`run()` is observation only.** It records a trace; it does not authorize.
  Use `session()` when you want enforcement. `run()` now warns on stderr the
  first time it is called in a process, and every trace it writes records
  `enforcement="observe"`, so `agent-gateway check --db` can report an unprotected
  run after the fact.
- **An audit cannot see an action that never reached the layer.** If an agent
  calls a provider directly, no trace is written and there is nothing to find.
  `agent-gateway check --app` inspects the code for this; `agent-gateway check --db` cannot,
  and reports `INCONCLUSIVE` rather than a pass when a database has no traces.
  Detecting bypasses is static analysis over a fixed set of provider clients and
  direct network calls, so an unrecognised shape may pass unnoticed.
- **The library cannot constrain its own process.** Code running in the same
  interpreter can reach the database directly. Use the gateway when the caller
  must not hold the upstream credential.
- **Credential custody depends on the deployment, not on the code.** The
  gateway holds the upstream key so the agent never receives it, but that only
  holds while the gateway runs as its own service across a boundary the agent
  cannot cross. In the agent's own process the agent can read the same
  environment the key came from, so there is no custody. Two boundaries are
  needed: the agent must not be able to *read* the key, and must not be able to
  *reach* the provider. A vault supplies neither by itself — it is lifecycle
  and rotation, not a boundary. `docs/gateway-deployment.md` gives the tiers,
  `agent-gateway gateway doctor` checks this host, and `make verify-boundary` probes
  the topology from the agent's own position.
- **Prompts and completions are persisted when a caller records them.** They go
  through the same recursive redaction as every other field, so keys,
  bearer tokens and emails are replaced before write. Anything redaction does not
  recognise — names, free text, an internal identifier — is stored as given.
  There is no automatic pruning; the trace table grows faster once exchanges are
  recorded, so a retention window belongs in your deployment.
- **Two deployment failures cannot be detected from here.** If an action never
  reached the layer, it wrote no trace, so no audit can find it — only
  `agent-gateway check --app` can, statically. And whether the agent's network can
  reach a provider is a fact about the adopter's network, which the gateway
  process cannot observe without inventing evidence.
- **No transport encryption is enforced.** The gateway forwards over whatever
  scheme its route declares; use `https` upstreams in production.
- **Approvals are not bound to a session.** An approval is bound to its
  payload and single-use, not to the run that requested it, so an approval
  obtained in one session can be spent by another. Binding it would break the
  legitimate "approve ahead of time" workflow, so the trade is documented
  rather than hidden.
- **A failed action still consumes its approval.** The approval is consumed once
  policy passes and before the tool runs, because we cannot always tell whether
  a partial effect occurred. The operator must re-approve the retry. This is
  fail-closed on purpose; relaxing it would reopen the replay race the
  single-use rule exists to close.
- **A tool that raises propagates its own exception.** The guard does not mask
  it, so a crash inside an adopter's function surfaces as a failed run rather
  than a silent block.
- **Beta.** The version has not been independently audited. What stands in its
  place is automated: seven labelled guarantee suites (`make proof`), a static
  check of the adopter's own wiring (`agent-gateway check`), and CI across Python
  3.11–3.13. None of that is an independent review of the design, and it should
  not be read as one.
