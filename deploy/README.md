# deploy/

Reference deployments for the gateway. Read `../docs/gateway-deployment.md`
first — this directory is the topology, that document is what the topology buys.

| File | Tier |
|---|---|
| `docker-compose.yml` | 2 — separate containers, two networks (recommended self-host) |
| `systemd/safety-gateway.service` | 1 — separate OS user (minimum) |
| `k8s/gateway.yaml` | 3 — separate host, egress control, workload identity |
| `routes.example.json` | the route table both use |
| `verify_boundary.py` | the probe that tests the topology |

## There is no `agent` service here, on purpose

You already have an agent. Shipping a container named `agent` would imply we
provide one, and it would prove only that our compose file is written correctly
— we strip its key, block its egress, then announce it cannot reach a provider.
That is a test of our file, not of your agent.

Your agent's side is a URL and a key:

```python
client = SafetyClient(base_url="http://gateway:8080", key=VIRTUAL_KEY)
```

## Try it

```bash
printf 'sk_live_replace_me' > secrets/stripe_key && chmod 600 secrets/stripe_key
export SAFETY_MASTER_KEY="$(python -c 'import secrets;print(secrets.token_urlsafe(32))')"

docker compose up -d gateway
make verify-boundary
```

The probe attaches to `agent_net` — the network your agent occupies — and tries
four escapes: reach a provider directly, read the secret, call the gateway with
no key, call it with a scoped key. It uses only the standard library, so our own
code cannot satisfy it.

Expected on a laptop: **check A fails.** Your machine has unrestricted egress,
so a bypass would succeed there. That failure is correct and is the finding.

```bash
safety gateway --config routes.example.json --db /tmp/g.db \
    issue-key --name billing-agent --ttl 1h --routes /charge
SAFETY_MASTER_KEY=... docker compose run --rm --no-deps \
    --network agent_net -v "$PWD/verify_boundary.py:/probe.py:ro" \
    -e SAFETY_PROBE_KEY=sk-virtual-... \
    python:3.12-slim python /probe.py --gateway http://gateway:8080
```

## Secrets

`routes.example.json` uses `secret_env: "file:/run/secrets/stripe_key"` rather
than a bare variable name, because a file can have an owner and a mode. The
gateway refuses to start if that file is group- or world-readable, or owned by
anyone but the gateway's user.

JSON, not YAML, because the library has no third-party dependencies and should
stay that way. YAML works with `pip install 'agent-safety-eval-layer[yaml]'`.