# deploy/

Reference deployments for the gateway and the MCP proxy. Read
`../docs/gateway-deployment.md` first — this directory is the topology, that
document is what the topology buys.

| File | What it is |
|---|---|
| `docker-compose.yml` | the gateway alone: separate containers, two networks (recommended self-host for HTTP APIs) |
| `docker-compose.proxy.yml` | the MCP proxy as its own service, the gateway behind it and the dashboard beside it ([below](#the-mcp-proxy)) |
| `systemd/agent-action-gateway.service` | the gateway as a separate OS user (minimum; not tested on Linux) |
| `k8s/gateway.yaml` | the gateway on a separate host, with egress control (not tested on a cluster) |
| `routes.example.json` | the route table for `docker-compose.yml` |
| `routes.credentials.example.json` | the route table for `docker-compose.proxy.yml` (the gateway holds the key, the proxy asks for approval) |
| `servers.proxy.example.json` | the proxy's server list for `docker-compose.proxy.yml` |
| `verify_boundary.py` | the probe that tests either setup from the agent's side |

One image (`Dockerfile.gateway`) runs every service; the command picks gateway,
proxy or dashboard.

## There is no `agent` service here, on purpose

You already have an agent. Shipping a container named `agent` would imply we
provide one, and it would prove only that our compose file is written correctly
— we strip its key, block its egress, then announce it cannot reach a provider.
That is a test of our file, not of your agent.

Your agent's side is a URL and a key. There is no client library to install:

```bash
curl -X POST http://gateway:8080/deploy \
  -H "Authorization: Bearer $VIRTUAL_KEY" -d '{"ref": "v2"}'
```

An agent that uses MCP tools connects to the [MCP proxy](../docs/sdk.md#mcp-proxy)
instead, and the proxy forwards to the gateway's `/mcp`.

## Try it

```bash
printf 'replace_me' > secrets/github_token && chmod 600 secrets/github_token
export AGENT_GATEWAY_MASTER_KEY="$(python -c 'import secrets;print(secrets.token_urlsafe(32))')"

docker compose up -d gateway
make verify-boundary
```

The probe attaches to `agent_net` — the network your agent occupies — and tries
four escapes: reach a provider directly, read the secret, call the gateway with
no key, call it with a scoped key. It uses only the standard library, so our own
code cannot satisfy it.

Expected on a laptop: **check A fails.** Your machine has unrestricted egress,
so a bypass would succeed there. That failure is correct and is the finding.

Issue the key against the gateway's own database — the same one the gateway
reads — and hand it to the probe:

```bash
export AGENT_GATEWAY_MASTER_KEY=...            # must match the running gateway's
KEY=$(docker compose exec -T -e AGENT_GATEWAY_MASTER_KEY gateway \
        agent-gateway gateway --config /etc/agent-action-gateway/routes.json \
        --db /var/lib/agent-action-gateway/gateway.db \
        issue-key --name deploy-agent --ttl 1h --routes /deploy \
      | sed -n 's/^Virtual key issued: //p')

AGENT_GATEWAY_PROBE_KEY=$KEY make verify-boundary
```

`docker compose exec` needs the key against the gateway's database, not a local
one, or the running gateway will never see it.

## Does your agent need internet?

Usually yes. Plain Compose cannot allow one host and block the rest, so there
are two topologies:

```bash
# Default: agent has no egress at all. Fails closed.
docker compose up -d gateway

# Override: agent can reach the internet, and therefore a provider too.
docker compose -f docker-compose.yml -f docker-compose.egress.yml up -d
```

The override exists because the common case needs it. It says plainly what it
gives up, and `make verify-boundary` will fail its egress check when it is in
use — which is correct, and is the point.

## The MCP proxy

`docker-compose.proxy.yml` runs the proxy as its own service, so an agent with a
terminal cannot change its config or approve itself through its database:

| Network | Who is on it |
|---|---|
| `agent_net` (internal) | your agent and the proxy, nothing else |
| `tools_net` (internal) | the proxy and the systems its tools change: the gateway, your own MCP servers |
| `upstream_net` | the gateway, to reach the real API |
| `review_net` | the dashboard, published on `127.0.0.1:8765` only |

The steps to bring it up are at the top of the file: three tokens, start the
gateway, issue the proxy a gateway key, start the proxy and the dashboard. Then:

```bash
make verify-proxy-boundary
```

From `agent_net`, it checks that there is no route to a provider, that the proxy
refuses a caller with no token and accepts the agent's token, that there is no
route to the gateway (the agent cannot skip the proxy), and that the proxy's
config and database cannot be read.

Your agent uses `http://proxy:8090/mcp` with `Authorization: Bearer
$AGENT_GATEWAY_PROXY_TOKEN`; an app that only starts commands uses
`agent-gateway mcp-connect`. Approvals are given at
`http://127.0.0.1:8765/?token=$AGENT_GATEWAY_DASHBOARD_TOKEN`. To add your own
MCP servers, list them in `servers.proxy.example.json` and put them on
`tools_net`, never on `agent_net`.

## Secrets

`routes.example.json` uses `secret_env: "file:/run/secrets/github_token"` rather
than a bare variable name, because a file can have an owner and a mode. The
gateway refuses to start if that file is group- or world-readable, or owned by
anyone but the gateway's user.

JSON, not YAML, because the library has no third-party dependencies and should
stay that way. YAML works with `pip install 'agent-action-gateway[yaml]'`.