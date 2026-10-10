# Deploying the gateway

The gateway holds your upstream credentials so your agent never sees them. That
only buys something under one condition, and stating the condition is the point
of this page:

> **The gateway must run as its own service, across a boundary your agent
> cannot cross.** If it runs inside your agent's process, your agent can read
> the same environment the key came from, and there is no custody to speak of.

Nothing in a Python library can create that boundary. Your operating system
does. What this project can do is refuse the deployments that have no boundary,
ship a reference one, and tell you whether it took.

## What the gateway checks, and what it cannot

| Check | Enforcement |
|---|---|
| Secret file is mode 0600 | **Enforced.** The gateway refuses to read it otherwise. |
| Secret file is owned by the gateway's user | **Enforced.** Refused otherwise. |
| Launched as root | **Enforced.** Drops to a service account first. |
| Caller UID matches the gateway's (Linux, unix socket) | **Enforced.** Rejected by the kernel's `SO_PEERCRED`. |
| Embedded in an agent's script | **Signalled.** Keyed on the launcher having a `__main__` file, so it cannot see an embed through `python -c`, `exec()` or a REPL. |
| Agent cannot reach a provider | **Not enforceable here.** It is a network fact. Run `make verify-boundary`. |
| Agent is actually wired to the gateway | **Not enforceable here.** This is the SDK adoption contract, a separate test. |

## Two boundaries, not one

A vault is not a boundary. It is lifecycle: short TTL, rotation, audit. It
limits how long a leaked key is useful. It does not stop an agent that already
has the key, and it does not stop an agent that can reach the provider with it.

You need both:

| | Stops | Provided by |
|---|---|---|
| **A. Cannot read the key** | The agent reading an env var, a file, or the gateway's memory | OS users, container mounts, `LoadCredential=`, a vault the agent cannot reach |
| **B. Cannot reach the provider** | The agent calling the API with a key it somehow obtained | Firewall, NetworkPolicy, container egress rules |

A vault gives you neither boundary by itself. It makes **A** cheaper to operate
and makes a leaked key expire quickly — which is worth having, and is not the
same thing as B.

## Tiers

### Tier 0 — same process. Unsupported.

```python
from safety_layer.interface.gateway import build_gateway_server   # refused
```

There is nothing to protect. The gateway refuses to start this way because a
green result here would be a claim the deployment cannot support.

### Tier 1 — separate OS user (minimum)

The kernel enforces this. `systemd`'s `User=` plus `LoadCredential=` means the
agent's user cannot read `/proc/<pid>/environ` and cannot `ptrace` the gateway.

```
deploy/systemd/safety-gateway.service
```

### Tier 2 — separate containers (recommended for self-hosting)

```
deploy/docker-compose.yml
```

Two networks, and the gateway is the only service on both. Your agent joins
`agent_net` only, so it has no route to a provider.

**This file deliberately contains no `agent:` service.** You already have an
agent; shipping a fake one would prove only that our compose file is written
correctly, not that your agent is protected.

### Tier 3 — separate host, egress control, workload identity (production)

```
deploy/k8s/gateway.yaml
```

Two NetworkPolicies. One restricts ingress to the gateway. The other restricts
agent egress to the gateway and DNS — **notably absent is any rule permitting
`api.stripe.com`**, which is what makes a leaked key harmless.

Bind the gateway's ServiceAccount to your provider's workload identity so it
holds no static credential at all.

## Your agent's side

There is no container to copy. There is a URL and a key:

```python
client = SafetyClient(base_url="http://gateway:8080", key=VIRTUAL_KEY)
```

Issue the key with the routes that agent is allowed to use:

```bash
safety gateway --config routes.json --db gateway.db \
    issue-key --name billing-agent --ttl 1h --routes /charge
```

An agent with a key for `/charge` receives `403` on `/refund`. An unregistered
path is refused identically, so the gateway does not become a route-existence
oracle.

### Status codes

A client has to be able to tell these apart, so they are not overloaded:

| Status | Meaning | Client should |
|---|---|---|
| `401` | No key, unknown key, expired or revoked | Re-authenticate. Do not retry blindly. |
| `403` | Authenticated, not permitted — route not in the key's scope | Request a key with that route. |
| `403` + `needs_approval: true` | Authenticated, action held pending approval | Obtain an approval, then retry. |
| `502` | The upstream could not be reached | Retry later. The action did not happen. |

`401` previously also meant "awaiting approval", which left a client unable to
tell whether to request an approval or to re-authenticate. It meant the
`make verify-boundary` probe reported a working key as rejected.

### Key lifecycle

Issuing and revoking take effect on the running gateway — no restart. The store
is re-read per request, so a revoked key stops working immediately. An earlier
version cached the key set at startup, which meant a compromised key stayed
valid until someone restarted the service.

## Checking your deployment

Two commands, and they answer different questions.

```bash
safety gateway doctor --config routes.json   # this host
make verify-boundary                        # from the agent's position
```

`doctor` checks what the gateway can genuinely observe: the uid it runs as, the
owner and mode of each secret, whether a master key is set, what it binds to.
It does **not** report whether your agent can reach a provider — that is a
different machine or namespace, and reporting on it from the gateway would be
inventing evidence.

`make verify-boundary` attaches an ephemeral container to your agent's network
and tries to escape: reach a provider directly, read the secret, call the
gateway without a key. It is written against the standard library only, because
a probe that imports our own code cannot tell our code from the adversary's.

It exits **2 when it cannot run**, never 0. "Could not check" is not "passed".

```
BOUNDARY NOT HELD: 1 check(s) failed: A  no route to a provider
  REACHABLE api.stripe.com:443 from the agent's network. A bypass would
  succeed here, so no credential boundary exists.
```

## What a green result means

| | Proves | Does **not** prove |
|---|---|---|
| `make verify-boundary` | The topology blocks direct provider access from the agent's position | That any agent behaves correctly |
| `tests/test_adoption_contract.py` | A hostile agent on the documented path is blocked | That the deployment topology holds |
| **Both** | Boundary **and** wiring | |

Neither substitutes for the other. A deployment with a perfect topology and an
agent that calls the provider directly is still unprotected; an agent perfectly
wired to a gateway that runs in its own process still holds no boundary.