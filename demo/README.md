# Demo: a real agent fixes a failed migration

A real Claude Code agent is asked to fix a database migration that failed
halfway on **staging**, then restart the staging API. It works through the MCP
proxy and nothing else. Everything here is a **test** setup: two test
databases, a small stand-in ops API, random keys made on first run.

This folder is not part of the Python package. The proxy and the gateway are
installed with pip inside their containers, like any user would.

## What it shows

| Scene | What happens |
|---|---|
| No way around | The agent's container has the task and one MCP address. It cannot reach Postgres, the gateway or the ops API. |
| Reads run | The agent reads the schema and the migration log without approval. |
| Environment | The session is staging; a call to prod is refused. |
| Exact approval | The fix (a write) is held. A person approves that exact SQL in the dashboard; it runs once. |
| Key custody | The restart goes through the gateway, which adds the ops API key. The agent never sees it. |
| Once only | Asked to restart again, and approved again, it answers with the first result. The restart count stays 1. |
| Proof | The dashboard shows every call, refusal and approval. |

Short clips (each set up on purpose): a loop is stopped; a changed tool is held
until a person accepts it; a call that times out is held and settled by a
person; `check --app` finds a direct call; the release gate fails a less safe
version. The videos are in [`../videos`](../videos).

## Parts

```
agent (Claude Code)  --agent_net-->  MCP proxy  --tools_net-->  Postgres MCP Pro (staging, prod) --> Postgres (test)
                                         |
                                         +--tools_net-->  gateway (holds the key) --ops_net--> ops API (test)
dashboard (127.0.0.1:8765) reads the proxy's records; a person approves there.
```

- `servers.json` (in `config/`): the proxy's servers and rules. `execute_sql` is
  one tool for every statement, so its risk is decided per call from the SQL.
- `routes.json` (in `config/`): the gateway's routes and the key it holds.
- `seed/`: the two test databases. Staging stopped halfway through migration 0042.
- `agent/workspace/`: all the agent gets: the task, the MCP address, and a
  setting that allows only the proxy's tools.

## Run it

Needs Docker and a Claude account.

```bash
./run.sh            # start everything except the agent; prints the dashboard link
./run.sh check      # check every scene without the LLM (on a fresh stack)
./run.sh agent      # open Claude Code in its container; run /login the first time
./run.sh down       # delete the databases and records (keeps the Claude login)
```

In the agent, ask: `Read TASK.md and do the task.` Approve in the dashboard when
it stops, then tell it to continue.

`record/` holds the scripts that made the videos (`record_main.sh`,
`record_clips.sh`; they need [VHS](https://github.com/charmbracelet/vhs), ffmpeg
and Chrome). The agent's words are not scripted, so each recording differs.

## Honest limits

- The agent container also has a network for the model API (`model_net`). It
  cannot reach the tools that way, but it is not cut off from the internet.
- Approvals in the recordings are sent through the dashboard's own form by a
  script (`approve.py`), as a person would click them.
- Postgres MCP Pro does not mark its tools read-only, so `config/servers.json`
  marks the listing tools as reads. `explain_query` and the index tools still
  need approval: they can run a query or create an extension.
