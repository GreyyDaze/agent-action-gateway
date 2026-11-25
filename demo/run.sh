#!/bin/sh
# Starts the demo. Makes random tokens and a test ops key on first run (kept in
# demo/.env, gitignored), issues the proxy a gateway
# virtual key, and starts everything except the agent.
#
#   ./run.sh            start (or restart) the stack
#   ./run.sh agent      open the agent (Claude Code) in its container
#   ./run.sh agent-shell CMD  run a shell command inside the agent container
#   ./run.sh check      check every scene without the LLM (on a fresh stack)
#   ./run.sh down       stop and delete the databases and records (keeps the Claude login)
set -eu
cd "$(dirname "$0")"
compose() { docker compose --env-file .env "$@"; }
rand() { python3 -c 'import secrets;print(secrets.token_urlsafe(32))'; }

case "${1:-up}" in
  # Deletes the databases and records, but never the agent-home volume: it
  # holds the Claude login.
  down) # By the Compose project label, so it works even without .env.
        ids=$(docker ps -aq --filter label=com.docker.compose.project=demo)
        [ -z "$ids" ] || docker rm -f -v $ids >/dev/null   # -v: Postgres data too
        docker volume rm -f demo_proxy-state demo_gateway-state >/dev/null 2>&1 || true
        for n in agent_net tools_net ops_net review_net model_net; do
          docker network rm "demo_$n" >/dev/null 2>&1 || true
        done
        rm -f .env; exit 0 ;;
  agent) compose run --rm agent; exit ;;
  check) compose run --rm check; exit ;;
  # chat SESSION "prompt" [new]: open Claude Code with a first message;
  # "new" starts the session, otherwise it continues it.
  chat) flag=--resume; [ "${4:-}" = new ] && flag=--session-id
        if [ -n "${3:-}" ]; then set -- "$2" "$3"; else set -- "$2"; fi
        compose run --rm agent claude --mcp-config /workspace/.mcp.json --strict-mcp-config \
          "$flag" "$@" 2>/dev/null; exit ;;
  agent-shell) shift; compose run --rm -T --entrypoint bash agent -c "( $* ) 2>&1" 2>/dev/null; exit ;;
esac

if [ ! -f .env ]; then
  umask 077
  {
    echo "AGENT_GATEWAY_MASTER_KEY=$(rand)"
    echo "AGENT_GATEWAY_PROXY_TOKEN=$(rand)"
    echo "AGENT_GATEWAY_DASHBOARD_TOKEN=$(rand)"
    echo "PG_PASSWORD=$(rand)"
    echo "OPS_API_KEY=$(rand)"
    echo "GATEWAY_VIRTUAL_KEY=unset"
  } > .env
fi

compose --profile agent build -q   # the agent too, so workspace changes reach it
compose up -d postgres ops-api gateway
if grep -qE "^GATEWAY_VIRTUAL_KEY=(unset)?$" .env; then
  key=""
  for _ in 1 2 3 4 5 6 7 8 9 10; do   # the gateway may still be starting
    key=$(compose exec -T gateway agent-gateway gateway \
          --config /etc/agent-action-gateway/routes.json \
          --db /var/lib/agent-action-gateway/gateway.db \
          issue-key --name proxy --routes /staging-api/status,/staging-api/restart 2>/dev/null \
          | sed -n 's/^Virtual key issued: //p') || true
    [ -n "$key" ] && break
    sleep 2
  done
  [ -n "$key" ] || { echo "could not issue a gateway key" >&2; exit 1; }
  sed -i.bak "s|^GATEWAY_VIRTUAL_KEY=.*|GATEWAY_VIRTUAL_KEY=$key|" .env && rm -f .env.bak
fi
compose up -d proxy dashboard
for _ in $(seq 60); do   # wait until the proxy has started its servers
  compose logs proxy 2>/dev/null | grep -q 'MCP over HTTP' && break
  sleep 1
done

token=$(sed -n 's/^AGENT_GATEWAY_DASHBOARD_TOKEN=//p' .env)
echo
echo "Dashboard: http://127.0.0.1:8765/?token=$token"
echo "Agent:     ./run.sh agent"
