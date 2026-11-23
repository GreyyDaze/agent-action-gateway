#!/usr/bin/env python3
"""Adversarial probe: run from the agent's position and try to escape.

This tests the DEPLOYMENT, not the library. It is written against the Python
standard library on purpose: if it imported agent_action_gateway, a bug in our own code
could satisfy it, and a check that cannot distinguish our code from the
adversary's is not a check.

Run it inside a container attached to `agent_net` — the network an agent
occupies, and the only one it is meant to reach:

    docker compose run --rm --no-deps \
        --network agent_net -v "$PWD/verify_boundary.py:/probe.py:ro" \
        python:3.12-slim python /probe.py --gateway http://gateway:8080

With `--target proxy` it probes docker-compose.proxy.yml instead: the agent
must reach the MCP proxy (with its token) and nothing else -- not the gateway,
not a provider -- and must not be able to read the proxy's config or database.
`make verify-proxy-boundary` runs it that way.

Each check states what it proves and what it does not, because a probe that
overstates itself is the failure mode this project exists to prevent.

Exit codes: 0 all checks passed, 1 a boundary failed, 2 could not determine.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request

PROVIDER_HOST = "api.github.com"


class Undetermined(Exception):
    """A check could not run here. Never reported as a pass."""


def _post(url: str, token: str | None, payload: dict | None = None) -> tuple[int, str]:
    body = json.dumps(payload or {}).encode()
    request = urllib.request.Request(url, data=body, method="POST")
    request.add_header("Content-Type", "application/json")
    if token is not None:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return int(response.status), response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return int(exc.code), exc.read().decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise Undetermined(f"could not reach {url}: {exc}") from exc


def _tcp_reachable(host: str, port: int = 443, timeout: float = 5.0) -> bool:
    """Whether a TCP connection to host:port completes.

    Used for the egress check. DNS failure and connection refusal both count as
    blocked, which is the outcome we want -- the exact mechanism does not
    matter, reachability does.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (TimeoutError, socket.gaierror, OSError):
        return False


def check_egress_blocked() -> tuple[bool, str]:
    """A: the agent's position must not have a route to a provider.

    Precisely what this proves: a leaked upstream credential would be *usable*
    from here. It does not claim a bypass is otherwise possible -- the agent
    holds no credential in the first place, which is the primary defence. The
    network check is the second barrier: it is what stops a key that leaked by
    some other route from being usable here.
    """
    if _tcp_reachable(PROVIDER_HOST):
        return False, (
            f"REACHABLE {PROVIDER_HOST}:443 from the agent's network. An "
            "upstream key that leaked for any reason would be usable from here, "
            "so this barrier is absent. If you turned egress on deliberately, "
            "carry the guarantee on scoped short-lived credentials or provider-"
            "side key restrictions instead -- see docker-compose.egress.yml."
        )
    return True, (
        f"no route to {PROVIDER_HOST}:443 from the agent's network, so a leaked "
        "upstream key would not be usable here"
    )


def check_gateway_requires_a_key(gateway: str) -> tuple[bool, str]:
    """The gateway must refuse an unauthenticated caller."""
    try:
        status, _ = _post(f"{gateway}/deploy", None)
    except Undetermined as exc:
        raise Undetermined(f"cannot reach the gateway to test it: {exc}") from exc
    if status == 401:
        return True, "gateway refuses a caller with no key (401)"
    return False, f"gateway answered {status} to an unauthenticated caller; expected 401"


def check_gateway_accepts_a_key(gateway: str, key: str) -> tuple[bool, str]:
    """A correctly scoped key must get past authentication.

    What happens next depends on policy, not on authentication: a held-until-
    approval or environment refusal is the expected answer and still proves the
    key was accepted. So the body is inspected rather than the status alone --
    a status code that means both "not authenticated" and "awaiting approval"
    is exactly the ambiguity this check must not depend on.
    """
    try:
        status, body = _post(f"{gateway}/deploy", key, {"ref": "main"})
    except Undetermined as exc:
        raise Undetermined(f"cannot reach the gateway to test it: {exc}") from exc

    try:
        parsed = json.loads(body)
    except (ValueError, TypeError):
        parsed = {}
    accepted = bool(parsed.get("needs_approval")) or status not in (401, 403)
    if not accepted:
        return False, f"gateway rejected the virtual key ({status}): {body[:120]}"
    if parsed.get("needs_approval"):
        return True, "key accepted, request held pending approval"
    return True, f"key accepted, gateway answered {status}"


def check_secret_unreadable(path: str) -> tuple[bool, str]:
    """The upstream credential must not be readable from here."""
    if not os.path.exists(path):
        # Absent is the strongest outcome: there is nothing here at all.
        return True, f"{path} is not present in the agent's filesystem"
    if not os.access(path, os.R_OK):
        return True, f"{path} exists but is not readable by this process"
    try:
        with open(path) as handle:
            handle.read(1)
    except OSError as exc:
        return True, f"{path} exists but could not be read ({exc.strerror})"
    return False, f"READ {path} from the agent's position. The credential is exposed."


def _mcp_initialize(url: str, token: str | None) -> tuple[int, str]:
    """Send MCP `initialize` to the proxy, as an agent's client would."""
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "boundary-probe", "version": "1"},
        },
    }
    request = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST")
    request.add_header("Content-Type", "application/json")
    request.add_header("Accept", "application/json, text/event-stream")
    if token is not None:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return int(response.status), response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return int(exc.code), exc.read().decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise Undetermined(f"could not reach {url}: {exc}") from exc


def check_proxy_requires_a_token(proxy: str) -> tuple[bool, str]:
    """The proxy must refuse a caller with no token."""
    status, _ = _mcp_initialize(proxy, None)
    if status == 401:
        return True, "proxy refuses a caller with no token (401)"
    return False, f"proxy answered {status} to a caller with no token; expected 401"


def check_proxy_accepts_a_token(proxy: str, token: str) -> tuple[bool, str]:
    """The agent's token must open an MCP session."""
    status, body = _mcp_initialize(proxy, token)
    if status == 200 and '"result"' in body:
        return True, "token accepted, MCP session opened"
    return False, f"proxy rejected the token ({status}): {body[:120]}"


def check_gateway_unreachable(gateway: str) -> tuple[bool, str]:
    """The agent must not reach the gateway directly, only through the proxy.

    A direct route would let the agent skip the proxy's checks (approval,
    limits, once-only) and use the gateway's routes with a key it obtained.
    """
    parsed = urllib.parse.urlsplit(gateway)
    host, port = parsed.hostname or "", parsed.port or 80
    if _tcp_reachable(host, port):
        return False, f"REACHABLE {host}:{port} from the agent's network: it can skip the proxy"
    return True, f"no route to the gateway ({host}:{port}): calls must go through the proxy"


def check_private_files_absent(paths: list[str]) -> tuple[bool, str]:
    """The proxy's config and database must not be readable from here.

    The database holds the approvals. An agent that can write it can approve
    its own actions; one that can read the config can learn the servers' keys.
    """
    exposed = [path for path in paths if os.path.exists(path) and os.access(path, os.R_OK)]
    if exposed:
        return False, f"READABLE from the agent's position: {', '.join(exposed)}"
    return True, f"not readable here: {', '.join(paths)}"


def _report(checks: list[tuple[str, bool | None, str]]) -> int:
    undetermined = 0
    for name, ok, detail in checks:
        if ok is None:
            label = "UNKNOWN"
            undetermined += 1
        elif ok:
            label = "PASS"
        else:
            label = "FAIL"
        print(f"{label:>7}  {name}\n         {detail}\n")

    if undetermined:
        print(
            f"INCONCLUSIVE: {undetermined} of {len(checks)} checks could not run "
            "here. That is not a pass."
        )
        return 2
    failed = [name for name, ok, _ in checks if ok is False]
    if failed:
        print(f"BOUNDARY NOT HELD: {len(failed)} check(s) failed: {', '.join(failed)}")
        return 1
    print("BOUNDARY HELD from the agent's position.")
    return 0


def _run(names_and_checks: list[tuple[str, object]]) -> list[tuple[str, bool | None, str]]:
    results: list[tuple[str, bool | None, str]] = []
    for name, run in names_and_checks:
        if isinstance(run, str):  # a reason the check cannot run
            results.append((name, None, run))
            continue
        try:
            ok, detail = run()  # type: ignore[operator]
            results.append((name, ok, detail))
        except Undetermined as exc:
            results.append((name, None, str(exc)))
    return results


def main_proxy(args: argparse.Namespace) -> int:
    print("PROBE: running from the agent's position, trying to get around the MCP proxy.\n")
    print("  Proves: the agent's network reaches the proxy and nothing else, the proxy")
    print("          needs a token, and its config and database are out of reach.")
    print("  Does NOT prove: that any particular agent is wired to the proxy.\n")
    token_check: object = (
        (lambda: check_proxy_accepts_a_token(args.proxy, args.token))
        if args.token
        else "no token supplied; set AGENT_GATEWAY_PROXY_TOKEN or pass --token"
    )
    return _report(_run([
        ("A  no route to a provider", check_egress_blocked),
        ("B  proxy refuses a caller with no token", lambda: check_proxy_requires_a_token(args.proxy)),
        ("C  proxy accepts the agent's token", token_check),
        ("D  no route to the gateway (cannot skip the proxy)", lambda: check_gateway_unreachable(args.gateway)),
        ("E  proxy's config and database unreadable here", lambda: check_private_files_absent(args.private_path)),
    ]))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gateway", default="http://gateway:8080")
    parser.add_argument(
        "--key",
        default=os.environ.get("AGENT_GATEWAY_PROBE_KEY", ""),
        help="a virtual key scoped to the gateway's routes",
    )
    parser.add_argument(
        "--secret-path",
        default="/run/secrets/github_token",
        help="where the upstream credential would be if it were wrongly mounted",
    )
    parser.add_argument(
        "--target",
        choices=("gateway", "proxy"),
        default="gateway",
        help="what the agent is meant to reach: the gateway, or the MCP proxy",
    )
    parser.add_argument("--proxy", default="http://proxy:8090/mcp")
    parser.add_argument(
        "--token",
        default=os.environ.get("AGENT_GATEWAY_PROXY_TOKEN", ""),
        help="the agent's token for the proxy",
    )
    parser.add_argument(
        "--private-path",
        action="append",
        default=None,
        help="a proxy file the agent must not read (repeatable)",
    )
    args = parser.parse_args()
    if args.target == "proxy":
        args.private_path = args.private_path or [
            "/etc/agent-action-gateway/servers.json",
            "/var/lib/agent-action-gateway/proxy.db",
        ]
        return main_proxy(args)

    print("PROBE: running from the agent's position, trying to escape the boundary.\n")
    print("  Proves: the deployment blocks direct provider access, and the gateway")
    print("          authenticates and scopes its callers.")
    print("  Does NOT prove: that any particular agent is wired to the gateway.\n")

    checks: list[tuple[str, bool | None, str]] = [
        ("A  no route to a provider", None, ""),
        ("B  gateway refuses a caller with no key", None, ""),
        ("C  gateway accepts a scoped key", None, ""),
        ("D  upstream secret unreadable here", None, ""),
    ]

    def record(index: int, ok: bool, detail: str) -> None:
        checks[index] = (checks[index][0], ok, detail)

    for index, run in (
        (0, lambda: check_egress_blocked()),
        (1, lambda: check_gateway_requires_a_key(args.gateway)),
        (3, lambda: check_secret_unreadable(args.secret_path)),
    ):
        try:
            record(index, *run())
        except Undetermined as exc:
            record(index, None, str(exc))

    if not args.key:
        record(2, None, "no virtual key supplied; set AGENT_GATEWAY_PROBE_KEY or pass --key")
    else:
        try:
            record(2, *check_gateway_accepts_a_key(args.gateway, args.key))
        except Undetermined as exc:
            record(2, None, str(exc))

    return _report(checks)


if __name__ == "__main__":
    sys.exit(main())
