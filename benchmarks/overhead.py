"""Per-call cost of the checks: library and MCP proxy against a plain call.

Run from the repo root:  python benchmarks/overhead.py

The tools here do no work, so every number is the cost of the checks themselves.
Most of it is SQLite writes (traces, receipts, approvals), so it depends on the
disk and on whether the database is SQLite or PostgreSQL.
"""

from __future__ import annotations

import statistics
import sys
import tempfile
import time
from collections.abc import Callable, Iterable
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from agent_action_gateway.integrations.mcp_proxy import (  # noqa: E402
    ProxyConfig,
    ServerConfig,
    StdioDownstream,
    build_proxy,
)
from agent_action_gateway.policy.fuses import FuseLimits  # noqa: E402
from agent_action_gateway.runtime.session import SafetySession  # noqa: E402
from agent_action_gateway.storage.traces import TraceStore  # noqa: E402

CALLS = 400
LIMITS = FuseLimits(max_steps=100_000, max_wall_seconds=3600)


def measure(name: str, call: Callable[[int], object], calls: Iterable[int]) -> None:
    """Time each call and print the median and the 95th percentile in ms."""
    samples = []
    for n in calls:
        start = time.perf_counter()
        call(n)
        samples.append(time.perf_counter() - start)
    samples.sort()
    median = statistics.median(samples) * 1000
    p95 = samples[int(len(samples) * 0.95) - 1] * 1000
    print(f"{name:<50} median {median:7.3f} ms   p95 {p95:7.3f} ms")


def approve(approvals, action: str, arguments: dict) -> str:
    approval = approvals.request(action, arguments, datetime.now(UTC) + timedelta(minutes=5))
    approvals.approve(approval.approval_id, "benchmark")
    return approval.approval_id


def main() -> None:
    tmp = tempfile.mkdtemp()

    def work(n: int) -> dict:
        return {"n": n}

    measure("library: the plain function", work, range(CALLS))

    session = SafetySession(TraceStore(f"{tmp}/library.db"), environment="dev", limits=LIMITS)
    read = session.tool(work, action="x.read", risk="read")
    measure("library: guarded read tool", lambda n: read(n=n), range(CALLS))

    write = session.tool(work, action="x.write", risk="destructive")
    ids = [approve(session.approvals, "x.write", {"n": n}) for n in range(CALLS)]
    measure(
        "library: guarded destructive tool (approved)",
        lambda n: write(n=n, approval_id=ids[n]),
        range(CALLS),
    )

    server = ServerConfig(
        name="db",
        command=sys.executable,
        args=(str(ROOT / "tests/fixtures/fake_mcp_server.py"),),
    )
    direct = StdioDownstream.from_config(server)
    direct.start()
    measure(
        "MCP: straight to the server (stdio round trip)",
        lambda _n: direct.call_tool("list_items", {}),
        range(CALLS),
    )
    direct.close()

    proxy = build_proxy(ProxyConfig((server,), limits=LIMITS), f"{tmp}/proxy.db")
    measure(
        "MCP: through the proxy, read tool",
        lambda n: proxy.call_tool("db__list_items", {"n": n}),
        range(CALLS),
    )
    for n in range(CALLS):
        approve(proxy.session.approvals, "db__delete_item", {"id": str(n)})
    measure(
        "MCP: through the proxy, destructive tool (approved)",
        lambda n: proxy.call_tool("db__delete_item", {"id": str(n)}),
        range(CALLS),
    )
    proxy.close()


if __name__ == "__main__":
    main()
