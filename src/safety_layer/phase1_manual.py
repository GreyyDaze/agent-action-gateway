from __future__ import annotations

import argparse
import http.server
import os
import signal
import sqlite3
import threading
from pathlib import Path

from .phase1_proof import ProviderHandler
from .provider import HttpRefundProvider
from .receipts import resolve_unknown
from .store import TraceStore


def main() -> None:
    parser = argparse.ArgumentParser(description="Run one visible Phase 1 crash/recovery drill")
    parser.add_argument("--kill-after-dispatch", action="store_true")
    args = parser.parse_args()

    root = Path("data/phase1-manual")
    root.mkdir(parents=True, exist_ok=True)
    receipt_db = root / "runtime.db"
    provider_db = root / "provider.db"
    ProviderHandler.db_path = str(provider_db)
    server = http.server.HTTPServer(("127.0.0.1", 0), ProviderHandler)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}"
        store = TraceStore(receipt_db)
        run_id = "manual-phase1"
        step_id = "step-1"
        receipt = store.create_receipt(run_id, step_id, "external_action", {"order_id": "ORD-100"})
        print(f"before: state={receipt.state} intent_key={receipt.intent_key}")

        if not args.kill_after_dispatch:
            print("Re-run with --kill-after-dispatch for the required crash drill.")
            return

        pid = os.fork()
        if pid == 0:
            HttpRefundProvider(url).refund("ORD-100", receipt.intent_key)
            os.kill(os.getpid(), signal.SIGKILL)

        _, status = os.waitpid(pid, 0)
        if not os.WIFSIGNALED(status) or os.WTERMSIG(status) != signal.SIGKILL:
            raise RuntimeError(f"expected SIGKILL, got status={status}")

        resolve_unknown(store, HttpRefundProvider(url))
        row = store.snapshot()["receipts"][0]
        with sqlite3.connect(provider_db) as db:
            actions = db.execute(
                "SELECT COUNT(*) FROM refunds WHERE intent_key=?",
                (receipt.intent_key,),
            ).fetchone()[0]
        print(f"after recovery: state={row['state']} provider_ref={row['provider_ref']}")
        print(f"provider actions for intent={actions}")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


if __name__ == "__main__":
    main()
