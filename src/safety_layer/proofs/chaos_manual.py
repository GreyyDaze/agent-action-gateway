"""A repeatable manual form of the chaos suite."""
from __future__ import annotations

import argparse
import http.server
import multiprocessing
import os
import signal
import sqlite3
import tempfile
import threading
from pathlib import Path

from safety_layer.audit.receipts import resolve_unknown
from safety_layer.integrations.adapters.base import HttpExternalActionProvider
from safety_layer.proofs.chaos import ProviderHandler, initialize_provider_db
from safety_layer.storage.traces import TraceStore


def crash_worker(provider_url: str, db_path: str, intent_key: str) -> None:
    # `db_path` is accepted for signature parity with the harness callers; this
    # worker kills the process before it could use it.
    del db_path
    provider_ref = HttpExternalActionProvider(provider_url).execute("ORD-100", intent_key)
    del provider_ref
    os.kill(os.getpid(), signal.SIGKILL)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run one visible crash recovery crash/recovery drill")
    parser.add_argument("--kill-after-dispatch", action="store_true")
    args = parser.parse_args()

    if not args.kill_after_dispatch:
        print("Re-run with --kill-after-dispatch for the required crash drill.")
        return

    context = multiprocessing.get_context("spawn")

    with tempfile.TemporaryDirectory(prefix="crash-manual-") as tmp:
        root = Path(tmp)
        receipt_db = root / "runtime.db"
        provider_db = root / "provider.db"
        initialize_provider_db(provider_db)
        ProviderHandler.db_path = str(provider_db)
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), ProviderHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_port}"
            store = TraceStore(receipt_db)
            run_id = "manual-phase1"
            step_id = "step-1"
            receipt = store.create_receipt(run_id, step_id, "external_action", {"order_id": "ORD-100"})
            print(f"before: state={receipt.state} intent_key={receipt.intent_key}")

            process = context.Process(
                target=crash_worker,
                args=(url, str(receipt_db), receipt.intent_key),
            )
            process.start()
            process.join()
            if process.exitcode != -signal.SIGKILL:
                raise RuntimeError(f"expected SIGKILL, got exitcode={process.exitcode}")

            resolve_unknown(store, HttpExternalActionProvider(url))
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
