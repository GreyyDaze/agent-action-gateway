"""Verification that the system stays safe under failure injection."""
from __future__ import annotations

import argparse
import http.server
import json
import multiprocessing
import os
import signal
import sqlite3
import tempfile
import threading
import time
from pathlib import Path

from safety_layer.audit.receipts import resolve_unknown
from safety_layer.integrations.adapters.base import HttpExternalActionProvider
from safety_layer.storage.traces import TraceStore


class ProviderHandler(http.server.BaseHTTPRequestHandler):
    db_path: str

    def _connect(self):
        connection = sqlite3.connect(self.db_path, timeout=30)
        connection.row_factory = sqlite3.Row
        return connection

    def do_POST(self):
        if self.path != "/refunds":
            self.send_error(404)
            return
        payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        key = payload["intent_key"]
        order_id = payload["order_id"]
        db = self._connect()
        try:
            existing = db.execute(
                "SELECT provider_ref FROM refunds WHERE intent_key=?",
                (key,),
            ).fetchone()
            if existing is not None:
                self._json({"provider_ref": existing["provider_ref"]})
                return
            provider_ref = f"refund-{time.time_ns()}"
            db.execute(
                "INSERT INTO refunds(intent_key, order_id, provider_ref) VALUES (?, ?, ?)",
                (key, order_id, provider_ref),
            )
            db.commit()
        finally:
            db.close()
        self._json({"provider_ref": provider_ref})

    def do_GET(self):
        prefix = "/refunds/"
        if not self.path.startswith(prefix):
            self.send_error(404)
            return
        key = self.path[len(prefix):]
        db = self._connect()
        try:
            row = db.execute(
                "SELECT provider_ref FROM refunds WHERE intent_key=?",
                (key,),
            ).fetchone()
        finally:
            db.close()
        if row is None:
            self.send_error(404)
            return
        self._json({"provider_ref": row["provider_ref"]})

    def _json(self, body):
        encoded = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, *_args):
        return


def initialize_provider_db(path: str | Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as db:
        db.execute(
            """CREATE TABLE IF NOT EXISTS refunds (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                intent_key TEXT NOT NULL UNIQUE,
                order_id TEXT NOT NULL,
                provider_ref TEXT NOT NULL
            )"""
        )


def worker(provider_url: str, db_path: str, run_id: str, step_id: str, kill_point: int) -> None:
    store = TraceStore(db_path)
    provider = HttpExternalActionProvider(provider_url)
    receipt = store.create_receipt(run_id, step_id, "external_action", {"target": "ORD-100"})
    if kill_point == 0:
        os.kill(os.getpid(), signal.SIGKILL)
    provider_ref = provider.execute("ORD-100", receipt.intent_key)
    if kill_point == 1:
        os.kill(os.getpid(), signal.SIGKILL)
    store.mark_done(receipt.intent_key, provider_ref)
    if kill_point == 2:
        os.kill(os.getpid(), signal.SIGKILL)


def count_provider_actions(path: str) -> int:
    with sqlite3.connect(path) as db:
        return db.execute("SELECT COUNT(*) FROM refunds").fetchone()[0]


def run_proof(jobs: int) -> tuple[int, int]:
    context = multiprocessing.get_context("spawn")

    with tempfile.TemporaryDirectory(prefix="crash-proof-") as tmp:
        root = Path(tmp)
        receipt_db = root / "runtime.db"
        provider_db = root / "provider.db"
        initialize_provider_db(provider_db)

        ProviderHandler.db_path = str(provider_db)
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), ProviderHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            provider_url = f"http://127.0.0.1:{server.server_port}"
            store = TraceStore(receipt_db)

            import random
            rng = random.Random(1)

            for index in range(jobs):
                run_id = f"crash-{index}"
                step_id = "step-1"
                kill_point = rng.randrange(3)

                process = context.Process(
                    target=worker,
                    args=(provider_url, str(receipt_db), run_id, step_id, kill_point),
                )
                process.start()
                process.join()

                if process.exitcode != 0 and process.exitcode != -signal.SIGKILL:
                    raise RuntimeError(
                        f"crash worker failed: job={index} exitcode={process.exitcode}"
                    )

                resolve_unknown(store, HttpExternalActionProvider(provider_url))

            unknown = len(store.unknown_receipts())
            provider_actions = count_provider_actions(str(provider_db))
            return provider_actions, unknown
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


# -- duplicate suppression ------------------------------------------------


def dedupe_worker(
    provider_url: str, db_path: str, run_id: str, step_id: str, kill_point: int
) -> None:
    """Claim one effect, then die at a chosen point.

    Every worker claims the *same* effect from a different run, which is what a
    retry after a crash looks like from the store's side. The effect key is
    derived from the action and its arguments, so all of them collide.
    """
    from safety_layer.audit.receipts import claim_effect

    store = TraceStore(db_path)
    arguments = {"target": "ORD-100"}
    receipt, owned = claim_effect(
        store, run_id, step_id, "external_action", arguments
    )
    if not owned:
        # Someone else holds the claim, or it already landed. Either way this
        # worker must not call the provider -- that is the whole guarantee.
        if receipt.state == "done":
            return
        # The claim is `pending`: a previous attempt crashed and the outcome is
        # unknown. Reconcile it the way recovery is meant to -- ask the provider
        # whether it landed. If it did, record that. If it did not, leave it
        # pending: a retry must not re-execute an effect whose fate is unknown.
        if receipt.state == "pending":
            found = HttpExternalActionProvider(provider_url).find(
                receipt.intent_key, receipt.arguments.get("target")
            )
            if found is not None:
                store.mark_resolved(receipt.intent_key, found)
        return
    if kill_point == 0:
        os.kill(os.getpid(), signal.SIGKILL)
    provider_ref = HttpExternalActionProvider(provider_url).execute(
        "ORD-100", receipt.intent_key
    )
    if kill_point == 1:
        os.kill(os.getpid(), signal.SIGKILL)
    store.mark_done(receipt.intent_key, provider_ref)
    if kill_point == 2:
        os.kill(os.getpid(), signal.SIGKILL)


def run_dedupe_proof(jobs: int) -> tuple[int, int]:
    """Claim one effect from `jobs` different runs, crashing at random points.

    The result is the number of provider actions taken. One effect claimed a
    thousand times must produce exactly one action, whatever the crash
    distribution and whatever the per-attempt key would have been -- and
    per-attempt keys are all different here, which is the point.
    """
    context = multiprocessing.get_context("spawn")

    with tempfile.TemporaryDirectory(prefix="dedupe-proof-") as tmp:
        root = Path(tmp)
        receipt_db = root / "runtime.db"
        provider_db = root / "provider.db"
        initialize_provider_db(provider_db)

        ProviderHandler.db_path = str(provider_db)
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), ProviderHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            provider_url = f"http://127.0.0.1:{server.server_port}"

            import random
            rng = random.Random(1)

            for index in range(jobs):
                # The first attempt always runs to completion. Without one
                # successful execution there is nothing to deduplicate, and a
                # proof that only ever crashes proves nothing about repeats.
                kill_point = 9 if index == 0 else rng.randrange(3)
                process = context.Process(
                    target=dedupe_worker,
                    args=(
                        provider_url,
                        str(receipt_db),
                        f"retry-{index}",
                        "step-1",
                        kill_point,
                    ),
                )
                process.start()
                process.join()
                if process.exitcode not in (0, -signal.SIGKILL):
                    raise RuntimeError(
                        f"dedupe worker failed: job={index} exitcode={process.exitcode}"
                    )

            actions = count_provider_actions(str(provider_db))
            receipts = len(TraceStore(receipt_db).snapshot()["receipts"])
            return actions, receipts
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--jobs", type=int, default=1000)
    args = parser.parse_args()

    actions, unknown = run_proof(args.jobs)
    if actions != args.jobs or unknown != 0:
        raise SystemExit(
            f"P1 FAILED: provider_actions={actions} expected={args.jobs} unknown={unknown}"
        )
    print(f"CRASH SAFETY: 0 dupes / {args.jobs} crash jobs")

    dedupe_actions, receipts = run_dedupe_proof(args.jobs)
    # One effect, claimed once, no matter how many runs tried. Anything above
    # one is a duplicate side effect, and more than one receipt row would mean
    # the claim itself is not holding.
    if dedupe_actions != 1 or receipts != 1:
        raise SystemExit(
            f"DEDUPLICATION FAILED: one effect claimed by {args.jobs} runs produced "
            f"{dedupe_actions} provider actions across {receipts} receipts"
        )
    print(
        f"DUPLICATE SUPPRESSION: 1 side effect / {args.jobs} crashed retries"
    )


if __name__ == "__main__":
    main()
