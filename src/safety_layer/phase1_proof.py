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

from .provider import HttpRefundProvider
from .receipts import resolve_unknown
from .store import TraceStore


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
    provider = HttpRefundProvider(provider_url)
    receipt = store.create_receipt(run_id, step_id, "external_action", {"order_id": "ORD-100"})
    if kill_point == 0:
        os.kill(os.getpid(), signal.SIGKILL)
    provider_ref = provider.refund("ORD-100", receipt.intent_key)
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

    with tempfile.TemporaryDirectory(prefix="phase1-proof-") as tmp:
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

                resolve_unknown(store, HttpRefundProvider(provider_url))

            unknown = len(store.unknown_receipts())
            provider_actions = count_provider_actions(str(provider_db))
            return provider_actions, unknown
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
    print(f"P1: 0 dupes / {args.jobs} crash jobs")


if __name__ == "__main__":
    main()
