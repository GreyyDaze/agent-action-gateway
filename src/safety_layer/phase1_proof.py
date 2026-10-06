from __future__ import annotations

import argparse
import http.server
import json
import os
import random
import signal
import socket
import sqlite3
import tempfile
import time
import warnings
from pathlib import Path

from .provider import HttpRefundProvider
from .receipts import resolve_unknown
from .store import TraceStore

warnings.filterwarnings("ignore", category=DeprecationWarning, message="This process .* fork")


class ProviderHandler(http.server.BaseHTTPRequestHandler):
    db_path: str

    def _connect(self):
        connection = sqlite3.connect(self.db_path, timeout=30)
        connection.execute(
            """CREATE TABLE IF NOT EXISTS refunds (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                intent_key TEXT NOT NULL,
                order_id TEXT NOT NULL,
                provider_ref TEXT NOT NULL
            )"""
        )
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
                "SELECT provider_ref FROM refunds WHERE intent_key=? ORDER BY id LIMIT 1",
                (key,),
            ).fetchone()
        finally:
            db.close()
        if row is None:
            self.send_error(404)
            return
        self._json({"provider_ref": row[0]})

    def _json(self, body):
        encoded = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, *_args):
        return


def worker(db_path: str, provider_url: str, run_id: str, step_id: str, kill_point: int) -> None:
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


def serve_provider(db_path: str, port: int) -> None:
    ProviderHandler.db_path = db_path
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), ProviderHandler)
    server.serve_forever()


def run_proof(jobs: int) -> tuple[int, int]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        receipt_db = root / "runtime.db"
        provider_db = root / "provider.db"
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            provider_port = probe.getsockname()[1]

        provider_pid = os.fork()
        if provider_pid == 0:
            serve_provider(str(provider_db), provider_port)
            os._exit(0)

        provider_url = f"http://127.0.0.1:{provider_port}"
        time.sleep(0.05)
        store = TraceStore(receipt_db)
        random.seed(1)

        for index in range(jobs):
            run_id = f"crash-{index}"
            step_id = "step-1"
            kill_point = random.randrange(3)

            pid = os.fork()
            if pid == 0:
                worker(str(receipt_db), provider_url, run_id, step_id, kill_point)
                os._exit(0)

            _, status = os.waitpid(pid, 0)
            if not (
                os.WIFSIGNALED(status)
                and os.WTERMSIG(status) == signal.SIGKILL
            ) and not os.WIFEXITED(status):
                raise RuntimeError(f"crash worker failed: status={status}")

            resolve_unknown(store, HttpRefundProvider(provider_url))

        unknown = len(store.unknown_receipts())
        provider_actions = count_provider_actions(str(provider_db))

        os.kill(provider_pid, signal.SIGTERM)
        os.waitpid(provider_pid, 0)
        return provider_actions, unknown


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
