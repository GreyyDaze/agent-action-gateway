"""A small stand-in for a real ops API: restart a staging service.

It needs the real key in `Authorization: Bearer <key>`. Only the gateway holds
that key; the agent never sees it. Every restart is counted so the video can
show it ran once. Test service only: nothing is really restarted.
"""

from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

KEY = os.environ["OPS_API_KEY"]
RESTARTS: dict[str, int] = {}


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, body: dict) -> None:
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:  # noqa: N802
        if self.headers.get("Authorization") != f"Bearer {KEY}":
            self._send(401, {"error": "bad or missing key"})
            return
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        if self.path.startswith("/services/staging-api/restart"):
            RESTARTS["staging-api"] = RESTARTS.get("staging-api", 0) + 1
            self._send(200, {"service": "staging-api", "restarted": True,
                             "restarts_so_far": RESTARTS["staging-api"],
                             "idempotency_key": self.headers.get("Idempotency-Key")})
        elif self.path.startswith("/services/staging-api/status"):
            self._send(200, {"service": "staging-api", "up": True,
                             "restarts_so_far": RESTARTS.get("staging-api", 0)})
        else:
            self._send(404, {"error": "no such endpoint"})

    def log_message(self, fmt: str, *args: object) -> None:
        print("ops-api:", fmt % args, flush=True)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 9000), Handler).serve_forever()
