import argparse
import json
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .store import TraceStore


class Handler(BaseHTTPRequestHandler):
    store: TraceStore

    def do_GET(self) -> None:
        snapshot = self.store.snapshot()
        body = (
            "<html><body><h1>Agent Safety Layer</h1>"
            f"<h2>Trace events ({len(snapshot['traces'])})</h2><pre>{escape(json.dumps(snapshot['traces'], indent=2))}</pre>"
            f"<h2>Receipts ({len(snapshot['receipts'])})</h2><pre>{escape(json.dumps(snapshot['receipts'], indent=2))}</pre>"
            f"<h2>Gate verdicts ({len(snapshot['gate_verdicts'])})</h2><pre>{escape(json.dumps(snapshot['gate_verdicts'], indent=2))}</pre>"
            "</body></html>"
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def serve(path: str, host: str, port: int) -> None:
    Handler.store = TraceStore(path)
    ThreadingHTTPServer((host, port), Handler).serve_forever()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", default="data/runtime.db")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    serve(args.db, args.host, args.port)
