import argparse
import json
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

from .locks import ApprovalStore
from .store import TraceStore


class Handler(BaseHTTPRequestHandler):
    store: TraceStore
    approvals: ApprovalStore

    def do_GET(self) -> None:
        snapshot = self.store.snapshot()
        pending = self.approvals.pending()
        approval_html = "".join(
            f"""
            <section>
              <h3>{escape(approval.action)}</h3>
              <p><strong>ID:</strong> {escape(approval.approval_id)}</p>
              <p><strong>Expires:</strong> {escape(approval.expires_at)}</p>
              <pre>{escape(json.dumps(approval.arguments, indent=2, sort_keys=True))}</pre>
              <form method="post" action="/approvals/approve">
                <input type="hidden" name="approval_id" value="{escape(approval.approval_id)}">
                <label>Approver <input name="approver" required></label>
                <button type="submit">Approve</button>
              </form>
              <form method="post" action="/approvals/deny">
                <input type="hidden" name="approval_id" value="{escape(approval.approval_id)}">
                <label>Approver <input name="approver" required></label>
                <button type="submit">Deny</button>
              </form>
            </section>
            """
            for approval in pending
        )
        body = (
            "<html><body><h1>Agent Safety Layer</h1>"
            f"<h2>Pending approvals ({len(pending)})</h2>"
            f"{approval_html or '<p>No pending approvals.</p>'}"
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

    def do_POST(self) -> None:
        if self.path not in {"/approvals/approve", "/approvals/deny"}:
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        form = parse_qs(self.rfile.read(length).decode("utf-8"))
        approval_id = form.get("approval_id", [None])[0]
        approver = form.get("approver", [None])[0]
        if not approval_id or not approver:
            self.send_error(400, "approval_id and approver are required")
            return
        try:
            if self.path.endswith("/approve"):
                self.approvals.approve(approval_id, approver)
            else:
                self.approvals.deny(approval_id, approver)
        except Exception as exc:
            self.send_error(400, str(exc))
            return
        self.send_response(303)
        self.send_header("Location", "/")
        self.end_headers()


def serve(path: str, host: str, port: int) -> None:
    Handler.store = TraceStore(path)
    Handler.approvals = ApprovalStore(Handler.store)
    ThreadingHTTPServer((host, port), Handler).serve_forever()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", default="data/runtime.db")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    serve(args.db, args.host, args.port)
