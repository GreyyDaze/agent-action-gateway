from __future__ import annotations

import argparse
import json
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .locks import ApprovalStore
from .store import TraceStore


def _json(value: object) -> str:
    return escape(json.dumps(value, indent=2, sort_keys=True, default=str))


def _metric(label: str, value: object) -> str:
    return f"<div class='metric'><span>{escape(label)}</span><strong>{escape(str(value))}</strong></div>"


class Handler(BaseHTTPRequestHandler):
    store: TraceStore
    approvals: ApprovalStore

    def _send_html(self, body: str, status: int = 200) -> None:
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _send_json(self, payload: object, status: int = 200) -> None:
        encoded = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/state":
            self._send_json(self.store.dashboard_snapshot())
            return
        if parsed.path != "/":
            self.send_error(404)
            return

        selected_run = parse_qs(parsed.query).get("run", [None])[0]
        snapshot = self.store.dashboard_snapshot()
        pending = self.approvals.pending()
        runs = snapshot["runs"]
        if selected_run is None and runs:
            selected_run = runs[0]["run_id"]

        traces = [t for t in snapshot["traces"] if selected_run is None or t["run_id"] == selected_run]
        budget = next((b for b in snapshot["budgets"] if b["run_id"] == selected_run), None)
        budget = budget or {"steps_used": 0, "dollars_used": 0.0, "elapsed_seconds": 0.0, "tripped": False}

        run_links = "".join(
            f"<a class='run' href='/?run={escape(run['run_id'])}'>{escape(run['run_id'])[:12]} <span>{escape(run['status'])}</span></a>"
            for run in runs
        ) or "<p>No runs recorded.</p>"

        trace_html = "".join(
            f"<article id='trace-{t['id']}' class='card'>"
            f"<h3>Trace #{t['id']} · {escape(t['event'])}</h3>"
            f"<p>Status: <strong>{escape(t['status'])}</strong> · step {t['step']} · flags: {escape(', '.join(t['flags']) or 'none')}</p>"
            f"<details><summary>Evidence</summary><pre>{_json(t)}</pre></details></article>"
            for t in traces
        ) or "<p>No trace events for this run.</p>"

        approval_html = "".join(
            f"<article class='card'><h3>{escape(item.action)}</h3>"
            f"<p>ID: {escape(item.approval_id)} · expires {escape(item.expires_at)}</p>"
            f"<pre>{escape(json.dumps(item.arguments, indent=2, sort_keys=True, default=str))}</pre>"
            f"<form method='post' action='/approvals/approve'><input type='hidden' name='approval_id' value='{escape(item.approval_id)}'><input name='approver' required placeholder='Approver'><button>Approve</button></form>"
            f"<form method='post' action='/approvals/deny'><input type='hidden' name='approval_id' value='{escape(item.approval_id)}'><input name='approver' required placeholder='Approver'><button>Deny</button></form></article>"
            for item in pending
        ) or "<p>No pending approvals.</p>"

        gate_html = "".join(
            f"<tr><td>{escape(str(g['run_id']))}</td><td><strong>{escape(g['verdict'])}</strong></td><td>{g['score']:.3f}</td><td>{g['threshold']:.3f}</td></tr>"
            for g in reversed(snapshot["gate_verdicts"])
        ) or "<tr><td colspan='4'>No gate verdicts.</td></tr>"

        body = f"""<!doctype html>
<html><head><meta charset='utf-8'><title>Agent Safety Layer</title>
<style>
body{{font-family:system-ui,sans-serif;max-width:1400px;margin:2rem auto;padding:0 1rem;background:#f6f7f9;color:#20242a}}
.grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem}} .metric,.card,.run{{background:#fff;border:1px solid #dfe3e8;border-radius:10px;padding:1rem}}
.metric span,.metric strong{{display:block}} .metric strong{{font-size:1.5rem;margin-top:.25rem}}
.layout{{display:grid;grid-template-columns:240px 1fr;gap:1rem;margin-top:1rem}} .sidebar{{display:flex;flex-direction:column;gap:.5rem}}
.run{{display:block;text-decoration:none;color:inherit}} .run span{{float:right;color:#667085}}
pre{{overflow:auto;background:#f0f2f5;padding:1rem;border-radius:8px}} input,button{{padding:.45rem;margin:.25rem}}
table{{width:100%;background:#fff;border-collapse:collapse}} td,th{{padding:.7rem;border-bottom:1px solid #eee;text-align:left}}
@media(max-width:900px){{.grid,.layout{{grid-template-columns:1fr}}}}
</style></head>
<body>
<h1>Agent Safety Layer</h1>
<p>Persisted evidence and enforcement state. Select a run to inspect its trace.</p>
<section class='grid'>
{_metric("Runs", len(runs))}{_metric("Pending approvals", len(pending))}{_metric("Trace events", len(snapshot["traces"]))}{_metric("Gate verdicts", len(snapshot["gate_verdicts"]))}
</section>
<div class='layout'><aside class='sidebar'><h2>Runs</h2>{run_links}</aside><main>
<section class='grid'>
{_metric("Steps used", budget["steps_used"])}{_metric("Spend used", f"$"+"{budget['dollars_used']:.4f}")}{_metric("Elapsed", f"{budget['elapsed_seconds']:.3f}s")}{_metric("Fuse", "TRIPPED" if budget["tripped"] else "OK")}
</section>
<h2>Trace viewer</h2>{trace_html}
<h2>Approval queue</h2>{approval_html}
<h2>Gate history</h2><table><thead><tr><th>Run</th><th>Verdict</th><th>Score</th><th>Threshold</th></tr></thead><tbody>{gate_html}</tbody></table>
</main></div></body></html>"""
        self._send_html(body)

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
