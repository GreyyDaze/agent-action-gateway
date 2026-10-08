from __future__ import annotations

import argparse
import json
import secrets
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .locks import ApprovalError, ApprovalStore
from .store import TraceStore


def _json(value: object) -> str:
    return escape(json.dumps(value, indent=2, sort_keys=True, default=str))


def _metric(label: str, value: object) -> str:
    return f"<div class='metric'><span>{escape(label)}</span><strong>{escape(str(value))}</strong></div>"


class Handler(BaseHTTPRequestHandler):
    """Read-only evidence viewer with an explicit approval write boundary.

    The approval queue is the human trust boundary of the whole product, so a
    POST must not be forgeable by another web page. Every approval form carries
    a per-process CSRF token, and POSTs are additionally required to come from a
    local origin.
    """

    store: TraceStore
    approvals: ApprovalStore
    csrf_token: str
    allowed_origins: frozenset[str]

    def _security_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; form-action 'self';"
            " base-uri 'none'; frame-ancestors 'none'",
        )

    def _send_html(self, body: str, status: int = 200) -> None:
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self._security_headers()
        self.end_headers()
        self.wfile.write(payload)

    def _send_json(self, payload: object, status: int = 200) -> None:
        encoded = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self._security_headers()
        self.end_headers()
        self.wfile.write(encoded)

    def _origin_is_trusted(self) -> bool:
        """Reject approval writes that were initiated by another site.

        A cross-site form POST carries the attacker's Origin. Requests with no
        Origin header at all are same-origin navigations from our own forms.
        """
        origin = self.headers.get("Origin")
        if origin is None:
            return True
        return origin in self.allowed_origins

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
            f"<form method='post' action='/approvals/approve'>"
            f"<input type='hidden' name='csrf_token' value='{escape(self.csrf_token)}'>"
            f"<input type='hidden' name='approval_id' value='{escape(item.approval_id)}'>"
            f"<input name='approver' required placeholder='Approver'><button>Approve</button></form>"
            f"<form method='post' action='/approvals/deny'>"
            f"<input type='hidden' name='csrf_token' value='{escape(self.csrf_token)}'>"
            f"<input type='hidden' name='approval_id' value='{escape(item.approval_id)}'>"
            f"<input name='approver' required placeholder='Approver'><button>Deny</button></form></article>"
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
        if not self._origin_is_trusted():
            self.send_error(403, "cross-origin approval request rejected")
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error(400, "invalid Content-Length")
            return
        form = parse_qs(self.rfile.read(length).decode("utf-8", errors="replace"))
        if not secrets.compare_digest(
            form.get("csrf_token", [""])[0] or "", self.csrf_token
        ):
            self.send_error(403, "missing or invalid CSRF token")
            return
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
        except ApprovalError as exc:
            # Surface the approval-policy message, never an internal traceback.
            self.send_error(400, str(exc))
            return
        self.send_response(303)
        self.send_header("Location", "/")
        self._security_headers()
        self.end_headers()


def build_server(path: str, host: str, port: int) -> ThreadingHTTPServer:
    """Create a dashboard server with per-instance state.

    Server state is bound on a generated subclass rather than mutated onto the
    shared Handler, so two servers can coexist in one process and tests do not
    leak state into each other.

    The trusted origins are derived from the address the OS actually bound, not
    the requested one, so `--port 0` and host aliases resolve correctly.
    """
    bound = type(
        "BoundHandler",
        (Handler,),
        {"store": TraceStore(path), "csrf_token": secrets.token_urlsafe(32)},
    )
    bound.approvals = ApprovalStore(bound.store)
    server = ThreadingHTTPServer((host, port), bound)
    bound_host, bound_port = server.server_address[0], server.server_address[1]
    bound.allowed_origins = frozenset(
        {f"http://{bound_host}:{bound_port}", f"https://{bound_host}:{bound_port}"}
    )
    return server


def serve(path: str, host: str, port: int) -> None:
    build_server(path, host, port).serve_forever()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", default="data/runtime.db")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    serve(args.db, args.host, args.port)
