"""A read-only local dashboard for recorded evidence.

Server-rendered and deliberately script-free. The Content-Security-Policy below
sets `default-src 'none'` with no `script-src`, so there is no way to run
JavaScript here even by accident. Every interactive affordance is native HTML:
`<details>` for expansion, forms for approval. That is a security property and
also the reason the layout cannot grow a client-side filter later without a
deliberate decision to relax the policy.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from safety_layer.observability.view import build_run_view
from safety_layer.policy.locks import ApprovalError, ApprovalStore
from safety_layer.storage.traces import TraceStore

_CHALLENGE_PAGE = (
    "<!doctype html><meta charset='utf-8'><title>Dashboard locked</title>"
    "<body style='font-family:system-ui;max-width:40rem;margin:4rem auto'>"
    "<h1>Dashboard locked</h1>"
    "<p>This dashboard holds run evidence and the approval queue, so every "
    "route requires the token printed when the server started.</p>"
    "<p>Open <code>/?token=&lt;token&gt;</code>, or send "
    "<code>Authorization: Bearer &lt;token&gt;</code>.</p>"
    "</body>"
)

_STYLE = """
:root{
  --bg:#f6f7f9; --panel:#ffffff; --ink:#1c2128; --muted:#5b6672; --line:#e2e6ea;
  --accent:#2f5fd0; --ok:#1a7f4b; --warn:#8a5a00; --bad:#b3261e; --warnbg:#fff6e0;
  --badbg:#fdeceb; --okbg:#e7f6ee; --accentbg:#eaf0fd; --radius:10px;
}
@media (prefers-color-scheme:dark){
  :root{
    --bg:#12151a; --panel:#1a1f26; --ink:#e6e9ee; --muted:#98a2b0; --line:#2a313a;
    --accent:#7aa2f7; --ok:#57c98a; --warn:#e0b050; --bad:#f2837c;
    --warnbg:#2e2513; --badbg:#33191a; --okbg:#142a20; --accentbg:#1b2740;
  }
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
  font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}
a{color:var(--accent)}
.wrap{max-width:1180px;margin:0 auto;padding:1.75rem 1.25rem 4rem}
h1{font-size:1.35rem;margin:0}
h2{font-size:.82rem;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);
  margin:2rem 0 .75rem;font-weight:650}
h3{font-size:.95rem;margin:0 0 .35rem}
p{margin:.35rem 0}
code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
pre{background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:.7rem;
  overflow:auto;max-height:22rem;font-size:.82rem;margin:.5rem 0 0}
.muted{color:var(--muted)}
.tiny{font-size:.8rem}
.topbar{display:flex;flex-wrap:wrap;gap:.75rem;align-items:baseline;
  justify-content:space-between;padding-bottom:1rem;border-bottom:1px solid var(--line)}
.runid{font-family:ui-monospace,monospace;font-size:.85rem;color:var(--muted)}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(132px,1fr));gap:.75rem}
.tile{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);padding:.7rem .85rem}
.tile dt{margin:0;font-size:.72rem;text-transform:uppercase;letter-spacing:.05em;color:var(--muted)}
.tile dd{margin:.2rem 0 0;font-size:1.3rem;font-weight:640;font-variant-numeric:tabular-nums}
.tile dd.small{font-size:1rem}
.layout{display:grid;grid-template-columns:220px 1fr;gap:1.5rem;margin-top:.5rem}
@media(max-width:820px){.layout{grid-template-columns:1fr}}
.runs{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:.4rem}
.runs a{display:block;padding:.5rem .65rem;border-radius:8px;border:1px solid var(--line);
  background:var(--panel);text-decoration:none;color:inherit;font-size:.85rem}
.runs a[aria-current="page"]{border-color:var(--accent);background:var(--accentbg)}
.runs .rid{font-family:ui-monospace,monospace;font-size:.76rem;display:block;
  overflow:hidden;text-overflow:ellipsis}
.card{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);
  padding:.85rem 1rem;margin-bottom:.7rem}
.card > summary{cursor:pointer;list-style:none;display:flex;flex-wrap:wrap;gap:.5rem;
  align-items:center;justify-content:space-between}
.card > summary::-webkit-details-marker{display:none}
.card > summary::before{content:"▸";color:var(--muted);font-size:.8rem}
.card[open] > summary::before{content:"▾"}
.badge{display:inline-block;padding:.1rem .5rem;border-radius:999px;font-size:.72rem;
  font-weight:640;letter-spacing:.02em;border:1px solid transparent;white-space:nowrap}
.b-ok{background:var(--okbg);color:var(--ok)}
.b-bad{background:var(--badbg);color:var(--bad)}
.b-warn{background:var(--warnbg);color:var(--warn)}
.b-info{background:var(--accentbg);color:var(--accent)}
.b-mute{background:var(--bg);color:var(--muted);border-color:var(--line)}
.meta{display:flex;flex-wrap:wrap;gap:.35rem .9rem;font-size:.78rem;color:var(--muted);
  margin-top:.4rem}
.kv{display:grid;grid-template-columns:auto 1fr;gap:.15rem .8rem;font-size:.85rem;margin-top:.5rem}
.kv dt{color:var(--muted)}
.kv dd{margin:0;font-family:ui-monospace,monospace;font-size:.8rem;word-break:break-all}
table{width:100%;border-collapse:collapse;font-size:.86rem;background:var(--panel);
  border:1px solid var(--line);border-radius:var(--radius);overflow:hidden}
th,td{padding:.5rem .7rem;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:.72rem;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);font-weight:650}
tr:last-child td{border-bottom:0}
table.wrap-table{overflow-x:auto}
.empty{color:var(--muted);font-size:.86rem;background:var(--panel);border:1px dashed var(--line);
  border-radius:var(--radius);padding:1rem;text-align:center}
form.inline{display:inline-flex;flex-wrap:wrap;gap:.4rem;align-items:center;margin:.6rem .5rem 0 0}
input,button{font:inherit;font-size:.85rem;padding:.35rem .6rem;border-radius:7px;
  border:1px solid var(--line);background:var(--panel);color:inherit}
button{background:var(--accent);color:#fff;border-color:transparent;cursor:pointer;font-weight:600}
button.deny{background:transparent;color:var(--bad);border-color:var(--bad)}
label{font-size:.8rem;color:var(--muted)}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:6px}
.alert{border-radius:var(--radius);padding:.7rem .9rem;margin:.75rem 0;font-size:.88rem;
  background:var(--warnbg);color:var(--warn);border:1px solid currentColor}
@media print{.layout{grid-template-columns:1fr}details{open:true}}
"""


def _json(value: object) -> str:
    return escape(json.dumps(value, indent=2, sort_keys=True, default=str))


def _tile(label: str, value: object, *, small: bool = False) -> str:
    cls = "small" if small else ""
    return (
        f"<div class='tile'><dt>{escape(label)}</dt>"
        f"<dd class='{cls}'>{escape(str(value))}</dd></div>"
    )


def _badge(text: str, kind: str) -> str:
    return f"<span class='badge b-{kind}'>{escape(text)}</span>"


def _status_badge(status: str) -> str:
    kind = {"blocked": "bad", "failed": "bad", "completed": "ok"}.get(status, "mute")
    return _badge(status or "unknown", kind)


def _state_badge(state: str) -> str:
    kind = {
        "done": "ok",
        "resolved": "ok",
        "pending": "warn",
        "failed": "bad",
        "unknown": "warn",
    }.get(state, "mute")
    return _badge(state or "unknown", kind)


def _empty(message: str) -> str:
    return f"<p class='empty'>{escape(message)}</p>"


def _render_runs(view: dict) -> str:
    if not view["runs"]:
        return _empty("No runs recorded yet.")
    items = []
    for run in view["runs"]:
        current = " aria-current='page'" if run["run_id"] == view["run_id"] else ""
        rid = run["run_id"][:12] + ("…" if len(run["run_id"]) > 12 else "")
        items.append(
            f"<li><a href='/?run={escape(run['run_id'])}'{current}>"
            f"<span class='rid'>{escape(rid)}</span>"
            f"<span>{_status_badge(run['status'])}</span>"
            f"<span class='muted tiny'>{run['steps']} steps"
            f"{' · ' + str(run['blocked']) + ' blocked' if run['blocked'] else ''}</span>"
            f"</a></li>"
        )
    return f"<ul class='runs'>{''.join(items)}</ul>"


def _render_traces(view: dict) -> str:
    if not view["traces"]:
        return _empty("No steps recorded for this run.")
    cards = []
    for trace in view["traces"]:
        flags = list(trace.get("flags") or [])
        prompt = trace.get("prompt")
        completion = trace.get("completion")
        bits = [
            _status_badge(str(trace.get("status") or "")),
            _badge(str(trace.get("enforcement") or "unknown"),
                   "info" if trace.get("enforcement") == "enforced" else "mute"),
        ]
        if flags:
            bits.append(_badge(", ".join(flags), "warn"))
        meta = [f"step {trace.get('step')}", f"event {trace.get('event')}"]
        if trace.get("cost_usd") is not None:
            meta.append(f"${float(trace['cost_usd']):.4f}")
        if trace.get("latency_ms") is not None:
            meta.append(f"{float(trace['latency_ms']):.0f} ms")
        if trace.get("tokens_in") is not None or trace.get("tokens_out") is not None:
            meta.append(f"{trace.get('tokens_in') or 0} in / {trace.get('tokens_out') or 0} out")

        rows = []
        if prompt is not None or completion is not None:
            state = str(trace.get("exchange_state") or "never_recorded")
            label = {
                "captured": "model exchange recorded",
                "pruned": "model exchange discarded by retention",
                "never_recorded": "no model exchange was recorded for this step",
            }.get(state, state)
            rows.append(f"<dt>Exchange</dt><dd>{escape(label)}</dd>")
            if prompt is not None:
                rows.append(f"<dt>Prompt</dt><dd>{_json(prompt)}</dd>")
            if completion is not None:
                rows.append(f"<dt>Completion</dt><dd>{_json(completion)}</dd>")
        for field in ("provider_metadata", "provider_evidence"):
            value = trace.get(field)
            if value:
                rows.append(f"<dt>{escape(field.replace('_', ' ').title())}</dt><dd>{_json(value)}</dd>")

        detail = ""
        if rows:
            detail = f"<dl class='kv'>{''.join(rows)}</dl>"
        cards.append(
            f"<details class='card' id='trace-{trace['id']}'>"
            f"<summary><span>{escape(str(trace.get('event') or 'step'))} "
            f"<span class='muted tiny'>#{trace.get('id')}</span></span>"
            f"<span>{' '.join(bits)}</span></summary>"
            f"<div class='meta'>{escape(' · '.join(meta))}</div>"
            f"<dl class='kv'><dt>Input</dt><dd>{_json(trace.get('input'))}</dd>"
            f"<dt>Output</dt><dd>{_json(trace.get('output'))}</dd></dl>"
            f"{detail}</details>"
        )
    return "".join(cards)


def _render_receipts(view: dict) -> str:
    if not view["receipts"]:
        return _empty(
            "No side-effect receipts for this run. Reads do not create one; "
            "a destructive action always does."
        )
    rows = []
    for receipt in view["receipts"]:
        state = str(receipt.get("state") or "")
        rows.append(
            "<tr>"
            f"<td><code>{escape(str(receipt.get('action') or ''))}</code>"
            f"<div class='muted tiny'>{escape(str(receipt.get('step_id') or ''))}</div></td>"
            f"<td>{_state_badge(state)}"
            f"<div class='muted tiny'>{escape(receipt['state_meaning'])}</div></td>"
            f"<td class='tiny'>{escape(str(receipt.get('effect_key') or '—'))}"
            f"<div class='muted tiny'>{escape(str(receipt.get('provider_ref') or ''))}</div></td>"
            f"<td><details><summary class='muted tiny'>arguments</summary>"
            f"<pre>{_json(receipt.get('arguments'))}</pre></details></td>"
            "</tr>"
        )
    return (
        "<div class='wrap-table'><table><thead><tr><th>Action</th><th>State</th>"
        "<th>Effect / reference</th><th>Arguments</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table></div>"
    )


def _render_approvals(pending: list) -> str:
    if not pending:
        return _empty("No approvals are waiting on a human.")
    cards = []
    for item in pending:
        cards.append(
            f"<div class='card'><h3>{escape(item.action)}</h3>"
            f"<div class='meta'><span>expires {escape(str(item.expires_at))}</span>"
            f"<span>id {escape(item.approval_id)}</span></div>"
            f"<pre>{_json(dict(item.arguments))}</pre>"
            f"<form class='inline' method='post' action='/approvals/approve'>"
            f"<input type='hidden' name='csrf_token' value='{escape(_CSRF[0])}'>"
            f"<input type='hidden' name='approval_id' value='{escape(item.approval_id)}'>"
            f"<label for='ap-{escape(item.approval_id)}'>Approver</label>"
            f"<input id='ap-{escape(item.approval_id)}' name='approver' required>"
            f"<button type='submit'>Approve</button></form>"
            f"<form class='inline' method='post' action='/approvals/deny'>"
            f"<input type='hidden' name='csrf_token' value='{escape(_CSRF[0])}'>"
            f"<input type='hidden' name='approval_id' value='{escape(item.approval_id)}'>"
            f"<label for='dn-{escape(item.approval_id)}'>Approver</label>"
            f"<input id='dn-{escape(item.approval_id)}' name='approver' required>"
            f"<button class='deny' type='submit'>Deny</button></form></div>"
        )
    return "".join(cards)


#: Per-process CSRF token, injected at build time. A one-element list so the
#: handler can read it without threading it through every render function.
_CSRF = [""]


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
    #: Bearer token required on every route. Printed at startup so the
    #: operator, and only the operator, can read the evidence.
    access_token: str
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

    def _send_auth_challenge(self) -> None:
        """401 with instructions, rather than a bare refusal.

        The token is printed to the operator's terminal at startup, so the
        remedy is always available without guessing.
        """
        body = _CHALLENGE_PAGE.encode("utf-8")
        self.send_response(401)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("WWW-Authenticate", 'Bearer realm="safety-dashboard"')
        self._security_headers()
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, payload: object, status: int = 200) -> None:
        encoded = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self._security_headers()
        self.end_headers()
        self.wfile.write(encoded)

    def _authorized(self, query: dict[str, list[str]] | None = None) -> bool:
        """Every route needs the per-process token.

        CSRF stops another site driving the browser. This stops any local
        process or user on the machine, which CSRF does not.
        """
        header = self.headers.get("Authorization", "")
        presented = header[7:] if header.startswith("Bearer ") else None
        if presented is None:
            presented = self.headers.get("X-Safety-Token") or None
        if presented is None and query:
            candidates = query.get("token") or [""]
            presented = candidates[0]
        if presented is None:
            return False
        return secrets.compare_digest(presented, self.access_token)

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
        query = parse_qs(parsed.query)
        if parsed.path not in {"/", "/api/state"}:
            self.send_error(404)
            return

        if not self._authorized(query):
            self._send_auth_challenge()
            return

        snapshot = self.store.dashboard_snapshot()
        if parsed.path == "/api/state":
            self._send_json(snapshot)
            return

        view = build_run_view(snapshot, query.get("run", [None])[0])
        pending = self.approvals.pending()
        body = self._render(view, pending)
        self._send_html(body)

    def _render(self, view: dict, pending: list) -> str:
        totals = view["totals"]
        budget = view.get("budget") or {}
        fuse = "TRIPPED" if budget.get("tripped") else "OK"

        banner = ""
        if totals["pending"]:
            banner = (
                f"<p class='alert'>{totals['pending']} effect "
                f"{'is' if totals['pending'] == 1 else 'are'} claimed with an unknown "
                "outcome. A retry is refused until each is resolved, because "
                "repeating an uncertain action is how a duplicate happens.</p>"
            )
        if not view["has_run"]:
            banner = _empty(
                "Nothing recorded yet. Run an agent through the safety layer, "
                "or open this page again after `safety run`."
            )

        gates = view["gates"]
        if gates:
            gate_rows = "".join(
                f"<tr><td>{_badge(str(g['verdict']), 'ok' if g['verdict'] == 'PASS' else 'bad')}</td>"
                f"<td>{float(g['score']):.4f}</td><td>{float(g['threshold']):.4f}</td></tr>"
                for g in gates
            )
            gate_block = (
                "<div class='wrap-table'><table><thead><tr><th>Verdict</th>"
                "<th>Score</th><th>Threshold</th></tr></thead>"
                f"<tbody>{gate_rows}</tbody></table></div>"
            )
        else:
            gate_block = _empty("No gate verdicts for this run.")

        approval_block = _render_approvals(pending)
        budget_block = (
            "<div class='wrap-table'><table><thead><tr><th>Steps</th><th>Spend</th>"
            "<th>Elapsed</th><th>Fuse</th></tr></thead><tbody><tr>"
            f"<td>{budget.get('steps_used', 0)}</td>"
            f"<td>${float(budget.get('dollars_used', 0.0)):.4f}</td>"
            f"<td>{float(budget.get('elapsed_seconds', 0.0)):.3f}s</td>"
            f"<td>{_badge(fuse, 'bad' if budget.get('tripped') else 'ok')}</td>"
            "</tr></tbody></table></div>"
            if budget
            else _empty("No budget recorded for this run.")
        )

        return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Agent Safety Layer — evidence</title><style>{_STYLE}</style></head>
<body><div class="wrap">
<div class="topbar">
  <h1>Agent Safety Layer</h1>
  <span class="runid">{escape(str(view['run_id'] or 'no run selected'))}</span>
</div>
<p class="muted">What the agent was allowed to do, what it tried, what a human approved,
and what landed. <span class="badge b-{'info' if view['enforcement'] == 'enforced' else 'mute'}">{escape(view['enforcement'])}</span></p>
{banner}
<div class="layout">
  <aside><h2>Runs</h2>{_render_runs(view)}</aside>
  <main>
    <h2>This run</h2>
    <dl class="tiles">
      {_tile('Steps', totals['steps'])}
      {_tile('Blocked', totals['blocked'])}
      {_tile('Receipts', totals['receipts'])}
      {_tile('Model calls', totals['model_calls'])}
      {_tile('Tokens', totals['tokens'])}
      {_tile('Cost', f"${totals['cost_usd']:.4f}")}
    </dl>

    <h2>Timeline</h2>
    {_render_traces(view)}

    <h2>Side-effect receipts</h2>
    {_render_receipts(view)}

    <h2>Approvals waiting</h2>
    {approval_block}

    <h2>Budget</h2>
    {budget_block}

    <h2>Gate history</h2>
    {gate_block}
  </main>
</div></div></body></html>"""

    def do_POST(self) -> None:
        if self.path not in {"/approvals/approve", "/approvals/deny"}:
            self.send_error(404)
            return
        if not self._authorized(parse_qs(self.path.partition("?")[2])):
            self.send_error(401, "dashboard token required")
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


def build_server(
    path: str, host: str, port: int, token: str | None = None
) -> tuple[ThreadingHTTPServer, type[Handler]]:
    """Create a dashboard server with per-instance state.

    State lives on a generated subclass rather than being mutated onto the
    shared Handler, so two servers can coexist in one process and tests do not
    leak state into each other.

    The trusted origins are derived from the address the OS actually bound, not
    the requested one, so `--port 0` and host aliases resolve correctly.
    """
    store = TraceStore(path)
    csrf_token = secrets.token_urlsafe(32)
    access_token = token or secrets.token_urlsafe(32)

    class BoundHandler(Handler):
        pass

    bound = BoundHandler
    bound.store = store
    bound.approvals = ApprovalStore(store)
    bound.csrf_token = csrf_token
    bound.access_token = access_token

    server = ThreadingHTTPServer((host, port), bound)
    # server_address is (host, port); decode because the socket family may
    # report the address as bytes.
    raw_host, raw_port = server.server_address[0], server.server_address[1]
    bound_host = raw_host.decode() if isinstance(raw_host, bytes) else str(raw_host)
    bound_port = int(raw_port)
    bound.allowed_origins = frozenset(
        {f"http://{bound_host}:{bound_port}", f"https://{bound_host}:{bound_port}"}
    )
    # The renderer reads the token from a module-level slot so it is not
    # threaded through every helper. Set here, per server, so two servers in one
    # process still get their own.
    _CSRF[0] = csrf_token
    return server, bound


def serve(path: str, host: str, port: int, token: str | None = None) -> None:
    """Start the dashboard, printing the access token to the operator.

    Binding beyond loopback is refused unless a token was supplied explicitly:
    an exposed dashboard without authentication would leak every trace and let
    anyone approve destructive actions.
    """
    resolved = token or os.environ.get("SAFETY_DASHBOARD_TOKEN")
    if host not in {"127.0.0.1", "localhost", "::1"} and not resolved:
        raise SystemExit(
            f"refusing to bind {host}: a dashboard reachable off-host needs an "
            "explicit SAFETY_DASHBOARD_TOKEN"
        )
    server, handler = build_server(path, host, port, resolved)
    print(f"Safety dashboard on http://{host}:{server.server_address[1]}/")
    print(f"access token: {handler.access_token}")
    print("Pass it as ?token=... or 'Authorization: Bearer ...'. Keep it private.")
    server.serve_forever()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", default="data/runtime.db")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    serve(args.db, args.host, args.port)
