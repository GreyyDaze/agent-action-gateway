"""A local dashboard for recorded evidence, and where a person acts.

Server-rendered. The only script is the short auto-refresh below; the
Content-Security-Policy allows that one script by its hash and nothing else, so
no other JavaScript can run here, not even an injected inline one. Every
interactive affordance is native HTML: `<details>` for expansion, forms for the
three moments a person is in the loop (approve or deny an action, settle a held
action, accept a changed tool).

The look follows a monochrome, high-density style: grey for structure, blue only
for the logo mark and links, green for OK, amber for waiting, red for refused or
urgent. No outside font or file is loaded (the policy allows none), so the font
falls back from Inter to the system font.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
from datetime import UTC, datetime
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, urlencode, urlparse

from agent_action_gateway.guards.redaction import redact
from agent_action_gateway.observability.view import build_run_view
from agent_action_gateway.policy.locks import Approval, ApprovalError, ApprovalStore
from agent_action_gateway.storage.traces import TraceStore

if TYPE_CHECKING:
    from agent_action_gateway.integrations.mcp_proxy import PinStore

#: The session cookie set after the token is presented once. HttpOnly, so a page
#: cannot read it; SameSite=Strict, so another site's form cannot send it.
_COOKIE = "agw_session"

_CHALLENGE_PAGE = (
    "<!doctype html><meta charset='utf-8'><title>Dashboard locked</title>"
    "<body style='font-family:-apple-system,system-ui,sans-serif;max-width:40rem;"
    "margin:4rem auto;color:#111827'>"
    "<h1 style='font-size:20px'>Dashboard locked</h1>"
    "<p>This dashboard holds run evidence and the approval queue, so every "
    "route requires the token printed when the server started.</p>"
    "<p>Open <code>/?token=&lt;token&gt;</code> once, or send "
    "<code>Authorization: Bearer &lt;token&gt;</code>.</p>"
    "</body>"
)

#: Reload every 10 seconds so new approvals show up, but never while a person is
#: in the middle of something: typing, a field filled in, a step opened, or the
#: tab hidden. The scroll position is kept across the reload.
_REFRESH_JS = (
    "(function(){var m=document.querySelector('main'),k='agw-scroll';"
    "try{var y=sessionStorage.getItem(k);if(m&&y){m.scrollTop=+y;}"
    "sessionStorage.removeItem(k);}catch(e){}"
    "function busy(){var a=document.activeElement;"
    "if(a&&/^(INPUT|TEXTAREA|SELECT|BUTTON)$/.test(a.tagName))return true;"
    "if(document.querySelector('details[open]'))return true;"
    "var f=document.querySelectorAll('input[type=text]');"
    "for(var i=0;i<f.length;i++){if(f[i].value)return true;}return false;}"
    "setInterval(function(){if(document.hidden||busy())return;"
    "try{if(m)sessionStorage.setItem(k,String(m.scrollTop));}catch(e){}"
    "location.reload();},10000);})();"
)
_REFRESH_HASH = base64.b64encode(hashlib.sha256(_REFRESH_JS.encode()).digest()).decode()

_STYLE = """
:root{
  --primary:#005DFF; --primary-hover:#004AD6;
  --canvas:#FFFFFF; --surface:#FFFFFF; --subtle:#EEEEF1; --muted-bg:#F4F4F5;
  --border-layout:#EEEEEE; --border-card:#E5E7EB; --border-control:#E5E5E7;
  --text-main:#111827; --text-body:#374151; --text-muted:#6B7280; --text-subtle:#9CA3AF;
  --ok:#027A48; --ok-bg:#ECFDF3;
  --wait:#785B12; --wait-bg:#FEF9E6; --wait-border:#F3E7BE;
  --bad:#B42318; --bad-bg:#FEF3F2; --urgent:#EF4444;
  --shadow-control:0 1px 2px rgba(0,0,0,.02); --shadow-card:0 1px 3px rgba(0,0,0,.03);
}
*{box-sizing:border-box}
html,body{height:100%}
/* Only the content area and the sidebar scroll, so a sidebar link never moves the topbar. */
@media (min-width:861px){html,body{overflow:hidden}}
.group,.section{scroll-margin-top:16px}
body{margin:0;background:var(--canvas);color:var(--text-main);
  font:15px/1.55 'Inter',-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
  -webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale;
  display:flex;flex-direction:column}
a{color:var(--primary);text-decoration:none}
a:hover{color:var(--primary-hover)}
code,pre,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
:focus-visible{outline:2px solid var(--text-main);outline-offset:2px;border-radius:6px}

.topbar{height:56px;flex:none;display:flex;align-items:center;justify-content:space-between;
  padding:0 24px;border-bottom:1px solid var(--border-layout);background:var(--surface)}
.brand{display:flex;align-items:center;gap:10px;font-weight:600;font-size:16px;min-width:0}
.brand svg{flex:none}
.slash{color:#E2E4E8;font-weight:300}
.crumb{color:var(--text-muted);font-size:14px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.top-right{display:flex;align-items:center;gap:8px;flex:none}
.pill{display:inline-flex;align-items:center;gap:6px;height:30px;background:#F2F2F5;
  border-radius:8px;padding:0 12px;font-size:13px;font-weight:600;color:var(--text-body);
  white-space:nowrap}
a.pill:hover{background:var(--subtle);color:var(--text-main)}
.pill.ok{background:var(--ok-bg);color:var(--ok)}
.pill.wait{background:var(--wait-bg);color:var(--wait);box-shadow:inset 0 0 0 1px var(--wait-border)}
.count{display:inline-flex;align-items:center;justify-content:center;min-width:20px;height:20px;
  padding:0 6px;border-radius:999px;background:var(--urgent);color:#fff;font-size:12px;font-weight:700}

.shell{flex:1;display:flex;min-height:0}
.sidebar{width:256px;flex:none;border-right:1px solid var(--border-layout);background:var(--surface);
  overflow-y:auto;padding:16px 12px}
.super{font-size:12px;font-weight:500;color:var(--text-muted);margin:16px 12px 8px;
  text-transform:uppercase;letter-spacing:.04em}
.super:first-child{margin-top:2px}
.nav{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:2px}
.nav a{display:flex;align-items:center;justify-content:space-between;gap:8px;height:40px;
  padding:0 12px;border-radius:8px;color:#2E333D;font-weight:500;font-size:15px}
.nav a:hover{background:var(--muted-bg)}
.nav a[aria-current="page"]{background:var(--subtle);color:var(--text-main);font-weight:600}
.nav .rid{font-family:ui-monospace,monospace;font-size:13px;overflow:hidden;text-overflow:ellipsis;
  white-space:nowrap}
.dot{width:8px;height:8px;border-radius:999px;flex:none;background:var(--text-subtle)}
.dot.ok{background:#12B76A}.dot.bad{background:var(--urgent)}.dot.wait{background:#E0B43A}

main{flex:1;overflow-y:auto;min-width:0;position:relative}
.canvas{max-width:1140px;margin:0 auto;padding:32px 32px 64px}
.section{margin-top:40px}
.section:first-child{margin-top:0}
h1{font-size:24px;font-weight:700;letter-spacing:-.015em;margin:0}
h2{font-size:17px;font-weight:600;margin:0 0 12px;color:var(--text-main);display:flex;
  align-items:center;gap:8px}
.lede{color:var(--text-muted);margin:4px 0 16px}
.group{margin-top:20px}

.card{border:1px solid var(--border-card);border-radius:18px;background:var(--surface);
  box-shadow:var(--shadow-card);padding:20px 24px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px}
.metric .label{font-size:14px;font-weight:500;color:#344054}
.metric .value{font-size:30px;font-weight:700;letter-spacing:-.02em;color:#101828;
  margin-top:8px;font-variant-numeric:tabular-nums;line-height:1.1}
.metric .value.none{font-size:16px;font-weight:500;color:var(--text-subtle);letter-spacing:0;
  margin-top:14px}
.none{color:var(--text-subtle)}
.stack{display:flex;flex-direction:column;gap:12px}
.item{border:1px solid var(--border-card);border-radius:14px;background:var(--surface);
  box-shadow:var(--shadow-card);padding:20px 24px}
.item-head{display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:8px}
.item-title{font-weight:600;font-size:16px}
.meta{display:flex;flex-wrap:wrap;gap:4px 14px;color:var(--text-muted);font-size:14px;margin-top:6px}
.meta b{color:var(--text-body);font-weight:600}
.mi{display:inline-flex;align-items:center;gap:6px}
.mi .icon{color:var(--text-subtle)}

.badge{display:inline-flex;align-items:center;gap:4px;padding:2px 10px;border-radius:6px;font-size:13px;font-weight:500;
  white-space:nowrap;background:var(--muted-bg);color:var(--text-body)}
.b-ok{background:var(--ok-bg);color:var(--ok)}
.b-wait{background:var(--wait-bg);color:var(--wait);box-shadow:inset 0 0 0 1px var(--wait-border)}
.b-bad{background:var(--bad-bg);color:var(--bad)}

pre{background:#FAFAFB;border:1px solid var(--border-layout);border-radius:8px;padding:12px;
  overflow:auto;max-height:22rem;font-size:13px;margin:8px 0 0;color:var(--text-body)}
details > summary{cursor:pointer;list-style:none}
details > summary::-webkit-details-marker{display:none}
details.step > summary{display:flex;flex-wrap:wrap;gap:8px;align-items:center;justify-content:space-between}
details.step > summary > .icon{color:var(--text-muted);transition:transform .15s}
details.step[open] > summary > .icon{transform:rotate(90deg)}
details.step > summary > .step-title{margin-right:auto}
.kv{display:grid;grid-template-columns:auto 1fr;gap:6px 16px;font-size:14px;margin-top:8px}
.kv dt{color:var(--text-muted)}
.kv dd{margin:0;min-width:0}

.table-wrap{border:1px solid var(--border-card);border-radius:14px;overflow:auto;background:var(--surface);
  box-shadow:var(--shadow-card)}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{padding:12px 16px;text-align:left;border-bottom:1px solid var(--border-layout);vertical-align:top}
th{font-size:13px;font-weight:500;color:var(--text-muted);background:#FAFAFB}
tr:last-child td{border-bottom:0}
.empty{display:flex;align-items:center;justify-content:center;gap:8px;
  min-height:120px;color:var(--text-subtle);font-size:14px;border:1px dashed var(--border-card);border-radius:14px;
  padding:12px 20px;text-align:center;margin:0}
.alert{border-radius:14px;padding:12px 16px;font-size:14px;background:var(--wait-bg);color:var(--wait);
  border:1px solid var(--wait-border);margin:0 0 12px}

form.act{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-top:16px}
input[type=text]{font:inherit;font-size:14px;height:40px;padding:0 12px;border-radius:8px;
  border:1px solid var(--border-control);background:var(--surface);color:var(--text-main);min-width:0}
input[type=text]::placeholder{color:var(--text-subtle)}
button{font:inherit;font-size:14px;font-weight:500;height:40px;padding:0 16px;border-radius:8px;
  border:1px solid var(--border-control);background:var(--surface);color:var(--text-main);
  cursor:pointer;box-shadow:var(--shadow-control)}
button{display:inline-flex;align-items:center;gap:6px}
button:hover{background:var(--muted-bg)}
.icon{flex:none}
h2 .icon{color:var(--text-muted)}
button.primary{background:var(--text-main);color:#fff;border-color:var(--text-main)}
button.primary:hover{background:#1F2937}
.seg{display:inline-flex;border:1px solid var(--border-control);border-radius:8px;overflow:hidden;
  box-shadow:var(--shadow-control)}
.seg button{border:0;border-radius:0;box-shadow:none;height:38px}
.seg button + button{border-left:1px solid var(--border-control)}
.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0)}

.brand > span{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
@media (max-width:860px){
  .crumb,.slash{display:none}
  .shell{flex-direction:column}
  .sidebar{width:auto;border-right:0;border-bottom:1px solid var(--border-layout);max-height:40vh}
  .canvas{padding:16px 16px 48px}
}
@media print{.sidebar,.topbar,form.act{display:none}}
"""

_LOGO = (
    "<svg width='20' height='20' viewBox='0 0 15 15' aria-hidden='true'>"
    "<rect width='15' height='15' rx='4' fill='#005DFF'/>"
    "<path d='M4 8l2.3 2.3L11 5' fill='none' stroke='#fff' stroke-width='1.8' "
    "stroke-linecap='round' stroke-linejoin='round'/></svg>"
)


#: Icons from Lucide (lucide.dev, ISC license), inline so the page loads no
#: outside files. They use currentColor, so they stay monochrome.
_ICONS = {
    "shield": "<path d='M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 "
    "1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z'/>"
    "<path d='m9 12 2 2 4-4'/>",
    "alert": "<path d='m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3'/>"
    "<path d='M12 9v4'/><path d='M12 17h.01'/>",
    "wrench": "<path d='M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 "
    "7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z'/>",
    "activity": "<path d='M22 12h-4l-3 9L9 3l-3 9H2'/>",
    "receipt": "<path d='M4 2v20l2-1 2 1 2-1 2 1 2-1 2 1 2-1 2 1V2l-2 1-2-1-2 1-2-1-2 1-2-1-2 1Z'/>"
    "<path d='M16 8h-6'/><path d='M16 12h-6'/><path d='M12 16h-2'/>",
    "gauge": "<path d='m12 14 4-4'/><path d='M3.34 19a10 10 0 1 1 17.32 0'/>",
    "flag": "<path d='M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z'/>"
    "<path d='M4 22v-7'/>",
    "history": "<path d='M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8'/><path d='M3 3v5h5'/>"
    "<path d='M12 7v5l4 2'/>",
    "check": "<path d='M20 6 9 17l-5-5'/>",
    "chevron": "<path d='m9 18 6-6-6-6'/>",
    "server": "<rect width='20' height='8' x='2' y='2' rx='2'/><rect width='20' height='8' x='2' "
    "y='14' rx='2'/><path d='M6 6h.01'/><path d='M6 18h.01'/>",
    "hash": "<path d='M4 9h16'/><path d='M4 15h16'/><path d='M10 3 8 21'/><path d='M16 3l-2 18'/>",
    "clock": "<circle cx='12' cy='12' r='10'/><path d='M12 6v6l4 2'/>",
    "inbox": "<path d='M22 12h-6l-2 3h-4l-2-3H2'/><path d='M5.45 5.11 2 12v6a2 2 0 0 0 2 "
    "2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z'/>",
    "x": "<path d='M18 6 6 18'/><path d='m6 6 12 12'/>",
}


def _icon(name: str, size: int = 18) -> str:
    return (
        f"<svg class='icon' width='{size}' height='{size}' viewBox='0 0 24 24' fill='none' "
        "stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round' "
        f"aria-hidden='true'>{_ICONS[name]}</svg>"
    )


def _json(value: object) -> str:
    return escape(json.dumps(value, indent=2, sort_keys=True, default=str))


#: The icon follows the state, so a badge reads the same without colour.
_BADGE_ICONS = {"ok": "check", "wait": "clock", "bad": "x"}


def _badge(text: str, kind: str = "", icon: str | None = None) -> str:
    cls = f"badge b-{kind}" if kind else "badge"
    name = icon or _BADGE_ICONS.get(kind)
    mark = _icon(name, 13) if name else ""
    return f"<span class='{cls}'>{mark}{escape(text)}</span>"


def _status_kind(status: str) -> str:
    return {"blocked": "bad", "failed": "bad", "completed": "ok"}.get(status, "")


def _status_badge(status: str) -> str:
    return _badge(status or "unknown", _status_kind(status))


def _state_badge(state: str) -> str:
    kind = {"done": "ok", "resolved": "ok", "pending": "wait", "failed": "bad",
            "unknown": "wait"}.get(state, "")
    return _badge(state or "unknown", kind)


def _empty(message: str) -> str:
    return f"<p class='empty'>{_icon('inbox', 16)}{escape(message)}</p>"


def _count(number: int) -> str:
    return f"<span class='count'>{number}</span>" if number else ""


def _meta_item(icon: str, body: str, title: str = "") -> str:
    """One fact in a card's meta line: an icon, then the value."""
    tip = f" title='{escape(title)}'" if title else ""
    return f"<span class='mi'{tip}>{_icon(icon, 15)}{body}</span>"


def _run_link(run_id: str) -> str:
    if not run_id:
        return "—"
    return (
        f"<a class='mono' href='/?{escape(urlencode({'run': run_id}))}' title='{escape(run_id)}'>"
        f"run {escape(run_id[:8])}</a>"
    )


def _expires(value: object) -> str:
    """`expires in 14 min`; the exact time goes in the tooltip."""
    try:
        moment = datetime.fromisoformat(str(value))
    except ValueError:
        return f"expires {_when(value)}"
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    minutes = int((moment - datetime.now(UTC)).total_seconds() // 60)
    if minutes < 1:
        return "expires in under a minute"
    return f"expires in {minutes} min"


def _protection_pill(protected: bool) -> str:
    if protected:
        return (
            "<span class='pill ok' title='Every step went through the checks'>"
            f"{_icon('shield', 15)}protected</span>"
        )
    return (
        "<span class='pill wait' title='Steps were recorded, not checked'>"
        f"{_icon('alert', 15)}recorded only</span>"
    )


def _spend(value: Any) -> str:
    """Budget spend. Zero means no step reported a cost, so say that."""
    amount = float(value or 0.0)
    if amount == 0:
        return "<span class='none' title='No step reported a cost (estimated_cost_usd)'>not reported</span>"
    return f"${amount:.4f}"


def _short(text: str, size: int = 12) -> str:
    return text[:size] + ("…" if len(text) > size else "")


def _when(value: object) -> str:
    """ISO time as `YYYY-MM-DD HH:MM UTC`, or the text as given."""
    text = str(value or "")
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        return text or "—"
    if moment.tzinfo is not None:
        moment = moment.astimezone(UTC)
    return moment.strftime("%Y-%m-%d %H:%M UTC")


def _csrf_field() -> str:
    return f"<input type='hidden' name='csrf_token' value='{escape(_CSRF[0])}'>"


def _name_field(field_id: str, placeholder: str = "Your name") -> str:
    return (
        f"<label class='sr' for='{escape(field_id)}'>{escape(placeholder)}</label>"
        f"<input type='text' id='{escape(field_id)}' name='approver' required "
        f"placeholder='{escape(placeholder)}' autocomplete='name'>"
    )


# -- the "needs you" panels ---------------------------------------------------


def _render_approvals(pending: list[Approval]) -> str:
    if not pending:
        return _empty("No approvals are waiting on a human.")
    cards = []
    for item in pending:
        context = item.context or {}
        risk = str(context.get("risk") or "")
        run_id = str(context.get("run_id") or "")
        aid = escape(item.approval_id)
        cards.append(
            "<div class='item'>"
            "<div class='item-head'>"
            f"<span class='item-title mono'>{escape(item.action)}</span>"
            f"<span>{_badge(risk or 'risk not recorded', 'bad' if risk == 'destructive' else '', 'alert' if risk == 'destructive' else None)}</span>"
            "</div>"
            "<div class='meta'>"
            + _meta_item("server", f"<b>{escape(str(context.get('environment') or '—'))}</b>",
                         "environment")
            + _meta_item("hash", _run_link(run_id))
            + _meta_item("clock", escape(_expires(item.expires_at)), _when(item.expires_at))
            + "</div>"
            f"<pre>{_json(redact(dict(item.arguments)))}</pre>"
            "<form class='act' method='post' action='/approvals/approve'>"
            f"{_csrf_field()}<input type='hidden' name='approval_id' value='{aid}'>"
            f"{_name_field('ap-' + item.approval_id)}"
            f"<button class='primary' type='submit'>{_icon('check', 16)}Approve</button>"
            f"<button type='submit' formaction='/approvals/deny'>{_icon('x', 16)}Deny</button>"
            "</form></div>"
        )
    return f"<div class='stack'>{''.join(cards)}</div>"


def _render_held(view: dict) -> str:
    held = view.get("held") or []
    if not held:
        return _empty("No held actions: every claimed action has a known outcome.")
    rows = []
    for receipt in held:
        key = str(receipt.get("intent_key") or "")
        run_id = str(receipt.get("run_id") or "")
        rows.append(
            "<div class='item'>"
            "<div class='item-head'>"
            f"<span class='item-title mono'>{escape(str(receipt.get('action') or ''))}</span>"
            f"{_state_badge(str(receipt.get('state') or ''))}"
            "</div>"
            "<div class='meta'>"
            + _meta_item("alert", escape(str(receipt.get('state_meaning') or '')))
            + _meta_item("hash", _run_link(run_id))
            + _meta_item("clock", "since " + escape(_when(receipt.get('created_at'))))
            + "</div>"
            f"<pre>{_json(redact(receipt.get('arguments') or {}))}</pre>"
            "<p class='meta'>Check the real system first. Then say what happened.</p>"
            "<form class='act' method='post' action='/receipts/settle'>"
            f"{_csrf_field()}<input type='hidden' name='intent_key' value='{escape(key)}'>"
            f"{_name_field('st-' + key)}"
            f"<label class='sr' for='ref-{escape(key)}'>Reference (optional)</label>"
            f"<input type='text' id='ref-{escape(key)}' name='ref' placeholder='Reference (optional)'>"
            "<span class='seg'>"
            f"<button type='submit' name='outcome' value='done'>{_icon('check', 16)}It happened</button>"
            f"<button type='submit' name='outcome' value='failed'>{_icon('x', 16)}It did not happen</button>"
            "</span></form></div>"
        )
    return f"<div class='stack'>{''.join(rows)}</div>"


def _render_tools(waiting: list[tuple[str, str]] | None) -> str:
    if waiting is None:
        return _empty("No MCP proxy data in this database.")
    if not waiting:
        return _empty("No tools are waiting: every tool the proxy shows was accepted.")
    rows = []
    for tool, why in waiting:
        rows.append(
            "<div class='item'>"
            "<div class='item-head'>"
            f"<span class='item-title mono'>{escape(tool)}</span>{_badge(why, 'wait')}"
            "</div>"
            "<p class='meta'>Hidden from the agent until a person accepts it. Check the "
            "server's change first; a changed definition can change what the tool does.</p>"
            "<form class='act' method='post' action='/tools/accept'>"
            f"{_csrf_field()}<input type='hidden' name='tool' value='{escape(tool)}'>"
            f"{_name_field('tl-' + tool)}"
            f"<button class='primary' type='submit'>{_icon('check', 16)}Accept</button>"
            "</form></div>"
        )
    return f"<div class='stack'>{''.join(rows)}</div>"


# -- the run ------------------------------------------------------------------


def _render_runs(view: dict) -> str:
    if not view["runs"]:
        return _empty("No runs recorded yet.")
    items = []
    for run in view["runs"]:
        current = " aria-current='page'" if run["run_id"] == view["run_id"] else ""
        kind = _status_kind(run["status"])
        items.append(
            f"<li><a href='/?{escape(urlencode({'run': run['run_id']}))}'{current} "
            f"title='{escape(run['run_id'])} · {escape(run['status'])} · {run['steps']} steps'>"
            f"<span class='rid'>{escape(_short(run['run_id'], 14))}</span>"
            f"<span class='dot {kind}' aria-label='{escape(run['status'])}'></span>"
            "</a></li>"
        )
    return f"<ul class='nav'>{''.join(items)}</ul>"


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
            _badge(str(trace.get("enforcement") or "unknown")),
        ]
        if flags:
            bits.append(_badge(", ".join(flags), "wait"))
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
                rows.append(f"<dt>Prompt</dt><dd><pre>{_json(prompt)}</pre></dd>")
            if completion is not None:
                rows.append(f"<dt>Completion</dt><dd><pre>{_json(completion)}</pre></dd>")
        for field in ("provider_metadata", "provider_evidence"):
            value = trace.get(field)
            if value:
                rows.append(
                    f"<dt>{escape(field.replace('_', ' ').title())}</dt>"
                    f"<dd><pre>{_json(value)}</pre></dd>"
                )

        cards.append(
            f"<details class='item step' id='trace-{trace['id']}'>"
            f"<summary>{_icon('chevron', 16)}<span class='step-title'><b>{escape(str(trace.get('event') or 'step'))}</b> "
            f"<span class='meta' style='display:inline'>#{trace.get('id')}</span></span>"
            f"<span>{' '.join(bits)}</span></summary>"
            f"<div class='meta'>{escape(' · '.join(meta))}</div>"
            f"<dl class='kv'><dt>Input</dt><dd><pre>{_json(trace.get('input'))}</pre></dd>"
            f"<dt>Output</dt><dd><pre>{_json(trace.get('output'))}</pre></dd>"
            f"{''.join(rows)}</dl></details>"
        )
    return f"<div class='stack'>{''.join(cards)}</div>"


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
            f"<div class='meta'>{escape(str(receipt.get('step_id') or ''))}</div></td>"
            f"<td>{_state_badge(state)}"
            f"<div class='meta'>{escape(receipt['state_meaning'])}</div></td>"
            f"<td class='mono'>{escape(str(receipt.get('effect_key') or '—'))}"
            f"<div class='meta'>{escape(str(receipt.get('provider_ref') or ''))}</div></td>"
            f"<td><details><summary class='meta'>arguments</summary>"
            f"<pre>{_json(redact(receipt.get('arguments') or {}))}</pre></details></td>"
            "</tr>"
        )
    return (
        "<div class='table-wrap'><table><thead><tr><th>Action</th><th>State</th>"
        "<th>Effect / reference</th><th>Arguments</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table></div>"
    )


def _render_history(decided: list[Approval]) -> str:
    if not decided:
        return _empty("No approval has been given or denied yet.")
    rows = []
    for item in decided:
        context = item.context or {}
        kind = "ok" if item.decision == "approved" else "bad"
        used = "used" if item.consumed_at else ("not used" if item.decision == "approved" else "—")
        rows.append(
            "<tr>"
            f"<td><code>{escape(item.action)}</code>"
            f"<div class='meta'>{escape(str(context.get('risk') or ''))}"
            f"{' · ' + escape(str(context.get('environment'))) if context.get('environment') else ''}"
            "</div></td>"
            f"<td>{_badge(item.decision, kind)}</td>"
            f"<td>{escape(str(item.approver or '—'))}</td>"
            f"<td>{escape(_when(item.decided_at))}</td>"
            f"<td>{escape(used)}</td>"
            "</tr>"
        )
    return (
        "<div class='table-wrap'><table><thead><tr><th>Action</th><th>Decision</th>"
        "<th>By (as typed)</th><th>When</th><th>Approval</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table></div>"
    )


#: Per-process CSRF token, injected at build time. A one-element list so the
#: handler can read it without threading it through every render function.
_CSRF = [""]

#: The POST endpoints. Every one is a person's decision, so every one needs the
#: token, a trusted origin and the CSRF token.
_ACTIONS = frozenset({"/approvals/approve", "/approvals/deny", "/receipts/settle", "/tools/accept"})


class Handler(BaseHTTPRequestHandler):
    """Evidence viewer with an explicit write boundary for a person's decisions.

    Approving, settling a held action and accepting a tool are the human trust
    boundary of the whole product, so a POST must not be forgeable by another
    web page. Every form carries a per-process CSRF token, POSTs must come from
    a trusted origin, and the session cookie is SameSite=Strict.
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
        # same-origin, not no-referrer: with no-referrer a browser sends
        # `Origin: null` on our own form posts, and the origin check then
        # refuses every real approval. Other sites still receive nothing.
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("Cache-Control", "no-store")
        self.send_header(
            "Content-Security-Policy",
            f"default-src 'none'; script-src 'sha256-{_REFRESH_HASH}';"
            " style-src 'unsafe-inline'; form-action 'self';"
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
        self.send_header("WWW-Authenticate", 'Bearer realm="agent-action-gateway"')
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

    def _redirect(self, location: str, *, set_session: bool = False) -> None:
        self.send_response(303)
        self.send_header("Location", location)
        if set_session:
            self.send_header(
                "Set-Cookie",
                f"{_COOKIE}={self.access_token}; HttpOnly; SameSite=Strict; Path=/",
            )
        self._security_headers()
        self.end_headers()

    def _cookie_token(self) -> str | None:
        for part in (self.headers.get("Cookie") or "").split(";"):
            name, _, value = part.strip().partition("=")
            if name == _COOKIE and value:
                return value
        return None

    def _authorized(self, query: dict[str, list[str]] | None = None) -> bool:
        """Every route needs the per-process token.

        Accepted as a bearer header, the session cookie, or `?token=` (which
        the GET handler swaps for the cookie straight away). CSRF stops another
        site driving the browser. This stops any local process or user on the
        machine, which CSRF does not.
        """
        header = self.headers.get("Authorization", "")
        presented = header[7:] if header.startswith("Bearer ") else None
        if presented is None:
            presented = self.headers.get("X-Safety-Token") or None
        if presented is None:
            presented = self._cookie_token()
        if presented is None and query:
            candidates = query.get("token") or [""]
            presented = candidates[0]
        if presented is None:
            return False
        return secrets.compare_digest(presented, self.access_token)

    def _origin_is_trusted(self) -> bool:
        """Reject writes that were initiated by another site.

        A cross-site form POST carries the attacker's Origin. Requests with no
        Origin header at all are same-origin navigations from our own forms.
        """
        origin = self.headers.get("Origin")
        if origin is None:
            return True
        return origin in self.allowed_origins

    def _pins(self) -> PinStore | None:
        """The proxy's pin store, when this database is a proxy's. None otherwise."""
        if not self.store._table_exists("mcp_tool_pins"):
            return None
        from agent_action_gateway.integrations.mcp_proxy import PinStore

        return PinStore(self.store.path)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        if parsed.path not in {"/", "/api/state"}:
            self.send_error(404)
            return

        if not self._authorized(query):
            self._send_auth_challenge()
            return

        if "token" in query and parsed.path == "/":
            # Swap the token in the address bar for an HttpOnly cookie, so it
            # leaves the URL (history, screenshots) and the forms work.
            rest = {k: v[0] for k, v in query.items() if k != "token" and v}
            self._redirect("/" + (f"?{urlencode(rest)}" if rest else ""), set_session=True)
            return

        snapshot = self.store.dashboard_snapshot()
        if parsed.path == "/api/state":
            self._send_json(snapshot)
            return

        view = build_run_view(snapshot, query.get("run", [None])[0])
        pins = self._pins()
        body = self._render(
            view,
            self.approvals.waiting(),
            decided=self.approvals.decided(),
            tools=None if pins is None else pins.waiting(),
        )
        self._send_html(body)

    def _render(
        self,
        view: dict,
        pending: list,
        *,
        decided: list | None = None,
        tools: list[tuple[str, str]] | None = None,
    ) -> str:
        totals = view["totals"]
        budget = view.get("budget") or {}
        held = view.get("held") or []
        needs_you = len(pending) + len(held) + len(tools or [])

        if not view["has_run"]:
            run_intro = _empty(
                "Nothing recorded yet. Run an agent through a session, "
                "then open this page again."
            )
        else:
            run_intro = ""
        if held:
            held_note = (
                f"<p class='alert'>{len(held)} action{'' if len(held) == 1 else 's'} "
                f"{'has' if len(held) == 1 else 'have'} an unknown outcome. The same "
                "action is refused until a person settles it, because repeating an "
                "uncertain action is how a duplicate happens.</p>"
            )
        else:
            held_note = ""

        gates = view["gates"]
        if gates:
            gate_rows = "".join(
                f"<tr><td>{_badge(str(g['verdict']), 'ok' if g['verdict'] == 'PASS' else 'bad')}</td>"
                f"<td>{float(g['score']):.4f}</td><td>{float(g['threshold']):.4f}</td></tr>"
                for g in gates
            )
            gate_block = (
                "<div class='table-wrap'><table><thead><tr><th>Verdict</th>"
                "<th>Score</th><th>Threshold</th></tr></thead>"
                f"<tbody>{gate_rows}</tbody></table></div>"
            )
        else:
            gate_block = _empty("No gate verdicts for this run.")

        if budget:
            fuse = "tripped" if budget.get("tripped") else "ok"
            budget_block = (
                "<div class='table-wrap'><table><thead><tr><th>Steps</th><th>Spend</th>"
                "<th>Elapsed</th><th>Limits</th></tr></thead><tbody><tr>"
                f"<td>{budget.get('steps_used', 0)}</td>"
                f"<td>{_spend(budget.get('dollars_used'))}</td>"
                f"<td>{float(budget.get('elapsed_seconds', 0.0)):.3f}s</td>"
                f"<td>{_badge(fuse, 'bad' if budget.get('tripped') else 'ok')}</td>"
                "</tr></tbody></table></div>"
            )
        else:
            budget_block = _empty("No budget recorded for this run.")

        protected = view["enforcement"] == "enforced"
        run_id = str(view["run_id"] or "no run selected")

        def metric(label: str, value: object) -> str:
            if value is None:
                shown = "<div class='value none' title='Your agent did not report this. "
                shown += "See record_model_exchange, or the proxy&#39;s /usage.'>not reported</div>"
            else:
                shown = f"<div class='value'>{escape(str(value))}</div>"
            return f"<div class='card metric'><div class='label'>{escape(label)}</div>{shown}</div>"

        reported = totals["model_calls"] > 0
        cost = totals["cost_usd"]

        return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light">
<title>Agent Action Gateway</title><style>{_STYLE}</style></head>
<body>
<header class="topbar">
  <div class="brand">{_LOGO}<span>Agent Action Gateway</span>
    <span class="slash">/</span><span class="crumb mono">{escape(_short(run_id, 24))}</span></div>
  <div class="top-right">
    <a href="#needs-you" class="pill">Needs you {_count(needs_you)}</a>
    {_protection_pill(protected)}
  </div>
</header>
<div class="shell">
  <nav class="sidebar" aria-label="Sections and runs">
    <div class="super">Sections</div>
    <ul class="nav">
      <li><a href="#needs-you">Needs you {_count(needs_you)}</a></li>
      <li><a href="#this-run">This run</a></li>
      <li><a href="#timeline">Timeline</a></li>
      <li><a href="#receipts">Receipts</a></li>
      <li><a href="#history">Approval history</a></li>
    </ul>
    <div class="super">Runs</div>
    {_render_runs(view)}
  </nav>
  <main><div class="canvas">

  <section class="section" id="needs-you">
    <h1>Needs you</h1>
    <p class="lede">The three moments a person is in the loop. Nothing here runs until you act.</p>
    <div class="group"><h2>{_icon('shield')}Approvals waiting {_count(len(pending))}</h2>{_render_approvals(pending)}</div>
    <div class="group"><h2>{_icon('alert')}Held actions {_count(len(held))}</h2>{held_note}{_render_held(view)}</div>
    <div class="group"><h2>{_icon('wrench')}Tools waiting {_count(len(tools or []))}</h2>{_render_tools(tools)}</div>
  </section>

  <section class="section" id="this-run">
    <h1>This run</h1>
    <p class="lede"><span class="mono">{escape(run_id)}</span> ·
      {'every step went through the checks' if protected else 'steps were recorded, not checked'}
      {_badge(view['enforcement'])}</p>
    {run_intro}
    <div class="cards">
      {metric('Steps', totals['steps'])}
      {metric('Blocked', totals['blocked'])}
      {metric('Receipts', totals['receipts'])}
      {metric('Model calls', totals['model_calls'] if reported else None)}
      {metric('Tokens', totals['tokens'])}
      {metric('Cost', None if cost is None else f"${cost:.4f}")}
    </div>
    <div class="group" id="timeline"><h2>{_icon('activity')}Timeline</h2>{_render_traces(view)}</div>
    <div class="group" id="receipts"><h2>{_icon('receipt')}Side-effect receipts</h2>{_render_receipts(view)}</div>
    <div class="group"><h2>{_icon('gauge')}Budget</h2>{budget_block}</div>
    <div class="group"><h2>{_icon('flag')}Gate history</h2>{gate_block}</div>
  </section>

  <section class="section" id="history">
    <h1>Approval history</h1>
    <p class="lede">Who let what run, across every run. Names are as typed: anyone with
      the dashboard token can type any name.</p>
    {_render_history(decided or [])}
  </section>

  </div></main>
</div><script>{_REFRESH_JS}</script></body></html>"""

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path not in _ACTIONS:
            self.send_error(404)
            return
        if not self._authorized(parse_qs(self.path.partition("?")[2])):
            self.send_error(401, "dashboard token required")
            return
        if not self._origin_is_trusted():
            self.send_error(403, "cross-origin request rejected")
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

        def field(name: str) -> str:
            return (form.get(name, [""])[0] or "").strip()

        name = field("approver")
        if not name:
            self.send_error(400, "a name is required")
            return
        try:
            if path in {"/approvals/approve", "/approvals/deny"}:
                approval_id = field("approval_id")
                if not approval_id:
                    self.send_error(400, "approval_id is required")
                    return
                if path.endswith("/approve"):
                    self.approvals.approve(approval_id, name)
                else:
                    self.approvals.deny(approval_id, name)
            elif path == "/receipts/settle":
                outcome = field("outcome")
                if outcome not in {"done", "failed"}:
                    self.send_error(400, "outcome must be done or failed")
                    return
                self.store.settle_receipt(
                    field("intent_key"), landed=outcome == "done", by=name,
                    ref=field("ref") or None,
                )
            else:
                pins = self._pins()
                tool = field("tool")
                if pins is None or not tool or not pins.accept(name, tool):
                    self.send_error(400, "that tool is not waiting")
                    return
        except (ApprovalError, ValueError) as exc:
            # Surface the policy message, never an internal traceback.
            self.send_error(400, str(exc))
            return
        self._redirect("/#needs-you")


def build_server(
    path: str,
    host: str,
    port: int,
    token: str | None = None,
    allow_origins: tuple[str, ...] = (),
) -> tuple[ThreadingHTTPServer, type[Handler]]:
    """Create a dashboard server with per-instance state.

    State lives on a generated subclass rather than being mutated onto the
    shared Handler, so two servers can coexist in one process and tests do not
    leak state into each other.

    The trusted origins are derived from the address the OS actually bound, not
    the requested one, so `--port 0` and host aliases resolve correctly.
    `allow_origins` adds the address a person really opens, when it differs
    from the bound one: a container bound to 0.0.0.0 and opened as
    http://127.0.0.1:8765 from the host.
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
        | {origin.rstrip("/") for origin in allow_origins}
    )
    # The renderer reads the token from a module-level slot so it is not
    # threaded through every helper. Set here, per server, so two servers in one
    # process still get their own.
    _CSRF[0] = csrf_token
    return server, bound


def serve(
    path: str,
    host: str,
    port: int,
    token: str | None = None,
    allow_origins: tuple[str, ...] = (),
) -> None:
    """Start the dashboard, printing the access token to the operator.

    Binding beyond loopback is refused unless a token was supplied explicitly:
    an exposed dashboard without authentication would leak every trace and let
    anyone approve destructive actions.
    """
    resolved = token or os.environ.get("AGENT_GATEWAY_DASHBOARD_TOKEN")
    if host not in {"127.0.0.1", "localhost", "::1"} and not resolved:
        raise SystemExit(
            f"refusing to bind {host}: a dashboard reachable off-host needs an "
            "explicit AGENT_GATEWAY_DASHBOARD_TOKEN"
        )
    server, handler = build_server(path, host, port, resolved, allow_origins)
    print(f"Agent Action Gateway dashboard on http://{host}:{server.server_address[1]}/")
    print(f"access token: {handler.access_token}")
    print("Open /?token=... once (it becomes a cookie), or send "
          "'Authorization: Bearer ...'. Keep it private.")
    server.serve_forever()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", default="data/runtime.db")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    serve(args.db, args.host, args.port)
