#!/usr/bin/env python3
"""
WSHawk Validation Target: Full-Stack Realtime SaaS

Intentionally vulnerable local application for validating:
- Browser auth capture
- HTTP replay and authz diff
- WebSocket handshake capture and replay
- Tenant hopping / subscription abuse
- Race conditions and replay windows
- Evidence export and project recovery

This target is designed for authorized local validation only.
"""

from __future__ import annotations

import asyncio
import csv
import html
import io
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlencode

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response


APP_VERSION = "4.0.0"
SESSION_COOKIE = "wshawk_validation_session"
CSRF_COOKIE = "wshawk_validation_csrf"


@dataclass
class UserRecord:
    username: str
    password: str
    role: str
    tenant: str
    display_name: str
    api_key: str


USERS: Dict[str, UserRecord] = {
    "alice": UserRecord("alice", "alice123", "user", "tenant-alpha", "Alice Analyst", "alpha-user-key"),
    "mallory": UserRecord("mallory", "mallory123", "manager", "tenant-alpha", "Mallory Manager", "alpha-manager-key"),
    "bob": UserRecord("bob", "bob123", "user", "tenant-beta", "Bob Billing", "beta-user-key"),
    "brenda": UserRecord("brenda", "brenda123", "manager", "tenant-beta", "Brenda Director", "beta-manager-key"),
    "admin": UserRecord("admin", "admin123", "admin", "tenant-root", "Root Admin", "root-admin-key"),
}

INVOICES: Dict[str, Dict[str, Any]] = {
    "inv-alpha-1001": {
        "id": "inv-alpha-1001",
        "tenant": "tenant-alpha",
        "customer": "Acme Retail",
        "amount": 1200,
        "currency": "USD",
        "status": "open",
        "approval_token": "approve-alpha-1001",
        "refund_attempts": 0,
        "notes": ["Annual support renewal"],
    },
    "inv-alpha-1002": {
        "id": "inv-alpha-1002",
        "tenant": "tenant-alpha",
        "customer": "Acme Labs",
        "amount": 540,
        "currency": "USD",
        "status": "paid",
        "approval_token": "approve-alpha-1002",
        "refund_attempts": 0,
        "notes": ["Pilot feature invoice"],
    },
    "inv-beta-9001": {
        "id": "inv-beta-9001",
        "tenant": "tenant-beta",
        "customer": "Northwind Health",
        "amount": 9999,
        "currency": "USD",
        "status": "paid",
        "approval_token": "approve-beta-9001",
        "refund_attempts": 0,
        "notes": ["Enterprise emergency retainer"],
    },
}

TENANT_MESSAGES = {
    "tenant-alpha": [
        {"id": "msg-a1", "channel": "ops", "text": "Alpha payroll run queued."},
        {"id": "msg-a2", "channel": "finance", "text": "Invoice inv-alpha-1002 escalated for review."},
    ],
    "tenant-beta": [
        {"id": "msg-b1", "channel": "ops", "text": "Beta healthcare export complete."},
        {"id": "msg-b2", "channel": "finance", "text": "Refund approval token approve-beta-9001 issued."},
    ],
}

SESSIONS: Dict[str, Dict[str, Any]] = {}
TOKENS: Dict[str, Dict[str, Any]] = {}
WS_CLIENTS: Dict[str, Dict[str, Any]] = {}
AUDIT_LOG: List[Dict[str, Any]] = []


def _now() -> float:
    return time.time()


def _select_ws_subprotocol(offered: Optional[List[str]]) -> Optional[str]:
    offered = offered or []
    if "wshawk-validation-v1" in offered:
        return "wshawk-validation-v1"
    return None


def _issue_session(username: str) -> Dict[str, str]:
    user = USERS[username]
    session_id = secrets.token_urlsafe(18)
    bearer = secrets.token_urlsafe(24)
    csrf = secrets.token_urlsafe(16)
    session = {
        "session_id": session_id,
        "username": username,
        "tenant": user.tenant,
        "role": user.role,
        "csrf": csrf,
        "bearer": bearer,
        "created_at": _now(),
        "logout_count": 0,
    }
    SESSIONS[session_id] = session
    TOKENS[bearer] = {
        "token": bearer,
        "username": username,
        "tenant": user.tenant,
        "role": user.role,
        "issued_at": _now(),
        "revoked": False,
        "source": "browser-login",
    }
    return {"session_id": session_id, "bearer": bearer, "csrf": csrf}


def _clear_session(session_id: Optional[str]) -> None:
    if not session_id:
        return
    session = SESSIONS.pop(session_id, None)
    if session:
        session["logout_count"] = session.get("logout_count", 0) + 1
        # Intentional vulnerability: bearer tokens remain usable after logout.


def _token_from_header(header_value: Optional[str]) -> Optional[str]:
    if not header_value:
        return None
    if header_value.lower().startswith("bearer "):
        return header_value.split(" ", 1)[1].strip()
    return header_value.strip()


def _get_identity_from_request(request: Request) -> Optional[Dict[str, Any]]:
    session_id = request.cookies.get(SESSION_COOKIE)
    if session_id and session_id in SESSIONS:
        session = SESSIONS[session_id]
        user = USERS[session["username"]]
        return {
            "auth_type": "session",
            "username": user.username,
            "role": user.role,
            "tenant": user.tenant,
            "display_name": user.display_name,
            "bearer": session["bearer"],
            "csrf": session["csrf"],
            "api_key": user.api_key,
        }

    bearer = _token_from_header(request.headers.get("Authorization"))
    if bearer and bearer in TOKENS:
        token = TOKENS[bearer]
        user = USERS[token["username"]]
        return {
            "auth_type": "bearer",
            "username": user.username,
            "role": user.role,
            "tenant": user.tenant,
            "display_name": user.display_name,
            "bearer": bearer,
            "csrf": request.cookies.get(CSRF_COOKIE, ""),
            "api_key": user.api_key,
        }

    api_key = request.headers.get("X-API-Key", "").strip()
    for user in USERS.values():
        if api_key and api_key == user.api_key:
            return {
                "auth_type": "api_key",
                "username": user.username,
                "role": user.role,
                "tenant": user.tenant,
                "display_name": user.display_name,
                "bearer": "",
                "csrf": "",
                "api_key": user.api_key,
            }
    return None


def _require_identity(request: Request) -> Dict[str, Any]:
    identity = _get_identity_from_request(request)
    if not identity:
        raise HTTPException(status_code=401, detail="Authentication required")
    return identity


def _get_identity_from_websocket(websocket: WebSocket) -> Optional[Dict[str, Any]]:
    bearer = websocket.query_params.get("token", "").strip()
    if bearer and bearer in TOKENS:
        token = TOKENS[bearer]
        user = USERS[token["username"]]
        return {
            "auth_type": "bearer",
            "username": user.username,
            "role": user.role,
            "tenant": user.tenant,
            "display_name": user.display_name,
            "bearer": bearer,
            "csrf": "",
            "api_key": user.api_key,
        }

    session_id = websocket.cookies.get(SESSION_COOKIE)
    if session_id and session_id in SESSIONS:
        session = SESSIONS[session_id]
        user = USERS[session["username"]]
        return {
            "auth_type": "session",
            "username": user.username,
            "role": user.role,
            "tenant": user.tenant,
            "display_name": user.display_name,
            "bearer": session["bearer"],
            "csrf": session["csrf"],
            "api_key": user.api_key,
        }
    return None


def _clone_invoice(invoice: Dict[str, Any], *, include_token: bool = False) -> Dict[str, Any]:
    cloned = {
        "id": invoice["id"],
        "tenant": invoice["tenant"],
        "customer": invoice["customer"],
        "amount": invoice["amount"],
        "currency": invoice["currency"],
        "status": invoice["status"],
        "refund_attempts": invoice["refund_attempts"],
        "notes": list(invoice.get("notes", [])),
    }
    if include_token:
        cloned["approval_token"] = invoice["approval_token"]
    return cloned


def _tenant_visible_invoices(identity: Dict[str, Any], tenant: Optional[str] = None) -> List[Dict[str, Any]]:
    requested_tenant = tenant or identity["tenant"]
    if identity["role"] == "admin":
        return [_clone_invoice(invoice) for invoice in INVOICES.values() if invoice["tenant"] == requested_tenant]
    return [_clone_invoice(invoice) for invoice in INVOICES.values() if invoice["tenant"] == identity["tenant"]]


def _log_event(kind: str, identity: Optional[Dict[str, Any]], details: Dict[str, Any]) -> None:
    AUDIT_LOG.append(
        {
            "kind": kind,
            "time": _now(),
            "identity": identity["username"] if identity else "anonymous",
            "tenant": identity["tenant"] if identity else "",
            "details": details,
        }
    )
    if len(AUDIT_LOG) > 200:
        del AUDIT_LOG[0 : len(AUDIT_LOG) - 200]


async def _broadcast(payload: Dict[str, Any], *, invoice_id: Optional[str] = None, tenant: Optional[str] = None) -> None:
    stale_ids: List[str] = []
    for client_id, client in list(WS_CLIENTS.items()):
        subscriptions = client.get("subscriptions", set())
        if invoice_id and f"invoice:{invoice_id}" in subscriptions:
            pass
        elif tenant and f"tenant:{tenant}" in subscriptions:
            pass
        elif not invoice_id and not tenant:
            pass
        else:
            continue
        try:
            await client["websocket"].send_text(json.dumps(payload))
        except Exception:
            stale_ids.append(client_id)
    for client_id in stale_ids:
        WS_CLIENTS.pop(client_id, None)


def _build_login_page(message: str = "") -> str:
    credentials = "".join(
        f"<tr><td>{html.escape(user.username)}</td><td>{html.escape(user.password)}</td><td>{html.escape(user.role)}</td><td>{html.escape(user.tenant)}</td></tr>"
        for user in USERS.values()
    )
    banner = f"<div class='msg'>{html.escape(message)}</div>" if message else ""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>WSHawk Validation SaaS Login</title>
  <style>
    :root {{
      --bg: #09111d;
      --panel: #122133;
      --ink: #e8f0f7;
      --muted: #9bb0c6;
      --accent: #ef4444;
      --accent-2: #f59e0b;
      --line: #23405e;
    }}
    body {{ margin: 0; font-family: 'Segoe UI', sans-serif; background: radial-gradient(circle at top, #143251, #09111d 55%); color: var(--ink); }}
    .wrap {{ max-width: 1100px; margin: 0 auto; padding: 48px 24px 80px; }}
    .hero {{ display: grid; grid-template-columns: 1.2fr 1fr; gap: 24px; align-items: start; }}
    .card {{ background: rgba(18,33,51,.92); border: 1px solid var(--line); border-radius: 18px; padding: 24px; box-shadow: 0 20px 60px rgba(0,0,0,.35); }}
    h1 {{ margin: 0 0 12px; font-size: 2.4rem; }}
    p {{ color: var(--muted); line-height: 1.6; }}
    form {{ display: grid; gap: 14px; }}
    input {{ width: 100%; padding: 12px 14px; border-radius: 12px; border: 1px solid var(--line); background: #0b1827; color: var(--ink); box-sizing: border-box; }}
    button {{ padding: 12px 16px; border-radius: 12px; border: none; background: linear-gradient(135deg, var(--accent), var(--accent-2)); color: white; font-weight: 700; cursor: pointer; }}
    .msg {{ margin-bottom: 12px; padding: 10px 12px; border-radius: 10px; background: rgba(239,68,68,.15); border: 1px solid rgba(239,68,68,.4); }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 18px; font-size: 0.95rem; }}
    th, td {{ padding: 10px 8px; border-bottom: 1px solid var(--line); text-align: left; }}
    .tags {{ display: flex; flex-wrap: wrap; gap: 10px; margin-top: 20px; }}
    .tag {{ padding: 8px 10px; border: 1px solid var(--line); border-radius: 999px; color: var(--muted); }}
    @media (max-width: 840px) {{ .hero {{ grid-template-columns: 1fr; }} }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="hero">
      <section class="card">
        <h1>Realtime SaaS Validation Lab</h1>
        <p>This intentionally vulnerable app is built for validating WSHawk desktop workflows across browser auth capture, HTTP replay, WebSocket interception, authz drift, tenant hopping, replay windows, and race conditions.</p>
        <div class="tags">
          <span class="tag">HTTP + WebSocket</span>
          <span class="tag">Cookie + Bearer + localStorage</span>
          <span class="tag">Cross-tenant preview leak</span>
          <span class="tag">Stale token reuse</span>
          <span class="tag">Duplicate refund race</span>
          <span class="tag">Open redirect + SSRF simulator</span>
        </div>
      </section>
      <section class="card">
        {banner}
        <form method="post" action="/login">
          <label>Username</label>
          <input type="text" name="username" placeholder="alice" autocomplete="username">
          <label>Password</label>
          <input type="password" name="password" placeholder="alice123" autocomplete="current-password">
          <button type="submit">Sign In And Bootstrap Live Feed</button>
        </form>
      </section>
    </div>
    <section class="card" style="margin-top: 24px;">
      <h2>Default Accounts</h2>
      <table>
        <thead><tr><th>User</th><th>Password</th><th>Role</th><th>Tenant</th></tr></thead>
        <tbody>{credentials}</tbody>
      </table>
    </section>
  </div>
</body>
</html>"""


def _build_dashboard(identity: Dict[str, Any], request: Request) -> str:
    base_url = str(request.base_url).rstrip("/")
    ws_scheme = "wss" if request.url.scheme == "https" else "ws"
    ws_url = f"{ws_scheme}://{request.url.netloc}/ws?{urlencode({'token': identity['bearer'], 'tenant': identity['tenant']})}"
    invoices = [_clone_invoice(invoice, include_token=True) for invoice in INVOICES.values() if invoice["tenant"] == identity["tenant"]]
    foreign_preview = _clone_invoice(INVOICES["inv-beta-9001"], include_token=True)
    bootstrap = {
        "version": APP_VERSION,
        "baseUrl": base_url,
        "wsUrl": ws_url,
        "bearerToken": identity["bearer"],
        "csrfToken": identity["csrf"],
        "tenant": identity["tenant"],
        "role": identity["role"],
        "username": identity["username"],
        "apiKey": identity["api_key"],
        "sampleInvoices": invoices,
        "foreignPreviewHint": foreign_preview["id"],
    }
    bootstrap_json = json.dumps(bootstrap)
    invoices_html = "".join(
        f"<tr><td>{html.escape(invoice['id'])}</td><td>{html.escape(invoice['customer'])}</td><td>{invoice['amount']}</td><td>{html.escape(invoice['status'])}</td><td><code>{html.escape(invoice['approval_token'])}</code></td></tr>"
        for invoice in invoices
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>WSHawk Validation Dashboard</title>
  <style>
    :root {{
      --bg: #09111d;
      --panel: rgba(17,30,46,.94);
      --line: #274867;
      --ink: #eaf2f9;
      --muted: #96acc2;
      --accent: #f97316;
      --accent2: #ef4444;
      --good: #22c55e;
    }}
    body {{ margin: 0; background: linear-gradient(180deg, #0d1b2b, #08111c); color: var(--ink); font-family: Inter, 'Segoe UI', sans-serif; }}
    .shell {{ max-width: 1280px; margin: 0 auto; padding: 24px; }}
    .hero {{ display: flex; justify-content: space-between; gap: 16px; align-items: start; flex-wrap: wrap; }}
    .hero h1 {{ margin: 0; font-size: 2rem; }}
    .meta {{ color: var(--muted); margin-top: 6px; }}
    .grid {{ display: grid; grid-template-columns: 1.15fr .85fr; gap: 18px; margin-top: 18px; }}
    .card {{ background: var(--panel); border: 1px solid var(--line); border-radius: 18px; padding: 18px; box-shadow: 0 16px 48px rgba(0,0,0,.28); }}
    .stack {{ display: grid; gap: 18px; }}
    .pills {{ display: flex; gap: 10px; flex-wrap: wrap; margin-top: 12px; }}
    .pill {{ border: 1px solid var(--line); border-radius: 999px; padding: 8px 12px; color: var(--muted); }}
    .actions {{ display: flex; gap: 10px; flex-wrap: wrap; margin-top: 14px; }}
    button {{ border: none; border-radius: 12px; padding: 10px 14px; font-weight: 700; cursor: pointer; background: linear-gradient(135deg, var(--accent2), var(--accent)); color: white; }}
    .ghost {{ background: transparent; border: 1px solid var(--line); color: var(--ink); }}
    pre {{ white-space: pre-wrap; word-break: break-word; background: #07111c; border: 1px solid #16324d; padding: 14px; border-radius: 14px; max-height: 280px; overflow: auto; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 0.95rem; }}
    th, td {{ text-align: left; padding: 10px 8px; border-bottom: 1px solid var(--line); }}
    .hint {{ color: var(--muted); font-size: 0.95rem; }}
    .log {{ min-height: 220px; }}
    .kpi {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-top: 14px; }}
    .kpi div {{ border: 1px solid var(--line); border-radius: 14px; padding: 14px; background: rgba(7,17,28,.75); }}
    .good {{ color: var(--good); }}
    @media (max-width: 1000px) {{ .grid {{ grid-template-columns: 1fr; }} .kpi {{ grid-template-columns: repeat(2, 1fr); }} }}
  </style>
</head>
<body>
  <div class="shell">
    <section class="hero card">
      <div>
        <h1>Validation Control Board</h1>
        <div class="meta">{html.escape(identity['display_name'])} · {html.escape(identity['role'])} · {html.escape(identity['tenant'])}</div>
        <div class="pills">
          <span class="pill">Version {APP_VERSION}</span>
          <span class="pill">Cookie + Bearer + localStorage bootstrap</span>
          <span class="pill">WS auto-connect enabled</span>
          <span class="pill">Known vulnerable lab</span>
        </div>
      </div>
      <div class="actions">
        <button id="refreshInvoices">Refresh Invoices</button>
        <button id="leakForeign" class="ghost">Leak Foreign Invoice</button>
        <button id="runRefund" class="ghost">HTTP Refund With Approval Token</button>
        <button id="runWsRefund" class="ghost">WS Refund Action</button>
        <button id="logoutBtn" class="ghost">Logout</button>
      </div>
    </section>

    <section class="grid">
      <div class="stack">
        <div class="card">
          <h2>Bootstrapped Identity</h2>
          <div class="kpi">
            <div><strong>User</strong><br>{html.escape(identity['username'])}</div>
            <div><strong>Role</strong><br>{html.escape(identity['role'])}</div>
            <div><strong>Tenant</strong><br>{html.escape(identity['tenant'])}</div>
            <div><strong>WS</strong><br><span id="wsState" class="good">connecting</span></div>
          </div>
          <p class="hint">The page stores the bearer token and CSRF token in <code>localStorage</code> and auto-opens a WebSocket. That makes it useful for WSHawk browser auth recording and extension handshake capture.</p>
          <pre id="bootstrapBox"></pre>
        </div>
        <div class="card">
          <h2>Tenant Invoices</h2>
          <table>
            <thead><tr><th>ID</th><th>Customer</th><th>Amount</th><th>Status</th><th>Approval Token</th></tr></thead>
            <tbody id="invoiceTable">{invoices_html}</tbody>
          </table>
        </div>
      </div>
      <div class="stack">
        <div class="card">
          <h2>Operator Notes</h2>
          <ul>
            <li>Use <code>/api/invoices/inv-beta-9001?preview=true</code> to trigger a cross-tenant preview leak.</li>
            <li>Use the leaked <code>approval_token</code> to replay refund actions over HTTP or WebSocket.</li>
            <li>Logout clears the cookie, but the old bearer token still works.</li>
            <li>Run multiple refund requests in parallel to trigger the duplicate refund race.</li>
            <li><code>/api/public/redirect?next=...</code> and <code>/api/internal/fetch?url=...</code> exist for web-pentest validation.</li>
          </ul>
        </div>
        <div class="card">
          <h2>Live Feed</h2>
          <pre id="wsLog" class="log"></pre>
        </div>
        <div class="card">
          <h2>HTTP Responses</h2>
          <pre id="httpLog" class="log"></pre>
        </div>
      </div>
    </section>
  </div>
  <script>
    const bootstrap = {bootstrap_json};
    localStorage.setItem('wshawk.validation.bearer', bootstrap.bearerToken);
    localStorage.setItem('wshawk.validation.csrf', bootstrap.csrfToken);
    localStorage.setItem('wshawk.validation.tenant', bootstrap.tenant);
    localStorage.setItem('wshawk.validation.role', bootstrap.role);
    localStorage.setItem('wshawk.validation.username', bootstrap.username);
    const bootstrapBox = document.getElementById('bootstrapBox');
    const wsLog = document.getElementById('wsLog');
    const httpLog = document.getElementById('httpLog');
    const wsState = document.getElementById('wsState');
    const invoiceTable = document.getElementById('invoiceTable');
    let ws;
    let foreignInvoice;

    function append(box, value) {{
      box.textContent = `${{new Date().toISOString()}}  ${{value}}\\n` + box.textContent;
    }}

    async function api(path, options = {{}}) {{
      const headers = Object.assign({{
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${{bootstrap.bearerToken}}`,
        'X-CSRF-Token': bootstrap.csrfToken,
      }}, options.headers || {{}});
      const response = await fetch(path, Object.assign({{
        credentials: 'include',
        headers,
      }}, options));
      const text = await response.text();
      append(httpLog, `${{options.method || 'GET'}} ${{path}} -> ${{response.status}} ${{text}}`);
      try {{
        return JSON.parse(text);
      }} catch (_) {{
        return text;
      }}
    }}

    function renderInvoices(items) {{
      invoiceTable.innerHTML = items.map((item) => `
        <tr>
          <td>${{item.id}}</td>
          <td>${{item.customer}}</td>
          <td>${{item.amount}}</td>
          <td>${{item.status}}</td>
          <td><code>${{item.approval_token || 'hidden'}}</code></td>
        </tr>
      `).join('');
    }}

    function connectWs() {{
      ws = new WebSocket(bootstrap.wsUrl, ['wshawk-validation-v1']);
      ws.addEventListener('open', () => {{
        wsState.textContent = 'connected';
        append(wsLog, 'WS connected');
        ws.send(JSON.stringify({{ action: 'subscribe_tenant_feed', tenant_id: bootstrap.tenant }}));
      }});
      ws.addEventListener('message', (event) => append(wsLog, event.data));
      ws.addEventListener('close', () => {{
        wsState.textContent = 'closed';
        append(wsLog, 'WS closed');
      }});
    }}

    document.getElementById('refreshInvoices').addEventListener('click', async () => {{
      const data = await api('/api/invoices');
      renderInvoices(data.invoices || []);
    }});

    document.getElementById('leakForeign').addEventListener('click', async () => {{
      foreignInvoice = await api('/api/invoices/inv-beta-9001?preview=true');
      append(httpLog, 'Captured leaked approval token: ' + (foreignInvoice.approval_token || 'none'));
    }});

    document.getElementById('runRefund').addEventListener('click', async () => {{
      if (!foreignInvoice) {{
        foreignInvoice = await api('/api/invoices/inv-beta-9001?preview=true');
      }}
      await api('/api/invoices/inv-beta-9001/refund', {{
        method: 'POST',
        body: JSON.stringify({{
          reason: 'Operator replay',
          approval_token: foreignInvoice.approval_token,
        }}),
      }});
    }});

    document.getElementById('runWsRefund').addEventListener('click', async () => {{
      if (!foreignInvoice) {{
        foreignInvoice = await api('/api/invoices/inv-beta-9001?preview=true');
      }}
      ws.send(JSON.stringify({{
        action: 'approve_refund',
        invoice_id: 'inv-beta-9001',
        approval_token: foreignInvoice.approval_token,
        reason: 'WS replay',
      }}));
    }});

    document.getElementById('logoutBtn').addEventListener('click', async () => {{
      await api('/api/auth/logout', {{ method: 'POST', body: '{{}}' }});
      append(httpLog, 'Cookie removed. Bearer token intentionally remains valid for stale-token testing.');
    }});

    bootstrapBox.textContent = JSON.stringify(bootstrap, null, 2);
    connectWs();
  </script>
</body>
</html>"""


app = FastAPI(title="WSHawk Validation SaaS", version=APP_VERSION)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    identity = _get_identity_from_request(request)
    if identity:
        return RedirectResponse(url="/dashboard", status_code=302)
    return HTMLResponse(_build_login_page())


@app.get("/login", response_class=HTMLResponse)
async def login_page():
    return HTMLResponse(_build_login_page())


@app.get("/favicon.ico")
async def favicon():
    return Response(status_code=204)


@app.post("/login")
async def login(request: Request):
    body = (await request.body()).decode("utf-8", errors="replace")
    parsed = parse_qs(body, keep_blank_values=True)
    username = str(parsed.get("username", [""])[0]).strip()
    password = str(parsed.get("password", [""])[0]).strip()
    user = USERS.get(username)
    if not user or user.password != password:
        return HTMLResponse(_build_login_page("Invalid credentials"), status_code=401)

    issued = _issue_session(username)
    response = RedirectResponse(url="/dashboard", status_code=302)
    response.set_cookie(SESSION_COOKIE, issued["session_id"], httponly=True, samesite="lax")
    response.set_cookie(CSRF_COOKIE, issued["csrf"], httponly=False, samesite="lax")
    return response


@app.post("/api/auth/login")
async def api_login(payload: Dict[str, Any]):
    username = str(payload.get("username", "")).strip()
    password = str(payload.get("password", "")).strip()
    user = USERS.get(username)
    if not user or user.password != password:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    issued = _issue_session(username)
    response = JSONResponse(
        {
            "ok": True,
            "username": username,
            "role": user.role,
            "tenant": user.tenant,
            "bearer_token": issued["bearer"],
            "csrf_token": issued["csrf"],
            "ws_path": "/ws",
        }
    )
    response.set_cookie(SESSION_COOKIE, issued["session_id"], httponly=True, samesite="lax")
    response.set_cookie(CSRF_COOKIE, issued["csrf"], httponly=False, samesite="lax")
    return response


@app.post("/logout")
async def logout(request: Request):
    _clear_session(request.cookies.get(SESSION_COOKIE))
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie(SESSION_COOKIE)
    response.delete_cookie(CSRF_COOKIE)
    return response


@app.post("/api/auth/logout")
async def api_logout(request: Request):
    _clear_session(request.cookies.get(SESSION_COOKIE))
    response = JSONResponse({"ok": True, "message": "Session cookie cleared; bearer token still valid for replay-window testing."})
    response.delete_cookie(SESSION_COOKIE)
    response.delete_cookie(CSRF_COOKIE)
    return response


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    identity = _require_identity(request)
    return HTMLResponse(_build_dashboard(identity, request))


@app.get("/robots.txt")
async def robots():
    return PlainTextResponse("User-agent: *\nDisallow: /debug\nDisallow: /exports\n")


@app.get("/internal/health")
async def internal_health():
    return JSONResponse({"ok": True, "build": APP_VERSION, "mode": "validation"})


@app.get("/exports/invoices.csv")
async def export_invoices_csv():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["invoice_id", "tenant", "customer", "amount", "status"])
    for invoice in INVOICES.values():
        writer.writerow([invoice["id"], invoice["tenant"], invoice["customer"], invoice["amount"], invoice["status"]])
    return Response(content=output.getvalue(), media_type="text/csv")


@app.get("/api/profile")
async def profile(request: Request):
    identity = _require_identity(request)
    return {
        "username": identity["username"],
        "role": identity["role"],
        "tenant": identity["tenant"],
        "auth_type": identity["auth_type"],
        "bearer_token": identity["bearer"],
        "csrf_token": identity["csrf"],
    }


@app.get("/api/bootstrap")
async def bootstrap(request: Request):
    identity = _require_identity(request)
    ws_scheme = "wss" if request.url.scheme == "https" else "ws"
    return {
        "version": APP_VERSION,
        "username": identity["username"],
        "role": identity["role"],
        "tenant": identity["tenant"],
        "bearer_token": identity["bearer"],
        "csrf_token": identity["csrf"],
        "ws_url": f"{ws_scheme}://{request.url.netloc}/ws?token={identity['bearer']}",
        "project_hints": {
            "preview_invoice": "inv-beta-9001",
            "race_invoice": "inv-beta-9001",
        },
    }


@app.get("/api/invoices")
async def list_invoices(request: Request, tenant: Optional[str] = None, preview: bool = False):
    identity = _require_identity(request)
    if preview and tenant:
        invoices = [_clone_invoice(invoice, include_token=True) for invoice in INVOICES.values() if invoice["tenant"] == tenant]
    elif identity["role"] == "admin" and tenant:
        invoices = [_clone_invoice(invoice, include_token=True) for invoice in INVOICES.values() if invoice["tenant"] == tenant]
    else:
        invoices = [_clone_invoice(invoice) for invoice in INVOICES.values() if invoice["tenant"] == identity["tenant"]]
    _log_event("list_invoices", identity, {"tenant": tenant or identity["tenant"], "preview": preview, "count": len(invoices)})
    return {"invoices": invoices}


@app.get("/api/invoices/{invoice_id}")
async def get_invoice(invoice_id: str, request: Request, preview: bool = False):
    identity = _require_identity(request)
    invoice = INVOICES.get(invoice_id)
    if not invoice:
        raise HTTPException(status_code=404, detail="Invoice not found")

    if invoice["tenant"] != identity["tenant"] and identity["role"] != "admin" and not preview:
        raise HTTPException(status_code=403, detail="Forbidden")

    include_token = preview or identity["role"] in {"manager", "admin"}
    _log_event("get_invoice", identity, {"invoice_id": invoice_id, "preview": preview})
    return _clone_invoice(invoice, include_token=include_token)


async def _process_refund(
    *,
    invoice_id: str,
    identity: Dict[str, Any],
    reason: str,
    approval_token: str,
    channel: str,
) -> Dict[str, Any]:
    invoice = INVOICES.get(invoice_id)
    if not invoice:
        raise HTTPException(status_code=404, detail="Invoice not found")

    allowed = False
    if identity["role"] == "admin":
        allowed = True
    elif identity["role"] == "manager" and invoice["tenant"] == identity["tenant"]:
        allowed = True
    elif approval_token and approval_token == invoice["approval_token"]:
        allowed = True

    if not allowed:
        raise HTTPException(status_code=403, detail="Approval requires manager role or valid approval token")

    # Intentional race window: there is no lock, no idempotency, and token reuse is allowed.
    await asyncio.sleep(0.2)
    invoice["refund_attempts"] += 1
    invoice["status"] = "refunded"
    invoice["notes"].append(f"{channel} refund by {identity['username']}: {reason}")
    result = {
        "ok": True,
        "invoice_id": invoice_id,
        "tenant": invoice["tenant"],
        "status": invoice["status"],
        "refund_attempts": invoice["refund_attempts"],
        "duplicate_success": invoice["refund_attempts"] > 1,
        "approval_token_reused": bool(approval_token),
        "processed_by": identity["username"],
        "channel": channel,
    }
    _log_event("refund", identity, result)
    await _broadcast({"type": "refund_processed", **result}, invoice_id=invoice_id, tenant=invoice["tenant"])
    return result


@app.post("/api/invoices/{invoice_id}/refund")
async def refund_invoice(invoice_id: str, request: Request, payload: Dict[str, Any]):
    identity = _require_identity(request)
    reason = str(payload.get("reason", "No reason provided")).strip()
    approval_token = str(payload.get("approval_token", "")).strip()
    return await _process_refund(
        invoice_id=invoice_id,
        identity=identity,
        reason=reason or "No reason provided",
        approval_token=approval_token,
        channel="http",
    )


@app.get("/api/team/messages")
async def team_messages(request: Request, tenant: Optional[str] = None):
    identity = _require_identity(request)
    requested = tenant or identity["tenant"]
    # Intentional tenant leak for validation: tenant parameter is trusted without authz enforcement.
    _log_event("team_messages", identity, {"requested_tenant": requested})
    return {"tenant": requested, "messages": TENANT_MESSAGES.get(requested, [])}


@app.get("/api/public/redirect")
async def open_redirect(next: str = "https://example.org"):
    return RedirectResponse(url=next, status_code=302)


@app.get("/api/internal/fetch")
async def ssrf_simulator(request: Request, url: str):
    identity = _require_identity(request)
    _log_event("ssrf_simulator", identity, {"url": url})
    if "169.254.169.254" in url or "metadata.google.internal" in url:
        return {
            "url": url,
            "response": {
                "AccessKeyId": "ASIAWSHAWKLAB",
                "SecretAccessKey": "wshawk-validation-secret",
                "Token": "metadata-leak-token",
            },
            "note": "This is a local SSRF simulation endpoint for WSHawk validation.",
        }
    return {"url": url, "response": f"Fetched {url}", "note": "Echo-only external fetch simulator"}


@app.get("/api/audit")
async def audit_log(request: Request):
    _require_identity(request)
    return {"events": AUDIT_LOG[-50:]}


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    identity = _get_identity_from_websocket(websocket)
    if not identity:
        await websocket.close(code=4401)
        return

    selected_subprotocol = _select_ws_subprotocol(websocket.scope.get("subprotocols"))
    if selected_subprotocol:
        await websocket.accept(subprotocol=selected_subprotocol)
    else:
        await websocket.accept()
    client_id = secrets.token_hex(6)
    WS_CLIENTS[client_id] = {
        "websocket": websocket,
        "identity": identity,
        "subscriptions": {f"tenant:{identity['tenant']}"},
    }
    await websocket.send_text(
        json.dumps(
            {
                "type": "welcome",
                "client_id": client_id,
                "username": identity["username"],
                "tenant": identity["tenant"],
                "role": identity["role"],
                "token_replay_supported": True,
            }
        )
    )

    try:
        while True:
            raw = await websocket.receive_text()
            try:
                message = json.loads(raw)
            except json.JSONDecodeError:
                await websocket.send_text(json.dumps({"type": "error", "error": "invalid_json"}))
                continue

            action = str(message.get("action", "")).strip()
            if action == "whoami":
                await websocket.send_text(json.dumps({"type": "whoami", **identity}))
            elif action == "subscribe_tenant_feed":
                tenant_id = str(message.get("tenant_id", identity["tenant"])).strip()
                WS_CLIENTS[client_id]["subscriptions"].add(f"tenant:{tenant_id}")
                await websocket.send_text(json.dumps({"type": "subscribed", "scope": "tenant", "tenant": tenant_id}))
            elif action == "subscribe_invoice":
                invoice_id = str(message.get("invoice_id", "")).strip()
                invoice = INVOICES.get(invoice_id)
                if not invoice:
                    await websocket.send_text(json.dumps({"type": "error", "error": "invoice_not_found"}))
                    continue
                # Intentional tenant-hopping flaw: subscription does not enforce tenant ownership.
                WS_CLIENTS[client_id]["subscriptions"].add(f"invoice:{invoice_id}")
                await websocket.send_text(json.dumps({"type": "invoice_snapshot", "invoice": _clone_invoice(invoice, include_token=True)}))
            elif action == "list_team_messages":
                tenant_id = str(message.get("tenant_id", identity["tenant"])).strip()
                await websocket.send_text(json.dumps({"type": "team_messages", "tenant": tenant_id, "messages": TENANT_MESSAGES.get(tenant_id, [])}))
            elif action == "approve_refund":
                try:
                    result = await _process_refund(
                        invoice_id=str(message.get("invoice_id", "")).strip(),
                        identity=identity,
                        reason=str(message.get("reason", "WS approval")).strip() or "WS approval",
                        approval_token=str(message.get("approval_token", "")).strip(),
                        channel="ws",
                    )
                    await websocket.send_text(json.dumps({"type": "refund_result", **result}))
                except HTTPException as exc:
                    await websocket.send_text(json.dumps({"type": "error", "error": exc.detail, "status_code": exc.status_code}))
            else:
                await websocket.send_text(json.dumps({"type": "error", "error": "unknown_action", "action": action}))
    except WebSocketDisconnect:
        pass
    finally:
        WS_CLIENTS.pop(client_id, None)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("validation.full_stack_realtime_saas.app:app", host="127.0.0.1", port=8010, reload=False)
