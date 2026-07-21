from __future__ import annotations

import asyncio
import json
from typing import Any, Optional
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse


app = FastAPI(title="WSHawk Industry Security Controls Benchmark")

IDENTITIES = {
    "industry-user-token": {"username": "alice", "role": "user", "tenant": "tenant-alpha"},
    "industry-admin-token": {"username": "root", "role": "admin", "tenant": "tenant-root"},
}
ORDERS = {
    "order-alpha": {"id": "order-alpha", "tenant": "tenant-alpha", "amount": 125},
    "order-beta": {"id": "order-beta", "tenant": "tenant-beta", "amount": 9900},
}
RACE_STATE = {
    "vulnerable_http": 0,
    "vulnerable_ws": 0,
    "hardened_http_keys": set(),
    "hardened_ws_keys": set(),
}
HTTP_IDEMPOTENCY_LOCK = asyncio.Lock()
WS_IDEMPOTENCY_LOCK = asyncio.Lock()


def reset_state() -> None:
    RACE_STATE["vulnerable_http"] = 0
    RACE_STATE["vulnerable_ws"] = 0
    RACE_STATE["hardened_http_keys"] = set()
    RACE_STATE["hardened_ws_keys"] = set()


def _http_identity(request: Request) -> dict[str, str]:
    authorization = request.headers.get("Authorization", "").strip()
    token = authorization.split(" ", 1)[1].strip() if authorization.lower().startswith("bearer ") else ""
    identity = IDENTITIES.get(token)
    if not identity:
        raise HTTPException(status_code=401, detail="Authentication required")
    return dict(identity)


def _ws_identity(websocket: WebSocket) -> Optional[dict[str, str]]:
    authorization = websocket.headers.get("Authorization", "").strip()
    token = websocket.query_params.get("token", "").strip()
    if authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
    identity = IDENTITIES.get(token)
    return dict(identity) if identity else None


@app.get("/")
async def index():
    return {
        "lab": "industry_security_controls_benchmark",
        "profiles": ["vulnerable", "hardened"],
        "scope": "localhost-only",
    }


@app.get("/{profile}/headers")
async def security_headers(profile: str):
    if profile == "vulnerable":
        return HTMLResponse("<h1>Legacy portal</h1>", headers={"X-Powered-By": "Express"})
    if profile == "hardened":
        return HTMLResponse(
            "<h1>Hardened portal</h1>",
            headers={
                "Content-Security-Policy": "default-src 'self'; object-src 'none'; frame-ancestors 'none'",
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
            },
        )
    raise HTTPException(status_code=404, detail="Unknown profile")


@app.get("/{profile}/cors")
async def cors(profile: str, request: Request):
    origin = request.headers.get("Origin", "")
    headers: dict[str, str] = {}
    if profile == "vulnerable" and origin:
        headers["Access-Control-Allow-Origin"] = origin
        headers["Access-Control-Allow-Credentials"] = "true"
    elif profile == "hardened" and origin == "https://trusted.example":
        headers["Access-Control-Allow-Origin"] = origin
        headers["Vary"] = "Origin"
    elif profile not in {"vulnerable", "hardened"}:
        raise HTTPException(status_code=404, detail="Unknown profile")
    return JSONResponse({"ok": True, "profile": profile}, headers=headers)


@app.get("/{profile}/api/orders/{order_id}")
async def get_order(profile: str, order_id: str, request: Request):
    identity = _http_identity(request)
    order = ORDERS.get(order_id)
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    if profile == "hardened" and identity["role"] != "admin" and order["tenant"] != identity["tenant"]:
        raise HTTPException(status_code=403, detail="Forbidden")
    if profile not in {"vulnerable", "hardened"}:
        raise HTTPException(status_code=404, detail="Unknown profile")
    return {**order, "requested_by": identity["username"]}


@app.get("/{profile}/api/import")
async def import_url(profile: str, request: Request, url: str):
    _http_identity(request)
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    internal = host in {"169.254.169.254", "127.0.0.1", "localhost"} or host.startswith("10.")
    unsafe_scheme = parsed.scheme not in {"http", "https"}
    if profile == "hardened" and (internal or unsafe_scheme):
        raise HTTPException(status_code=403, detail="Outbound destination blocked")
    if profile not in {"vulnerable", "hardened"}:
        raise HTTPException(status_code=404, detail="Unknown profile")
    if internal:
        return PlainTextResponse("ami-id\ninstance-id\niam/security-credentials/industry-role\nAccessKeyId")
    return {"ok": True, "result": "upstream response accepted"}


@app.get("/{profile}/redirect")
async def redirect(profile: str, next: str = "/"):
    if profile == "vulnerable":
        return RedirectResponse(next, status_code=302)
    if profile == "hardened":
        parsed = urlparse(next)
        if parsed.scheme or parsed.netloc or not next.startswith("/") or next.startswith("//"):
            raise HTTPException(status_code=400, detail="External redirects are not allowed")
        return RedirectResponse(next, status_code=302)
    raise HTTPException(status_code=404, detail="Unknown profile")


@app.get("/{profile}/api/config")
async def config(profile: str, request: Request):
    _http_identity(request)
    if profile == "vulnerable":
        return PlainTextResponse(
            "AWS_ACCESS_KEY=AKIAABCDEFGHIJKLMNOP\n"
            "DATABASE_URL=postgres://industry:industry@10.20.30.40/benchmark\n"
            "OWNER=security@example.test"
        )
    if profile == "hardened":
        return {"storage": "configured", "credentials": "managed externally"}
    raise HTTPException(status_code=404, detail="Unknown profile")


@app.post("/{profile}/transfer")
async def transfer(profile: str, request: Request):
    _http_identity(request)
    if profile == "hardened" and request.headers.get("X-CSRF-Token") != "industry-csrf-token":
        raise HTTPException(status_code=403, detail="CSRF token required")
    if profile not in {"vulnerable", "hardened"}:
        raise HTTPException(status_code=404, detail="Unknown profile")
    await request.body()
    return {"ok": True, "profile": profile}


@app.post("/{profile}/api/redeem")
async def redeem(profile: str, request: Request):
    _http_identity(request)
    await asyncio.sleep(0.02)
    if profile == "vulnerable":
        RACE_STATE["vulnerable_http"] = int(RACE_STATE["vulnerable_http"]) + 1
        attempts = int(RACE_STATE["vulnerable_http"])
        return {"ok": True, "attempt": attempts, "duplicate": attempts > 1}
    if profile == "hardened":
        key = request.headers.get("Idempotency-Key", "")
        if not key:
            raise HTTPException(status_code=400, detail="Idempotency-Key required")
        async with HTTP_IDEMPOTENCY_LOCK:
            keys = RACE_STATE["hardened_http_keys"]
            if key in keys:
                return JSONResponse({"ok": False, "error": "duplicate rejected"}, status_code=409)
            keys.add(key)
        return {"ok": True, "idempotency_key_accepted": True}
    raise HTTPException(status_code=404, detail="Unknown profile")


@app.websocket("/{profile}/ws")
async def websocket_endpoint(websocket: WebSocket, profile: str):
    identity = _ws_identity(websocket)
    if not identity or profile not in {"vulnerable", "hardened"}:
        await websocket.close(code=4401)
        return
    if profile == "hardened" and websocket.headers.get("Origin") != "https://trusted.example":
        await websocket.close(code=4403)
        return

    await websocket.accept()
    await websocket.send_text(json.dumps({"type": "welcome", "profile": profile, **identity}))
    try:
        while True:
            raw = await websocket.receive_text()
            try:
                message: dict[str, Any] = json.loads(raw)
            except json.JSONDecodeError:
                await websocket.send_text(json.dumps({"type": "error", "error": "invalid_json"}))
                continue

            action = str(message.get("action", ""))
            if action == "subscribe":
                tenant_id = str(message.get("tenant_id", identity["tenant"]))
                if profile == "hardened" and identity["role"] != "admin" and tenant_id != identity["tenant"]:
                    await websocket.send_text(
                        json.dumps({"type": "error", "error": "forbidden", "status_code": 403})
                    )
                else:
                    await websocket.send_text(
                        json.dumps({"type": "subscription", "accepted": True, "tenant": tenant_id})
                    )
            elif action == "redeem":
                await asyncio.sleep(0.02)
                if profile == "vulnerable":
                    RACE_STATE["vulnerable_ws"] = int(RACE_STATE["vulnerable_ws"]) + 1
                    attempts = int(RACE_STATE["vulnerable_ws"])
                    await websocket.send_text(
                        json.dumps({"type": "redeem_result", "ok": True, "attempt": attempts})
                    )
                else:
                    key = str(message.get("idempotency_key", ""))
                    if not key:
                        await websocket.send_text(
                            json.dumps({"type": "error", "error": "idempotency_key_required", "status_code": 400})
                        )
                        continue
                    async with WS_IDEMPOTENCY_LOCK:
                        keys = RACE_STATE["hardened_ws_keys"]
                        if key in keys:
                            await websocket.send_text(
                                json.dumps({"type": "error", "error": "duplicate rejected", "status_code": 409})
                            )
                            continue
                        keys.add(key)
                    await websocket.send_text(json.dumps({"type": "redeem_result", "ok": True}))
            else:
                await websocket.send_text(
                    json.dumps({"type": "error", "error": "unknown_action", "status_code": 400})
                )
    except WebSocketDisconnect:
        return
