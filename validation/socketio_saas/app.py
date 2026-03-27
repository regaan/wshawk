from __future__ import annotations

from copy import deepcopy
from typing import Any
from uuid import uuid4

import socketio
from fastapi import FastAPI, HTTPException, Response
from pydantic import BaseModel


USERS = {
    "alice": {"password": "alice123", "role": "user", "tenant": "tenant-alpha", "display_name": "Alice Analyst"},
    "mallory": {"password": "mallory123", "role": "manager", "tenant": "tenant-alpha", "display_name": "Mallory Manager"},
    "bob": {"password": "bob123", "role": "user", "tenant": "tenant-beta", "display_name": "Bob Billing"},
    "brenda": {"password": "brenda123", "role": "manager", "tenant": "tenant-beta", "display_name": "Brenda Billing"},
}

BASE_ORDERS = {
    "ord-alpha-1001": {
        "id": "ord-alpha-1001",
        "tenant": "tenant-alpha",
        "customer": "Acme Retail",
        "amount": 1200,
        "currency": "USD",
        "status": "open",
        "refund_attempts": 0,
        "notes": ["Annual renewal order"],
        "approval_token": "approve-alpha-1001",
    },
    "ord-beta-9001": {
        "id": "ord-beta-9001",
        "tenant": "tenant-beta",
        "customer": "Northwind Health",
        "amount": 9999,
        "currency": "USD",
        "status": "paid",
        "refund_attempts": 0,
        "notes": ["Emergency services retainer"],
        "approval_token": "approve-beta-9001",
    },
}

TENANT_MESSAGES = {
    "tenant-alpha": [
        {"id": "alpha-msg-1", "channel": "ops", "text": "Alpha tenant reconciliation complete."},
        {"id": "alpha-msg-2", "channel": "finance", "text": "Alpha order approve-alpha-1001 issued."},
    ],
    "tenant-beta": [
        {"id": "beta-msg-1", "channel": "ops", "text": "Beta tenant export completed."},
        {"id": "beta-msg-2", "channel": "finance", "text": "Beta order approve-beta-9001 issued."},
    ],
}

ORDERS = deepcopy(BASE_ORDERS)
TOKENS: dict[str, dict[str, Any]] = {}
SESSIONS: dict[str, dict[str, Any]] = {}


class LoginRequest(BaseModel):
    username: str
    password: str


def reset_lab_state() -> None:
    ORDERS.clear()
    ORDERS.update(deepcopy(BASE_ORDERS))
    TOKENS.clear()
    SESSIONS.clear()


def mint_identity(username: str) -> dict[str, Any]:
    profile = USERS[username]
    token = f"socketio-{username}-{uuid4().hex[:10]}"
    session_id = f"socketio-session-{uuid4().hex[:10]}"
    identity = {
        "username": username,
        "role": profile["role"],
        "tenant": profile["tenant"],
        "display_name": profile["display_name"],
        "bearer_token": token,
        "session_id": session_id,
    }
    TOKENS[token] = identity
    SESSIONS[session_id] = identity
    return identity


def resolve_auth(auth_payload: dict[str, Any] | None) -> dict[str, Any] | None:
    if not auth_payload:
        return None
    token = auth_payload.get("token") or auth_payload.get("bearer_token")
    if not token:
        return None
    return TOKENS.get(token)


http_app = FastAPI(title="WSHawk Socket.IO Validation Lab")
sio = socketio.AsyncServer(async_mode="asgi", cors_allowed_origins="*")
app = socketio.ASGIApp(sio, other_asgi_app=http_app)


@http_app.get("/")
async def root():
    return {
        "lab": "socketio_saas",
        "protocol": "socket.io",
        "target": "local validation coverage",
    }


@http_app.post("/api/auth/login")
async def login(payload: LoginRequest, response: Response):
    profile = USERS.get(payload.username)
    if not profile or profile["password"] != payload.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    identity = mint_identity(payload.username)
    response.set_cookie("socketio_session", identity["session_id"], httponly=False, samesite="lax")
    return identity


def _serialize_welcome(identity: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "welcome",
        "username": identity["username"],
        "tenant": identity["tenant"],
        "role": identity["role"],
        "client_id": uuid4().hex[:12],
        "token_replay_supported": True,
    }


@sio.event
async def connect(sid, environ, auth):
    identity = resolve_auth(auth)
    if not identity:
        return False
    await sio.save_session(sid, identity)
    await sio.emit("welcome", _serialize_welcome(identity), to=sid)


async def _session_identity(sid: str) -> dict[str, Any]:
    session = await sio.get_session(sid)
    if not session:
        raise ConnectionRefusedError("session_missing")
    return session


@sio.event
async def whoami(sid, _data):
    identity = await _session_identity(sid)
    return {
        "type": "whoami",
        "username": identity["username"],
        "tenant": identity["tenant"],
        "role": identity["role"],
    }


@sio.event
async def subscribe_order(sid, data):
    await _session_identity(sid)
    order = ORDERS.get((data or {}).get("order_id"))
    if not order:
        return {"type": "error", "error": "order_not_found", "status_code": 404}
    return {"type": "order_snapshot", "order": deepcopy(order)}


@sio.event
async def list_room_messages(sid, data):
    identity = await _session_identity(sid)
    tenant_id = (data or {}).get("tenant_id") or identity["tenant"]
    return {
        "type": "room_messages",
        "tenant": tenant_id,
        "messages": deepcopy(TENANT_MESSAGES.get(tenant_id, [])),
    }


@sio.event
async def approve_refund(sid, data):
    identity = await _session_identity(sid)
    payload = data or {}
    order = ORDERS.get(payload.get("order_id"))
    if not order:
        return {"type": "error", "error": "order_not_found", "status_code": 404}

    approval_token = payload.get("approval_token")
    manager_allowed = identity["role"] == "manager" and identity["tenant"] == order["tenant"]
    token_allowed = approval_token == order["approval_token"]
    if not manager_allowed and not token_allowed:
        return {
            "type": "error",
            "error": "Approval requires manager role or valid approval token",
            "status_code": 403,
        }

    order["status"] = "refunded"
    order["refund_attempts"] += 1
    duplicate_success = order["refund_attempts"] > 1
    order["notes"].append(f"socketio refund by {identity['username']}: {payload.get('reason', 'no-reason')}")
    return {
        "type": "refund_result",
        "ok": True,
        "order_id": order["id"],
        "tenant": order["tenant"],
        "status": order["status"],
        "refund_attempts": order["refund_attempts"],
        "duplicate_success": duplicate_success,
        "approval_token_reused": token_allowed,
        "processed_by": identity["username"],
        "channel": "socket.io",
    }
