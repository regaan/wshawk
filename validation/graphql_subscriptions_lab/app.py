from __future__ import annotations

import json
import re
from copy import deepcopy
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Response, WebSocket, WebSocketDisconnect
from pydantic import BaseModel


USERS = {
    "alice": {"password": "alice123", "role": "user", "tenant": "tenant-alpha", "display_name": "Alice Analyst"},
    "mallory": {"password": "mallory123", "role": "manager", "tenant": "tenant-alpha", "display_name": "Mallory Manager"},
    "bob": {"password": "bob123", "role": "user", "tenant": "tenant-beta", "display_name": "Bob Billing"},
    "brenda": {"password": "brenda123", "role": "manager", "tenant": "tenant-beta", "display_name": "Brenda Billing"},
}

BASE_INVOICES = {
    "inv-alpha-1001": {
        "id": "inv-alpha-1001",
        "tenant": "tenant-alpha",
        "customer": "Acme Retail",
        "amount": 1200,
        "currency": "USD",
        "status": "open",
        "refund_attempts": 0,
        "notes": ["Annual support renewal"],
        "approval_token": "approve-alpha-1001",
    },
    "inv-beta-9001": {
        "id": "inv-beta-9001",
        "tenant": "tenant-beta",
        "customer": "Northwind Health",
        "amount": 9999,
        "currency": "USD",
        "status": "paid",
        "refund_attempts": 0,
        "notes": ["GraphQL validation retainer"],
        "approval_token": "approve-beta-9001",
    },
}

TENANT_MESSAGES = {
    "tenant-alpha": [
        {"id": "alpha-gql-1", "channel": "ops", "text": "Alpha GraphQL subscription settled."},
    ],
    "tenant-beta": [
        {"id": "beta-gql-1", "channel": "ops", "text": "Beta enterprise export completed."},
        {"id": "beta-gql-2", "channel": "finance", "text": "Approval token approve-beta-9001 approved."},
    ],
}

INVOICES = deepcopy(BASE_INVOICES)
TOKENS: dict[str, dict[str, Any]] = {}


class LoginRequest(BaseModel):
    username: str
    password: str


def reset_lab_state() -> None:
    INVOICES.clear()
    INVOICES.update(deepcopy(BASE_INVOICES))
    TOKENS.clear()


def mint_identity(username: str) -> dict[str, Any]:
    profile = USERS[username]
    token = f"graphql-{username}-{uuid4().hex[:10]}"
    identity = {
        "username": username,
        "role": profile["role"],
        "tenant": profile["tenant"],
        "display_name": profile["display_name"],
        "bearer_token": token,
    }
    TOKENS[token] = identity
    return identity


def pick_subprotocol(websocket: WebSocket) -> str | None:
    raw = websocket.headers.get("sec-websocket-protocol", "")
    offered = [item.strip() for item in raw.split(",") if item.strip()]
    if "graphql-transport-ws" in offered:
        return "graphql-transport-ws"
    return None


def extract_bearer_token(payload: dict[str, Any]) -> str | None:
    if not isinstance(payload, dict):
        return None
    auth_header = payload.get("Authorization") or payload.get("authorization")
    if isinstance(auth_header, str) and auth_header.lower().startswith("bearer "):
        return auth_header.split(" ", 1)[1]
    return payload.get("token") or payload.get("bearer_token")


def value_from_query(query: str, name: str) -> str | None:
    pattern = rf"{name}\s*:\s*\"([^\"]+)\""
    match = re.search(pattern, query)
    return match.group(1) if match else None


def coalesce_value(variables: dict[str, Any], query: str, variable_key: str, query_key: str) -> str | None:
    return variables.get(variable_key) or variables.get(query_key) or value_from_query(query, query_key)


def execute_graphql_operation(identity: dict[str, Any], query: str, variables: dict[str, Any]) -> dict[str, Any]:
    normalized = " ".join(query.split())
    if "whoami" in normalized:
        return {
            "data": {
                "whoami": {
                    "username": identity["username"],
                    "tenant": identity["tenant"],
                    "role": identity["role"],
                }
            }
        }

    if "invoiceUpdates" in normalized:
        invoice_id = coalesce_value(variables, normalized, "invoiceId", "invoiceId")
        invoice = INVOICES.get(invoice_id or "")
        if not invoice:
            return {"errors": [{"message": "invoice_not_found"}]}
        return {"data": {"invoiceUpdates": deepcopy(invoice)}}

    if "tenantMessages" in normalized:
        tenant_id = coalesce_value(variables, normalized, "tenantId", "tenantId") or identity["tenant"]
        return {"data": {"tenantMessages": deepcopy(TENANT_MESSAGES.get(tenant_id, []))}}

    if "approveRefund" in normalized:
        invoice_id = coalesce_value(variables, normalized, "invoiceId", "invoiceId")
        reason = coalesce_value(variables, normalized, "reason", "reason") or "graphql-replay"
        approval_token = coalesce_value(variables, normalized, "approvalToken", "approvalToken")
        invoice = INVOICES.get(invoice_id or "")
        if not invoice:
            return {"errors": [{"message": "invoice_not_found"}]}

        manager_allowed = identity["role"] == "manager" and identity["tenant"] == invoice["tenant"]
        token_allowed = approval_token == invoice["approval_token"]
        if not manager_allowed and not token_allowed:
            return {"errors": [{"message": "Approval requires manager role or valid approval token"}]}

        invoice["status"] = "refunded"
        invoice["refund_attempts"] += 1
        invoice["notes"].append(f"graphql refund by {identity['username']}: {reason}")
        return {
            "data": {
                "approveRefund": {
                    "ok": True,
                    "invoice_id": invoice["id"],
                    "tenant": invoice["tenant"],
                    "processed_by": identity["username"],
                    "approval_token_reused": token_allowed,
                    "refund_attempts": invoice["refund_attempts"],
                }
            }
        }

    return {"errors": [{"message": "unsupported_operation"}]}


app = FastAPI(title="WSHawk GraphQL Subscriptions Validation Lab")


@app.get("/")
async def root():
    return {
        "lab": "graphql_subscriptions_lab",
        "protocol": "graphql-transport-ws",
    }


@app.post("/api/auth/login")
async def login(payload: LoginRequest, response: Response):
    profile = USERS.get(payload.username)
    if not profile or profile["password"] != payload.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    identity = mint_identity(payload.username)
    response.set_cookie("graphql_session", identity["bearer_token"], httponly=False, samesite="lax")
    return identity


@app.websocket("/graphql")
async def graphql_endpoint(websocket: WebSocket):
    await websocket.accept(subprotocol=pick_subprotocol(websocket))
    identity = None
    try:
        init_message = await websocket.receive_json()
        if init_message.get("type") != "connection_init":
            await websocket.close(code=4400, reason="expected_connection_init")
            return
        token = extract_bearer_token(init_message.get("payload") or {})
        identity = TOKENS.get(token or "")
        if not identity:
            await websocket.close(code=4401, reason="unauthorized")
            return
        await websocket.send_json({"type": "connection_ack"})

        while True:
            message = await websocket.receive_json()
            if message.get("type") != "subscribe":
                if message.get("type") == "ping":
                    await websocket.send_json({"type": "pong"})
                continue

            op_id = message.get("id", uuid4().hex[:8])
            payload = message.get("payload") or {}
            query = payload.get("query") or ""
            variables = payload.get("variables") or {}
            result = execute_graphql_operation(identity, query, variables)
            await websocket.send_json({"id": op_id, "type": "next", "payload": result})
            await websocket.send_json({"id": op_id, "type": "complete"})
    except WebSocketDisconnect:
        return
