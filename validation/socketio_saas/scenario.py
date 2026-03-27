from __future__ import annotations

import asyncio
import json

import socketio

from validation.common import LiveASGIServer, asgi_request
from validation.socketio_saas.app import http_app, reset_lab_state, app


async def _run_socketio_scenario(base_url: str) -> dict:
    status, headers, payload = await asgi_request(
        http_app,
        "POST",
        "/api/auth/login",
        json_body={"username": "alice", "password": "alice123"},
    )
    login = json.loads(payload)

    client = socketio.AsyncClient()
    welcome_holder = {}

    @client.on("welcome")
    async def on_welcome(data):
        welcome_holder["event"] = data

    await client.connect(base_url, auth={"token": login["bearer_token"]}, transports=["websocket"])
    await asyncio.sleep(0.05)

    whoami = await client.call("whoami", {})
    snapshot = await client.call("subscribe_order", {"order_id": "ord-beta-9001"})
    messages = await client.call("list_room_messages", {"tenant_id": "tenant-beta"})
    denied = await client.call("approve_refund", {"order_id": "ord-beta-9001", "reason": "socketio-no-token"})
    replay = await client.call(
        "approve_refund",
        {
            "order_id": "ord-beta-9001",
            "reason": "socketio-replay",
            "approval_token": "approve-beta-9001",
        },
    )
    await client.disconnect()
    # Let Engine.IO finish cancelling background tasks before the loop exits.
    await asyncio.sleep(0.05)

    checks = {
        "socketio_connects_with_token": status == 200 and whoami.get("username") == "alice" and bool(welcome_holder.get("event")),
        "socketio_cross_tenant_order_exposure": snapshot.get("order", {}).get("tenant") == "tenant-beta"
        and snapshot.get("order", {}).get("approval_token") == "approve-beta-9001",
        "socketio_cross_tenant_message_exposure": messages.get("tenant") == "tenant-beta"
        and any("approve-beta-9001" in item.get("text", "") for item in messages.get("messages", [])),
        "socketio_refund_denied_without_token": denied.get("status_code") == 403
        and "Approval requires" in denied.get("error", ""),
        "socketio_refund_replay_succeeds_with_token": replay.get("ok") is True
        and replay.get("approval_token_reused") is True
        and replay.get("tenant") == "tenant-beta",
    }
    return {
        "lab": "socketio_saas",
        "checks": checks,
        "summary": {
            "login_status": status,
            "login_cookie_present": "set-cookie" in headers,
            "welcome_received": bool(welcome_holder.get("event")),
            "replay_status": replay.get("status"),
        },
        "artifacts": {
            "whoami": whoami,
            "welcome": welcome_holder.get("event"),
            "order_snapshot": snapshot,
            "room_messages": messages,
            "denied_response": denied,
            "replay_response": replay,
        },
    }


def run_validation_scenario() -> dict:
    reset_lab_state()
    with LiveASGIServer(app) as server:
        return asyncio.run(_run_socketio_scenario(f"http://{server.host}:{server.port}"))
