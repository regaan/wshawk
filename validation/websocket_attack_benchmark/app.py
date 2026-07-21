from __future__ import annotations

import asyncio
import json
from typing import Any, Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect


app = FastAPI(title="WSHawk WebSocket Attack Benchmark")
REFUND_STATE = {"attempts": 0}

IDENTITIES = {
    "benchmark-user-token": {"username": "analyst", "role": "user", "tenant": "tenant-alpha"},
    "benchmark-admin-token": {"username": "administrator", "role": "admin", "tenant": "tenant-root"},
}


def reset_state() -> None:
    REFUND_STATE["attempts"] = 0


def _identity(websocket: WebSocket) -> Optional[dict[str, str]]:
    token = websocket.query_params.get("token", "").strip()
    authorization = websocket.headers.get("Authorization", "").strip()
    if authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
    identity = IDENTITIES.get(token)
    return dict(identity) if identity else None


@app.get("/")
async def index():
    return {"lab": "websocket_attack_benchmark", "ws_path": "/ws"}


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    identity = _identity(websocket)
    if not identity:
        await websocket.close(code=4401)
        return

    await websocket.accept()
    await websocket.send_text(
        json.dumps(
            {
                "type": "welcome",
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
                message: dict[str, Any] = json.loads(raw)
            except json.JSONDecodeError:
                await websocket.send_text(json.dumps({"type": "error", "error": "invalid_json"}))
                continue

            action = str(message.get("action", ""))
            if action == "whoami":
                await websocket.send_text(json.dumps({"type": "identity", **identity}))
            elif action == "read_admin":
                if identity["role"] != "admin":
                    await websocket.send_text(
                        json.dumps({"type": "error", "error": "forbidden", "status_code": 403})
                    )
                else:
                    await websocket.send_text(
                        json.dumps({"type": "admin_data", "ok": True, "scope": "all-tenants"})
                    )
            elif action == "subscribe":
                tenant_id = str(message.get("tenant_id", identity["tenant"]))
                await websocket.send_text(
                    json.dumps(
                        {
                            "type": "subscription",
                            "accepted": True,
                            "tenant": tenant_id,
                            "events": [f"private-event-for-{tenant_id}"],
                        }
                    )
                )
            elif action == "refund":
                if message.get("approval_token") != "benchmark-refund-token":
                    await websocket.send_text(
                        json.dumps({"type": "error", "error": "invalid_approval", "status_code": 403})
                    )
                    continue
                await asyncio.sleep(0.03)
                REFUND_STATE["attempts"] += 1
                await websocket.send_text(
                    json.dumps(
                        {
                            "type": "refund_result",
                            "ok": True,
                            "attempt": REFUND_STATE["attempts"],
                            "duplicate": REFUND_STATE["attempts"] > 1,
                        }
                    )
                )
            elif action == "application_error":
                await websocket.send_text(
                    json.dumps({"type": "error", "error": "benchmark_denied", "status_code": 403})
                )
            else:
                await websocket.send_text(
                    json.dumps({"type": "error", "error": "unknown_action", "status_code": 400})
                )
    except WebSocketDisconnect:
        return
