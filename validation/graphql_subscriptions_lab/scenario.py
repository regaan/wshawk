from __future__ import annotations

import asyncio
import json

import websockets

from validation.common import LiveASGIServer, asgi_request
from validation.graphql_subscriptions_lab.app import app, reset_lab_state


async def _subscribe_json(ws, *, op_id: str, query: str, variables: dict | None = None) -> dict:
    await ws.send(
        json.dumps(
            {
                "id": op_id,
                "type": "subscribe",
                "payload": {
                    "query": query,
                    "variables": variables or {},
                },
            }
        )
    )
    while True:
        message = json.loads(await ws.recv())
        if message.get("type") == "next" and message.get("id") == op_id:
            payload = message.get("payload") or {}
            await ws.recv()  # consume complete
            return payload


async def _run_graphql_scenario(ws_url: str) -> dict:
    status, headers, payload = await asgi_request(
        app,
        "POST",
        "/api/auth/login",
        json_body={"username": "alice", "password": "alice123"},
    )
    login = json.loads(payload)

    async with websockets.connect(ws_url, subprotocols=["graphql-transport-ws"]) as ws:
        await ws.send(
            json.dumps(
                {
                    "type": "connection_init",
                    "payload": {"Authorization": f"Bearer {login['bearer_token']}"},
                }
            )
        )
        ack = json.loads(await ws.recv())

        whoami = await _subscribe_json(
            ws,
            op_id="1",
            query="query WhoAmI { whoami { username tenant role } }",
        )
        invoice = await _subscribe_json(
            ws,
            op_id="2",
            query="subscription InvoiceUpdates($invoiceId: String!) { invoiceUpdates(invoiceId: $invoiceId) { id tenant approval_token } }",
            variables={"invoiceId": "inv-beta-9001"},
        )
        messages = await _subscribe_json(
            ws,
            op_id="3",
            query="subscription TenantMessages($tenantId: String!) { tenantMessages(tenantId: $tenantId) { id channel text } }",
            variables={"tenantId": "tenant-beta"},
        )
        denied = await _subscribe_json(
            ws,
            op_id="4",
            query="mutation ApproveRefund($invoiceId: String!, $reason: String!) { approveRefund(invoiceId: $invoiceId, reason: $reason) { ok tenant processed_by approval_token_reused } }",
            variables={"invoiceId": "inv-beta-9001", "reason": "graphql-no-token"},
        )
        replay = await _subscribe_json(
            ws,
            op_id="5",
            query="mutation ApproveRefund($invoiceId: String!, $reason: String!, $approvalToken: String!) { approveRefund(invoiceId: $invoiceId, reason: $reason, approvalToken: $approvalToken) { ok tenant processed_by approval_token_reused } }",
            variables={
                "invoiceId": "inv-beta-9001",
                "reason": "graphql-replay",
                "approvalToken": "approve-beta-9001",
            },
        )

    denied_errors = denied.get("errors") or []
    replay_data = (replay.get("data") or {}).get("approveRefund") or {}
    invoice_data = (invoice.get("data") or {}).get("invoiceUpdates") or {}
    message_rows = (messages.get("data") or {}).get("tenantMessages") or []
    checks = {
        "graphql_acknowledged": status == 200 and ack.get("type") == "connection_ack",
        "graphql_cross_tenant_invoice_subscription": invoice_data.get("tenant") == "tenant-beta"
        and invoice_data.get("approval_token") == "approve-beta-9001",
        "graphql_cross_tenant_message_subscription": any("approve-beta-9001" in row.get("text", "") for row in message_rows),
        "graphql_refund_denied_without_token": any("Approval requires" in item.get("message", "") for item in denied_errors),
        "graphql_refund_replay_succeeds_with_token": replay_data.get("ok") is True
        and replay_data.get("approval_token_reused") is True
        and replay_data.get("tenant") == "tenant-beta",
    }
    return {
        "lab": "graphql_subscriptions_lab",
        "checks": checks,
        "summary": {
            "login_status": status,
            "login_cookie_present": "set-cookie" in headers,
            "connection_ack": ack.get("type"),
        },
        "artifacts": {
            "whoami": whoami,
            "invoice_subscription": invoice,
            "tenant_messages": messages,
            "denied_response": denied,
            "replay_response": replay,
        },
    }


def run_validation_scenario() -> dict:
    reset_lab_state()
    with LiveASGIServer(app) as server:
        ws_url = f"ws://{server.host}:{server.port}/graphql"
        return asyncio.run(_run_graphql_scenario(ws_url))
