from __future__ import annotations

import asyncio
import json

from validation.common import asgi_request
from validation.full_stack_realtime_saas.app import INVOICES, app


def reset_lab_state() -> None:
    INVOICES["inv-alpha-1001"]["status"] = "open"
    INVOICES["inv-alpha-1001"]["refund_attempts"] = 0
    INVOICES["inv-alpha-1001"]["notes"] = ["Annual support renewal"]
    INVOICES["inv-beta-9001"]["status"] = "paid"
    INVOICES["inv-beta-9001"]["refund_attempts"] = 0
    INVOICES["inv-beta-9001"]["notes"] = ["Enterprise emergency retainer"]


def run_validation_scenario() -> dict:
    reset_lab_state()
    status, headers, payload = asyncio.run(
        asgi_request(app, "POST", "/api/auth/login", json_body={"username": "alice", "password": "alice123"})
    )
    login = json.loads(payload)
    bearer = login["bearer_token"]
    cookie = headers["set-cookie"].split(";", 1)[0]

    preview_status, _, preview_payload = asyncio.run(
        asgi_request(
            app,
            "GET",
            "/api/invoices/inv-beta-9001?preview=true",
            headers={"Authorization": f"Bearer {bearer}"},
        )
    )
    preview = json.loads(preview_payload)

    denied_status, _, denied_payload = asyncio.run(
        asgi_request(
            app,
            "POST",
            "/api/invoices/inv-beta-9001/refund",
            headers={"Authorization": f"Bearer {bearer}", "Cookie": cookie},
            json_body={"reason": "runner-no-token"},
        )
    )
    denied = json.loads(denied_payload)

    replay_status, _, replay_payload = asyncio.run(
        asgi_request(
            app,
            "POST",
            "/api/invoices/inv-beta-9001/refund",
            headers={"Authorization": f"Bearer {bearer}", "Cookie": cookie},
            json_body={"reason": "runner-http-replay", "approval_token": "approve-beta-9001"},
        )
    )
    replay = json.loads(replay_payload)

    race_statuses = []
    for attempt in range(2):
        status_code, _, payload_text = asyncio.run(
            asgi_request(
                app,
                "POST",
                "/api/invoices/inv-beta-9001/refund",
                headers={"Authorization": f"Bearer {bearer}", "Cookie": cookie},
                json_body={"reason": f"runner-race-{attempt}", "approval_token": "approve-beta-9001"},
            )
        )
        race_statuses.append((status_code, json.loads(payload_text)))

    checks = {
        "login_sets_cookie": status == 200 and bool(headers.get("set-cookie")),
        "preview_leaks_foreign_invoice": preview_status == 200 and preview.get("tenant") == "tenant-beta" and preview.get("approval_token") == "approve-beta-9001",
        "refund_denied_without_token": denied_status == 403 and "Approval requires" in denied.get("detail", ""),
        "refund_replay_succeeds_with_token": replay_status == 200 and replay.get("ok") is True and replay.get("approval_token_reused") is True,
        "duplicate_refund_race_possible": all(item[0] == 200 for item in race_statuses) and any(item[1].get("duplicate_success") for item in race_statuses),
    }
    return {
        "lab": "full_stack_realtime_saas",
        "checks": checks,
        "summary": {
            "login_status": status,
            "preview_status": preview_status,
            "denied_status": denied_status,
            "replay_status": replay_status,
            "final_refund_attempts": INVOICES["inv-beta-9001"]["refund_attempts"],
        },
        "artifacts": {
            "preview_invoice": preview,
            "denied_response": denied,
            "replay_response": replay,
            "race_responses": [item[1] for item in race_statuses],
        },
    }
