from __future__ import annotations

import asyncio
import time
from typing import Any, Awaitable

from validation.common import LiveASGIServer
from validation.websocket_attack_benchmark.app import app, reset_state
from wshawk.attacks import (
    WebSocketAuthzDiffService,
    WebSocketRaceService,
    WebSocketReplayService,
    WebSocketSubscriptionAbuseService,
)
from wshawk.attacks.common import ws_result_effective_success
from wshawk.defensive_validation import CSWSHValidator


async def _run_benchmark(ws_url: str) -> dict[str, Any]:
    timings_ms: dict[str, float] = {}

    async def measured(name: str, operation: Awaitable[Any]) -> Any:
        started = time.perf_counter()
        result = await operation
        timings_ms[name] = round((time.perf_counter() - started) * 1000, 2)
        return result

    user = {
        "id": "benchmark-user",
        "alias": "user",
        "headers": {"Authorization": "Bearer benchmark-user-token"},
    }
    admin = {
        "id": "benchmark-admin",
        "alias": "admin",
        "headers": {"Authorization": "Bearer benchmark-admin-token"},
    }

    replay = await measured(
        "ws_replay",
        WebSocketReplayService().replay(
            project_id="websocket-attack-benchmark",
            url=ws_url,
            payload={"action": "whoami"},
            identity=user,
            timeout=2.0,
        ),
    )
    error_replay = await measured(
        "ws_error_classification",
        WebSocketReplayService().replay(
            project_id="websocket-attack-benchmark",
            url=ws_url,
            payload={"action": "application_error"},
            identity=user,
            timeout=2.0,
        ),
    )
    authz = await measured(
        "ws_authz_diff",
        WebSocketAuthzDiffService().compare(
            project_id="websocket-attack-benchmark",
            url=ws_url,
            payload={"action": "read_admin"},
            identities=[user, admin],
            timeout=2.0,
        ),
    )
    subscription = await measured(
        "ws_subscription_abuse",
        WebSocketSubscriptionAbuseService().probe(
            project_id="websocket-attack-benchmark",
            url=ws_url,
            payload={"action": "subscribe", "tenant_id": "tenant-alpha"},
            identities=[user],
            field_paths=["tenant_id"],
            candidate_values=["tenant-beta"],
            max_mutations=1,
            timeout=2.0,
        ),
    )
    race = await measured(
        "ws_race",
        WebSocketRaceService().run(
            project_id="websocket-attack-benchmark",
            url=ws_url,
            payload={"action": "refund", "approval_token": "benchmark-refund-token"},
            identities=[user],
            concurrency=3,
            waves=2,
            mode="duplicate_action",
            timeout=2.0,
        ),
    )
    origin = await measured(
        "websocket_origin_probe",
        CSWSHValidator(
            f"{ws_url}?token=benchmark-user-token",
            max_origins=2,
            origin_concurrency=2,
            connection_timeout=1.0,
        ).test_origin_validation(),
    )

    checks = {
        "replay_skips_welcome_frame": (
            replay.get("status") == "received"
            and replay.get("prelude_frame_count", 0) >= 1
            and '"type": "identity"' in replay.get("response", "")
        ),
        "application_error_is_not_counted_as_success": ws_result_effective_success(error_replay) is False,
        "authz_diff_compares_live_identities": (
            authz["summary"]["behavior_changed"] is True
            and authz["summary"]["identity_count"] == 2
        ),
        "subscription_abuse_detects_tenant_hop": subscription["summary"]["suspicious_attempt_count"] >= 1,
        "race_attack_detects_duplicate_success": race["summary"]["suspicious_race_window"] is True,
        "origin_probe_observes_untrusted_origin_acceptance": len(origin.get("accepted_origins", [])) == 2,
        "all_attack_transports_complete_without_errors": (
            replay.get("status") == "received"
            and error_replay.get("status") == "received"
            and authz["summary"]["status_breakdown"].get("received") == 2
            and race["summary"]["error_count"] == 0
        ),
    }

    return {
        "lab": "websocket_attack_benchmark",
        "checks": checks,
        "summary": {
            "checks_passed": sum(1 for value in checks.values() if value),
            "checks_total": len(checks),
            "frames_exercised": (
                2
                + len(authz.get("results", []))
                + len(subscription.get("baseline_results", []))
                + len(subscription.get("attempts", []))
                + len(race.get("results", []))
            ),
            "timings_ms": timings_ms,
            "total_timed_ms": round(sum(timings_ms.values()), 2),
        },
        "artifacts": {
            "replay_status": replay.get("status"),
            "replay_prelude_frames": replay.get("prelude_frame_count", 0),
            "error_replay_effective_success": ws_result_effective_success(error_replay),
            "authz_summary": authz.get("summary", {}),
            "subscription_summary": subscription.get("summary", {}),
            "race_summary": race.get("summary", {}),
            "origin_probe": {
                "tested_origins": origin.get("tested_origins", 0),
                "accepted_origin_count": len(origin.get("accepted_origins", [])),
                "probe_error_count": len(origin.get("errors", [])),
            },
        },
    }


def run_validation_scenario() -> dict[str, Any]:
    reset_state()
    with LiveASGIServer(app) as server:
        return asyncio.run(_run_benchmark(f"ws://{server.host}:{server.port}/ws"))
