from __future__ import annotations

import asyncio
import time
from typing import Any, Awaitable

from benchmarks.industry_lab.app import app, reset_state
from validation.common import LiveASGIServer
from wshawk.attacks import HTTPRaceService, HTTPReplayService, WebSocketRaceService, WebSocketSubscriptionAbuseService
from wshawk.defensive_validation import CSWSHValidator
from wshawk.transport import WSHawkHTTPProxy
from wshawk.web_pentest import (
    WSHawkBlindProbe,
    WSHawkCORSTester,
    WSHawkCSRFForge,
    WSHawkHeaderAnalyzer,
    WSHawkRedirectHunter,
    WSHawkSensitiveFinder,
)


async def _run_industry_benchmark(base_url: str) -> dict[str, Any]:
    timings_ms: dict[str, float] = {}

    async def measured(name: str, operation: Awaitable[Any]) -> Any:
        started = time.perf_counter()
        result = await operation
        timings_ms[name] = round((time.perf_counter() - started) * 1000, 2)
        return result

    user_headers = {"Authorization": "Bearer industry-user-token"}
    user_identity = {
        "id": "industry-user",
        "alias": "tenant-alpha-user",
        "headers": user_headers,
    }
    trusted_origin = {"Origin": "https://trusted.example"}
    proxy = WSHawkHTTPProxy()

    vulnerable_headers = await measured(
        "vulnerable_headers",
        WSHawkHeaderAnalyzer().analyze(f"{base_url}/vulnerable/headers"),
    )
    hardened_headers = await measured(
        "hardened_headers",
        WSHawkHeaderAnalyzer().analyze(f"{base_url}/hardened/headers"),
    )
    vulnerable_cors = await measured(
        "vulnerable_cors",
        WSHawkCORSTester().test(f"{base_url}/vulnerable/cors"),
    )
    hardened_cors = await measured(
        "hardened_cors",
        WSHawkCORSTester().test(f"{base_url}/hardened/cors"),
    )
    vulnerable_sensitive = await measured(
        "vulnerable_sensitive_data",
        WSHawkSensitiveFinder().scan_url(
            f"{base_url}/vulnerable/api/config",
            headers=user_headers,
        ),
    )
    hardened_sensitive = await measured(
        "hardened_sensitive_data",
        WSHawkSensitiveFinder().scan_url(
            f"{base_url}/hardened/api/config",
            headers=user_headers,
        ),
    )
    vulnerable_redirect = await measured(
        "vulnerable_redirect",
        WSHawkRedirectHunter().scan(f"{base_url}/vulnerable/redirect?next=/"),
    )
    hardened_redirect = await measured(
        "hardened_redirect",
        WSHawkRedirectHunter().scan(f"{base_url}/hardened/redirect?next=/"),
    )
    vulnerable_ssrf = await measured(
        "vulnerable_ssrf",
        WSHawkBlindProbe().probe(
            f"{base_url}/vulnerable/api/import?url=https://example.org",
            headers=user_headers,
        ),
    )
    hardened_ssrf = await measured(
        "hardened_ssrf",
        WSHawkBlindProbe().probe(
            f"{base_url}/hardened/api/import?url=https://example.org",
            headers=user_headers,
        ),
    )

    replay_service = HTTPReplayService(http_proxy=proxy)
    vulnerable_bola = await measured(
        "vulnerable_bola",
        replay_service.replay(
            project_id="industry-security-controls",
            method="GET",
            url=f"{base_url}/vulnerable/api/orders/order-beta",
            identity=user_identity,
        ),
    )
    hardened_bola = await measured(
        "hardened_bola",
        replay_service.replay(
            project_id="industry-security-controls",
            method="GET",
            url=f"{base_url}/hardened/api/orders/order-beta",
            identity=user_identity,
        ),
    )

    csrf_engine = WSHawkCSRFForge()
    vulnerable_csrf = await measured(
        "vulnerable_csrf",
        csrf_engine.replay(
            method="POST",
            url=f"{base_url}/vulnerable/transfer",
            headers="Authorization: Bearer industry-user-token\nContent-Type: application/x-www-form-urlencoded",
            body="amount=250",
            content_type="application/x-www-form-urlencoded",
            http_proxy=proxy,
        ),
    )
    hardened_csrf = await measured(
        "hardened_csrf",
        csrf_engine.replay(
            method="POST",
            url=f"{base_url}/hardened/transfer",
            headers="Authorization: Bearer industry-user-token\nContent-Type: application/x-www-form-urlencoded",
            body="amount=250",
            content_type="application/x-www-form-urlencoded",
            http_proxy=proxy,
        ),
    )

    vulnerable_http_race = await measured(
        "vulnerable_http_race",
        HTTPRaceService(http_proxy=proxy).run(
            project_id="industry-security-controls",
            method="POST",
            url=f"{base_url}/vulnerable/api/redeem",
            headers={**user_headers, "Content-Type": "application/json"},
            body='{"voucher":"INDUSTRY"}',
            concurrency=3,
            waves=2,
            mode="duplicate_action",
        ),
    )
    hardened_http_race = await measured(
        "hardened_http_race",
        HTTPRaceService(http_proxy=proxy).run(
            project_id="industry-security-controls",
            method="POST",
            url=f"{base_url}/hardened/api/redeem",
            headers={
                **user_headers,
                "Content-Type": "application/json",
                "Idempotency-Key": "industry-http-idempotency",
            },
            body='{"voucher":"INDUSTRY"}',
            concurrency=3,
            waves=2,
            mode="duplicate_action",
        ),
    )

    vulnerable_ws_url = base_url.replace("http://", "ws://") + "/vulnerable/ws"
    hardened_ws_url = base_url.replace("http://", "ws://") + "/hardened/ws"
    vulnerable_subscription = await measured(
        "vulnerable_ws_subscription",
        WebSocketSubscriptionAbuseService().probe(
            project_id="industry-security-controls",
            url=vulnerable_ws_url,
            payload={"action": "subscribe", "tenant_id": "tenant-alpha"},
            identities=[user_identity],
            field_paths=["tenant_id"],
            candidate_values=["tenant-beta"],
            max_mutations=1,
            timeout=2.0,
        ),
    )
    hardened_subscription = await measured(
        "hardened_ws_subscription",
        WebSocketSubscriptionAbuseService().probe(
            project_id="industry-security-controls",
            url=hardened_ws_url,
            payload={"action": "subscribe", "tenant_id": "tenant-alpha"},
            identities=[user_identity],
            headers=trusted_origin,
            field_paths=["tenant_id"],
            candidate_values=["tenant-beta"],
            max_mutations=1,
            timeout=2.0,
        ),
    )
    vulnerable_ws_race = await measured(
        "vulnerable_ws_race",
        WebSocketRaceService().run(
            project_id="industry-security-controls",
            url=vulnerable_ws_url,
            payload={"action": "redeem"},
            identities=[user_identity],
            concurrency=3,
            waves=2,
            timeout=2.0,
        ),
    )
    hardened_ws_race = await measured(
        "hardened_ws_race",
        WebSocketRaceService().run(
            project_id="industry-security-controls",
            url=hardened_ws_url,
            payload={"action": "redeem", "idempotency_key": "industry-ws-idempotency"},
            identities=[user_identity],
            headers=trusted_origin,
            concurrency=3,
            waves=2,
            timeout=2.0,
        ),
    )
    vulnerable_origin = await measured(
        "vulnerable_ws_origin",
        CSWSHValidator(
            f"{vulnerable_ws_url}?token=industry-user-token",
            max_origins=2,
            origin_concurrency=2,
            connection_timeout=1.0,
        ).test_origin_validation(),
    )
    hardened_origin = await measured(
        "hardened_ws_origin",
        CSWSHValidator(
            f"{hardened_ws_url}?token=industry-user-token",
            max_origins=2,
            origin_concurrency=2,
            connection_timeout=1.0,
        ).test_origin_validation(),
    )

    vulnerable_header_findings = sum(
        1 for result in vulnerable_headers.values() if result.get("risk") in {"High", "Medium"}
    )
    hardened_header_findings = sum(
        1 for result in hardened_headers.values() if result.get("risk") in {"High", "Medium"}
    )
    checks = {
        "headers_distinguish_vulnerable_and_hardened_profiles": (
            vulnerable_header_findings >= 3 and hardened_header_findings == 0
        ),
        "cors_distinguishes_reflection_and_allowlist": (
            vulnerable_cors.get("risk_score") == "High" and hardened_cors.get("risk_score") == "Safe"
        ),
        "sensitive_data_distinguishes_leak_and_redaction": (
            vulnerable_sensitive.get("total", 0) >= 3 and hardened_sensitive.get("total", 0) == 0
        ),
        "redirect_distinguishes_open_and_local_only": (
            vulnerable_redirect.get("total_findings", 0) > 0 and hardened_redirect.get("total_findings", 0) == 0
        ),
        "ssrf_distinguishes_metadata_access_and_egress_filter": (
            any(item.get("strong_indicators") for item in vulnerable_ssrf.get("findings", []))
            and hardened_ssrf.get("total_findings", 0) == 0
        ),
        "bola_distinguishes_missing_and_enforced_object_authorization": (
            vulnerable_bola.get("http_status") == "200" and hardened_bola.get("http_status") == "403"
        ),
        "csrf_replay_distinguishes_unprotected_and_protected_actions": (
            vulnerable_csrf.get("replay_status") == "200" and hardened_csrf.get("replay_status") == "403"
        ),
        "http_race_distinguishes_duplicate_acceptance_and_idempotency": (
            vulnerable_http_race["summary"]["suspicious_race_window"] is True
            and hardened_http_race["summary"]["suspicious_race_window"] is False
            and hardened_http_race["summary"]["success_count"] == 1
        ),
        "ws_subscription_distinguishes_tenant_hop_and_enforcement": (
            vulnerable_subscription["summary"]["suspicious_attempt_count"] >= 1
            and hardened_subscription["summary"]["accepted_mutation_count"] == 0
        ),
        "ws_race_distinguishes_duplicate_acceptance_and_idempotency": (
            vulnerable_ws_race["summary"]["suspicious_race_window"] is True
            and hardened_ws_race["summary"]["suspicious_race_window"] is False
            and hardened_ws_race["summary"]["accepted_count"] == 1
        ),
        "ws_origin_distinguishes_open_and_allowlisted_handshakes": (
            len(vulnerable_origin.get("accepted_origins", [])) == 2
            and len(hardened_origin.get("accepted_origins", [])) == 0
            and len(hardened_origin.get("errors", [])) == 0
        ),
    }

    return {
        "lab": "industry_security_controls_benchmark",
        "checks": checks,
        "summary": {
            "checks_passed": sum(1 for value in checks.values() if value),
            "checks_total": len(checks),
            "paired_controls": len(checks),
            "timings_ms": timings_ms,
            "total_timed_ms": round(sum(timings_ms.values()), 2),
        },
        "artifacts": {
            "http": {
                "vulnerable_header_findings": vulnerable_header_findings,
                "hardened_header_findings": hardened_header_findings,
                "vulnerable_cors_risk": vulnerable_cors.get("risk_score"),
                "hardened_cors_risk": hardened_cors.get("risk_score"),
                "vulnerable_sensitive_findings": vulnerable_sensitive.get("total", 0),
                "hardened_sensitive_findings": hardened_sensitive.get("total", 0),
                "vulnerable_redirect_findings": vulnerable_redirect.get("total_findings", 0),
                "hardened_redirect_findings": hardened_redirect.get("total_findings", 0),
                "vulnerable_ssrf_findings": vulnerable_ssrf.get("total_findings", 0),
                "hardened_ssrf_findings": hardened_ssrf.get("total_findings", 0),
                "vulnerable_bola_status": vulnerable_bola.get("http_status"),
                "hardened_bola_status": hardened_bola.get("http_status"),
                "vulnerable_race": vulnerable_http_race.get("summary", {}),
                "hardened_race": hardened_http_race.get("summary", {}),
            },
            "websocket": {
                "vulnerable_subscription": vulnerable_subscription.get("summary", {}),
                "hardened_subscription": hardened_subscription.get("summary", {}),
                "vulnerable_race": vulnerable_ws_race.get("summary", {}),
                "hardened_race": hardened_ws_race.get("summary", {}),
                "vulnerable_origins_accepted": len(vulnerable_origin.get("accepted_origins", [])),
                "hardened_origins_accepted": len(hardened_origin.get("accepted_origins", [])),
            },
        },
    }


def run_validation_scenario() -> dict[str, Any]:
    reset_state()
    with LiveASGIServer(app) as server:
        return asyncio.run(_run_industry_benchmark(f"http://{server.host}:{server.port}"))
