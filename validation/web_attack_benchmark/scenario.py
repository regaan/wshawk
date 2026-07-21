from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any, Awaitable

from validation.common import LiveASGIServer
from validation.web_attack_benchmark.app import app, reset_state
from wshawk.attacks import HTTPAuthzDiffService, HTTPRaceService, HTTPReplayService
from wshawk.transport import WSHawkHTTPProxy
from wshawk.web_pentest import (
    WSHawkBlindProbe,
    WSHawkCORSTester,
    WSHawkCSRFForge,
    WSHawkCrawler,
    WSHawkDirScanner,
    WSHawkFuzzer,
    WSHawkHeaderAnalyzer,
    WSHawkPortScanner,
    WSHawkProtoPolluter,
    WSHawkRedirectHunter,
    WSHawkSensitiveFinder,
    WSHawkTechFingerprinter,
    WSHawkWAFDetector,
)


HERE = Path(__file__).resolve().parent


async def _run_benchmark(base_url: str, port: int) -> dict[str, Any]:
    timings_ms: dict[str, float] = {}

    async def measured(name: str, operation: Awaitable[Any]) -> Any:
        started = time.perf_counter()
        result = await operation
        timings_ms[name] = round((time.perf_counter() - started) * 1000, 2)
        return result

    auth_headers = {"Authorization": "Bearer benchmark-user"}
    proxy = WSHawkHTTPProxy()

    crawler = await measured(
        "crawler",
        WSHawkCrawler().crawl(base_url, max_depth=2, max_pages=20, throttle_ms=0),
    )
    directory = await measured(
        "directory_scanner",
        WSHawkDirScanner().scan_directories(
            base_url,
            exts_raw="txt",
            custom_file=str(HERE / "directories.txt"),
            return_results=True,
        ),
    )
    fuzz = await measured(
        "fuzzer",
        WSHawkFuzzer().run_fuzz(
            method="GET",
            url=f"{base_url}/api/search?q=§FUZZ§",
            wordlist_name="custom",
            custom_file=str(HERE / "wordlist.txt"),
            grep_regex="WSHAWK_BENCHMARK_MARKER",
        ),
    )
    headers = await measured("header_analyzer", WSHawkHeaderAnalyzer().analyze(base_url))
    cors = await measured("cors_tester", WSHawkCORSTester().test(base_url))
    fingerprint = await measured("tech_fingerprint", WSHawkTechFingerprinter().fingerprint(base_url))
    sensitive = await measured(
        "sensitive_finder",
        WSHawkSensitiveFinder().scan_url(f"{base_url}/api/private", headers=auth_headers),
    )
    redirect = await measured(
        "redirect_scanner",
        WSHawkRedirectHunter().scan(
            f"{base_url}/redirect?next=/",
            custom_payloads=["https://benchmark-attacker.example/landing"],
        ),
    )
    ssrf = await measured(
        "ssrf_prober",
        WSHawkBlindProbe().probe(
            f"{base_url}/fetch?url=https://example.org",
            headers=auth_headers,
            custom_payloads=["http://169.254.169.254/latest/meta-data/iam/security-credentials/"],
        ),
    )
    ssrf_negative = await measured(
        "ssrf_false_positive_control",
        WSHawkBlindProbe().probe(f"{base_url}/large-static?url=https://example.org"),
    )
    prototype = await measured("prototype_pollution", WSHawkProtoPolluter().test(f"{base_url}/merge"))
    waf = await measured("waf_detector", WSHawkWAFDetector().detect(f"{base_url}/waf"))

    csrf_engine = WSHawkCSRFForge()
    csrf = await measured(
        "csrf_forge",
        csrf_engine.replay(
            method="POST",
            url=f"{base_url}/transfer",
            headers="Content-Type: application/x-www-form-urlencoded",
            body="amount=10",
            content_type="application/x-www-form-urlencoded",
            http_proxy=proxy,
        ),
    )
    port_scan = await measured(
        "port_scanner",
        WSHawkPortScanner().scan("127.0.0.1", ports=str(port), timeout_s=0.5, grab_banners=False),
    )

    replay = await measured(
        "http_replay",
        HTTPReplayService(http_proxy=proxy).replay(
            project_id="web-attack-benchmark",
            method="GET",
            url=f"{base_url}/api/identity",
            identity={
                "id": "benchmark-admin",
                "alias": "admin",
                "headers": {"Authorization": "Bearer benchmark-admin"},
            },
        ),
    )
    authz = await measured(
        "http_authz_diff",
        HTTPAuthzDiffService(http_proxy=proxy).compare(
            project_id="web-attack-benchmark",
            method="GET",
            url=f"{base_url}/api/identity",
            identities=[
                {
                    "id": "benchmark-user",
                    "alias": "user",
                    "headers": {"Authorization": "Bearer benchmark-user"},
                },
                {
                    "id": "benchmark-admin",
                    "alias": "admin",
                    "headers": {"Authorization": "Bearer benchmark-admin"},
                },
            ],
        ),
    )
    race = await measured(
        "http_race",
        HTTPRaceService(http_proxy=proxy).run(
            project_id="web-attack-benchmark",
            method="POST",
            url=f"{base_url}/api/race",
            body='{"action":"redeem"}',
            headers={"Content-Type": "application/json"},
            concurrency=3,
            waves=2,
            mode="duplicate_action",
        ),
    )

    technology_names = {item["name"] for item in fingerprint.get("technologies", [])}
    sensitive_types = {item["type"] for item in sensitive.get("findings", [])}
    directory_paths = {item["path"] for item in directory.get("findings", [])}
    checks = {
        "crawler_discovers_pages_and_sensitive_files": (
            crawler["stats"]["pages_crawled"] >= 3
            and any(item.get("type") == ".env" for item in crawler.get("sensitive_files", []))
        ),
        "directory_scanner_finds_admin": "/admin" in directory_paths,
        "fuzzer_detects_reflection": any(item.get("grepped") for item in fuzz.get("findings", [])),
        "header_analyzer_handles_http_hsts": headers["strict-transport-security"]["risk"] == "Info",
        "cors_tester_detects_origin_reflection": cors.get("risk_score") == "High" and cors.get("total", 0) >= 4,
        "fingerprinter_detects_stack": {"Express.js", "WordPress", "jQuery"}.issubset(technology_names),
        "sensitive_finder_uses_auth_headers": {"AWS Access Key", "Internal IPv4", "Email Address"}.issubset(sensitive_types),
        "redirect_scanner_detects_external_redirect": redirect.get("total_findings", 0) > 0,
        "ssrf_prober_uses_auth_and_finds_metadata": any(
            finding.get("strong_indicators") for finding in ssrf.get("findings", [])
        ),
        "ssrf_long_page_control_has_no_false_positive": ssrf_negative.get("total_findings") == 0,
        "prototype_pollution_detects_canary": any(
            finding.get("indicators") for finding in prototype.get("findings", [])
        ),
        "waf_detector_identifies_modsecurity": any(
            item.get("name") == "ModSecurity" for item in waf.get("detected", [])
        ),
        "csrf_forge_replays_unprotected_action": csrf.get("exploitable") is True and csrf.get("replay_status") == "200",
        "port_scanner_finds_lab_port": any(item.get("port") == port for item in port_scan.get("open_ports", [])),
        "http_replay_uses_identity": replay.get("http_status") == "200",
        "http_authz_diff_detects_role_change": authz["summary"]["behavior_changed"] is True,
        "http_race_detects_duplicate_success": race["summary"]["suspicious_race_window"] is True,
    }

    return {
        "lab": "web_attack_benchmark",
        "checks": checks,
        "summary": {
            "checks_passed": sum(1 for value in checks.values() if value),
            "checks_total": len(checks),
            "payloads_exercised": (
                int(fuzz.get("count", 0))
                + int(redirect.get("payloads_sent", 0))
                + int(ssrf.get("payloads_sent", 0))
                + int(ssrf_negative.get("payloads_sent", 0))
                + int(prototype.get("tests_run", 0))
                + int(race["summary"].get("attempt_count", 0))
            ),
            "timings_ms": timings_ms,
            "total_timed_ms": round(sum(timings_ms.values()), 2),
        },
        "artifacts": {
            "crawler_stats": crawler.get("stats", {}),
            "directory_findings": len(directory.get("findings", [])),
            "fuzzer_findings": len(fuzz.get("findings", [])),
            "cors_findings": cors.get("total", 0),
            "technologies": sorted(technology_names),
            "sensitive_types": sorted(sensitive_types),
            "redirect_findings": redirect.get("total_findings", 0),
            "ssrf_findings": ssrf.get("total_findings", 0),
            "prototype_findings": prototype.get("total_findings", 0),
            "waf_products": [item.get("name") for item in waf.get("detected", [])],
            "http_authz_summary": authz.get("summary", {}),
            "http_race_summary": race.get("summary", {}),
        },
    }


def run_validation_scenario() -> dict[str, Any]:
    reset_state()
    with LiveASGIServer(app) as server:
        return asyncio.run(_run_benchmark(f"http://{server.host}:{server.port}", server.port))
