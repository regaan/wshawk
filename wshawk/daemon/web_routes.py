import asyncio
from typing import Any, Dict

from fastapi import HTTPException

from wshawk.web_pentest import (
    WSHawkBlindProbe,
    WSHawkCORSTester,
    WSHawkCSRFForge,
    WSHawkCrawler,
    WSHawkDirScanner,
    WSHawkDNSLookup,
    WSHawkFuzzer,
    WSHawkHeaderAnalyzer,
    WSHawkPortScanner,
    WSHawkProtoPolluter,
    WSHawkRedirectHunter,
    WSHawkReportGenerator,
    WSHawkSensitiveFinder,
    WSHawkSSLAnalyzer,
    WSHawkSubdomainFinder,
    WSHawkTechFingerprinter,
    WSHawkVulnScanner,
    WSHawkWAFDetector,
)

from .context import BridgeContext
from .session_routes import register_session_routes
from .web_route_support import build_web_route_helpers
from .web_workflow_routes import register_web_workflow_routes


def register_web_routes(ctx: BridgeContext) -> None:
    helpers = build_web_route_helpers(ctx)
    runtime = helpers["runtime"]
    _normalize_headers = helpers["_normalize_headers"]
    _normalize_cookies = helpers["_normalize_cookies"]
    _normalize_body = helpers["_normalize_body"]
    _is_json_content_type = helpers["_is_json_content_type"]
    _decode_nested_json = helpers["_decode_nested_json"]
    _normalize_http_request_body = helpers["_normalize_http_request_body"]
    _build_state = helpers["_build_state"]
    _attach_state = helpers["_attach_state"]
    _complete_attack = helpers["_complete_attack"]
    _fail_attack = helpers["_fail_attack"]
    _persist_findings = helpers["_persist_findings"]
    _run_background = helpers["_run_background"]
    _normalize_dir_findings = helpers["_normalize_dir_findings"]
    _run_vuln_wrapper = helpers["_run_vuln_wrapper"]
    @ctx.app.post("/web/request")
    async def web_request(data: Dict[str, Any]):
        url = data.get("url", "").strip()
        if not url:
            raise HTTPException(status_code=400, detail="URL is required")

        request_headers = _normalize_headers(data.get("headers"))
        body = _normalize_http_request_body(data.get("body", ""), request_headers)
        state = _build_state(
            data,
            attack_type="http_request",
            target_url=url,
            parameters={"method": data.get("method", "GET")},
        )

        try:
            result = await ctx.http_proxy_service.send_request(
                method=data.get("method", "GET"),
                url=url,
                headers=state["request_context"].headers,
                body=body,
                cookies=state["request_context"].cookies,
                project_id=state.get("project_id"),
                correlation_id=state["request_context"].correlation_id,
                attack_run_id=state.get("attack_run_id"),
                metadata={
                    "source": "http_forge",
                    "identity_id": state.get("identity_id"),
                },
            )
            summary = {
                "method": data.get("method", "GET"),
                "status": result.get("status"),
                "body_length": len(result.get("body", "")),
                "flow_id": result.get("flow_id"),
                "error": result.get("error", ""),
            }
            if result.get("error"):
                runtime.fail_attack(state.get("attack_run_id"), summary)
            else:
                _complete_attack(
                    state,
                    summary,
                    note_title="HTTP request replayed",
                    note_body=f"{data.get('method', 'GET')} {url} completed with status {result.get('status')}.",
                )
            ctx.maybe_log_platform_event(
                state.get("project_id"),
                "http_request_replayed",
                payload=summary,
                target=url,
            )
            return _attach_state(result, state)
        except ValueError as exc:
            _fail_attack(state, exc, title="HTTP request replay failure")
            raise HTTPException(status_code=400, detail=str(exc))
        except Exception as exc:
            _fail_attack(state, exc, title="HTTP request replay failure")
            raise HTTPException(status_code=500, detail=str(exc))

    @ctx.app.post("/web/fuzz")
    async def web_fuzz(data: Dict[str, Any]):
        url = data.get("url", "")
        if not url or "§FUZZ§" not in url and "§FUZZ§" not in _normalize_body(data.get("body", "")):
            raise HTTPException(status_code=400, detail="URL or body must contain §FUZZ§ marker.")

        body = _normalize_body(data.get("body", ""))
        state = _build_state(
            data,
            attack_type="http_fuzz",
            target_url=url,
            parameters={
                "method": data.get("method", "GET"),
                "wordlist": data.get("wordlist", "common"),
                "encoder": data.get("encoder", "none"),
            },
        )

        async def _task():
            engine = WSHawkFuzzer(sio_instance=ctx.sio, http_proxy=ctx.http_proxy_service)
            result = await engine.run_fuzz(
                method=data.get("method", "GET"),
                url=url,
                body=body,
                headers=state["request_context"].headers,
                cookies=state["request_context"].cookies,
                wordlist_name=data.get("wordlist", "common"),
                custom_file=data.get("custom_file"),
                encoder=data.get("encoder", "none"),
                grep_regex=data.get("grep_regex", ""),
                project_id=state.get("project_id"),
                correlation_id=state["request_context"].correlation_id,
                attack_run_id=state.get("attack_run_id"),
                metadata={
                    "module": "web_routes",
                    "identity_id": state.get("identity_id"),
                },
            )
            findings = WSHawkVulnScanner._normalize_fuzz_findings(url, result.get("findings", []))
            _persist_findings(
                state,
                target_url=url,
                category="http_fuzz",
                findings=findings,
                default_severity="medium",
            )
            _complete_attack(
                state,
                {
                    "payload_count": result.get("count", 0),
                    "finding_count": len(findings),
                },
                note_title="HTTP fuzz completed",
                note_body=f"Fuzzed {result.get('count', 0)} payloads against {url} with {len(findings)} suspicious responses.",
            )

        asyncio.create_task(_run_background("http_fuzz", state, _task()))
        return _attach_state({"status": "started", "msg": "Fuzz task submitted"}, state)

    @ctx.app.post("/web/dirscan")
    async def web_dirscan(data: Dict[str, Any]):
        url = data.get("url", "").strip()
        if not url:
            raise HTTPException(status_code=400, detail="URL required")

        state = _build_state(
            data,
            attack_type="dirscan",
            target_url=url,
            parameters={
                "exts": data.get("exts", ""),
                "recursive": bool(data.get("recursive", False)),
            },
        )

        async def _task():
            engine = WSHawkDirScanner(sio_instance=ctx.sio, http_proxy=ctx.http_proxy_service)
            result = await engine.scan_directories(
                url=url,
                exts_raw=data.get("exts", ""),
                custom_file=data.get("custom_file", ""),
                recursive=data.get("recursive", False),
                throttle_ms=int(data.get("throttle_ms", 0)),
                headers=state["request_context"].headers,
                cookies=state["request_context"].cookies,
                project_id=state.get("project_id"),
                correlation_id=state["request_context"].correlation_id,
                attack_run_id=state.get("attack_run_id"),
                identity_id=state.get("identity_id"),
                return_results=True,
            )
            findings = _normalize_dir_findings(result)
            _persist_findings(
                state,
                target_url=url,
                category="content_exposure",
                findings=findings,
                default_severity="medium",
            )
            _complete_attack(
                state,
                {
                    "queued_words": result.get("count", 0),
                    "discovered_count": len(result.get("findings", [])),
                    "directory_count": len(result.get("discovered_directories", [])),
                },
                note_title="Directory scan completed",
                note_body=f"Directory scan against {url} produced {len(result.get('findings', []))} candidate paths.",
            )

        asyncio.create_task(_run_background("dirscan", state, _task()))
        return _attach_state({"status": "started", "msg": "Dirscan task submitted"}, state)

    @ctx.app.post("/web/headers")
    async def web_headers(data: Dict[str, Any]):
        url = data.get("url", "").strip()
        if not url:
            raise HTTPException(status_code=400, detail="URL required")

        state = _build_state(data, attack_type="header_analysis", target_url=url)
        try:
            result = await WSHawkHeaderAnalyzer(http_proxy=ctx.http_proxy_service).analyze(
                url,
                project_id=state.get("project_id"),
                correlation_id=state["request_context"].correlation_id,
                attack_run_id=state.get("attack_run_id"),
                headers=state["request_context"].headers,
                cookies=state["request_context"].cookies,
                identity_id=state.get("identity_id"),
            )
            findings = []
            for header_name, evaluation in result.items():
                if evaluation.get("risk") in ("High", "Medium"):
                    findings.append(
                        {
                            "title": f"Insecure header: {header_name}",
                            "detail": evaluation.get("msg", ""),
                            "severity": evaluation.get("risk", "Medium").lower(),
                            "header": header_name,
                            "value": evaluation.get("value", ""),
                        }
                    )
            _persist_findings(
                state,
                target_url=url,
                category="header_analysis",
                findings=findings,
                default_severity="medium",
            )
            _complete_attack(
                state,
                {"finding_count": len(findings)},
                note_title="Header analysis completed",
                note_body=f"Header analysis against {url} produced {len(findings)} flagged headers.",
            )
            return _attach_state({"status": "success", "headers": result}, state)
        except ValueError as exc:
            _fail_attack(state, exc, title="Header analysis failure")
            raise HTTPException(status_code=400, detail=str(exc))
        except Exception as exc:
            _fail_attack(state, exc, title="Header analysis failure")
            raise HTTPException(status_code=500, detail=str(exc))

    @ctx.app.post("/web/subdomains")
    async def web_subdomains(data: Dict[str, Any]):
        target = data.get("target", "").strip()
        if not target:
            raise HTTPException(status_code=400, detail="Target domain required")

        state = _build_state(data, attack_type="subdomain_enumeration", target_url=f"https://{target}")
        try:
            engine = WSHawkSubdomainFinder(sio_instance=ctx.sio)
            subs = await engine.list_subdomains(
                target=target,
                active_brute=data.get("active_brute", False),
                active_resolve=data.get("active_resolve", True),
            )
            if state.get("project_id"):
                for subdomain in subs:
                    ctx.platform_store.ensure_target(state["project_id"], f"https://{subdomain}", kind="domain")
            _complete_attack(
                state,
                {"subdomain_count": len(subs)},
                note_title="Subdomain enumeration completed",
                note_body=f"Resolved {len(subs)} subdomains for {target}.",
            )
            return _attach_state({"status": "success", "subdomains": subs}, state)
        except Exception as exc:
            _fail_attack(state, exc, title="Subdomain enumeration failure")
            raise HTTPException(status_code=500, detail=str(exc))

    @ctx.app.post("/web/crawl")
    async def web_crawl(data: Dict[str, Any]):
        url = data.get("url", "").strip()
        if not url:
            raise HTTPException(status_code=400, detail="URL required")

        state = _build_state(
            data,
            attack_type="web_crawl",
            target_url=url,
            parameters={
                "max_depth": int(data.get("max_depth", 3)),
                "max_pages": int(data.get("max_pages", 100)),
            },
        )

        async def _task():
            engine = WSHawkCrawler(sio_instance=ctx.sio, http_proxy=ctx.http_proxy_service)
            result = await engine.crawl(
                start_url=url,
                max_depth=int(data.get("max_depth", 3)),
                max_pages=int(data.get("max_pages", 100)),
                headers=state["request_context"].headers,
                cookies=state["request_context"].cookies,
                project_id=state.get("project_id"),
                correlation_id=state["request_context"].correlation_id,
                attack_run_id=state.get("attack_run_id"),
                identity_id=state.get("identity_id"),
            )
            runtime.record_csrf_tokens(
                project_id=state.get("project_id"),
                identity_id=state.get("identity_id"),
                url=url,
                csrf_tokens=result.get("csrf_tokens", []),
                source="web_crawl",
                correlation_id=state["request_context"].correlation_id,
            )
            findings = [
                {
                    "title": f"Sensitive file exposed: {item.get('type', 'unknown')}",
                    "detail": "Crawler discovered a sensitive file exposed at the target root.",
                    "severity": "high",
                    "url": item.get("url", url),
                    "payload": item,
                }
                for item in result.get("sensitive_files", [])
            ]
            _persist_findings(
                state,
                target_url=url,
                category="sensitive_file",
                findings=findings,
                default_severity="high",
            )
            stats = result.get("stats", {})
            _complete_attack(
                state,
                stats,
                note_title="Web crawl completed",
                note_body=f"Crawled {stats.get('pages_crawled', 0)} pages from {url} with {len(result.get('csrf_tokens', []))} CSRF token candidates.",
            )

        asyncio.create_task(_run_background("web_crawl", state, _task()))
        return _attach_state({"status": "started", "msg": "Crawl task submitted"}, state)

    @ctx.app.post("/web/vulnscan")
    async def web_vulnscan(data: Dict[str, Any]):
        url = data.get("url", "").strip()
        if not url:
            raise HTTPException(status_code=400, detail="Target URL required")

        ctx._vuln_scanner = WSHawkVulnScanner(
            sio_instance=ctx.sio,
            db=ctx.db,
            store=ctx.platform_store,
            http_proxy=ctx.http_proxy_service,
        )
        options = dict(data.get("options", {}))
        for key in ("project_id", "identity_id", "identity_alias", "correlation_id", "headers", "cookies"):
            if key in data and key not in options:
                options[key] = data.get(key)

        asyncio.create_task(_run_vuln_wrapper(url, options))
        return {"status": "started", "msg": "Vulnerability scan submitted", "project_id": options.get("project_id")}

    @ctx.app.post("/web/vulnscan/stop")
    async def web_vulnscan_stop():
        if ctx._vuln_scanner:
            ctx._vuln_scanner.stop()
        return {"status": "stopped"}

    @ctx.app.get("/history")
    async def api_get_history():
        try:
            return {"status": "success", "history": ctx.db.list_all()}
        except Exception as exc:
            ctx.logger.exception("Unexpected scan history listing failure")
            raise HTTPException(status_code=500, detail="Scan history listing failed") from exc

    @ctx.app.get("/history/{scan_id}")
    async def api_get_scan(scan_id: str):
        try:
            scan = ctx.db.get(scan_id)
            if not scan:
                raise HTTPException(status_code=404, detail="Scan not found")
            return {"status": "success", "scan": scan}
        except HTTPException:
            raise
        except Exception as exc:
            ctx.logger.exception("Unexpected scan history lookup failure")
            raise HTTPException(status_code=500, detail="Scan history lookup failed") from exc

    @ctx.app.get("/history/compare/{id1}/{id2}")
    async def api_compare_scans(id1: str, id2: str):
        try:
            res = ctx.db.compare_scans(id1, id2)
            if "error" in res:
                raise HTTPException(status_code=404, detail=res["error"])
            return {"status": "success", "diff": res}
        except HTTPException:
            raise
        except Exception as exc:
            ctx.logger.exception("Unexpected scan comparison failure")
            raise HTTPException(status_code=500, detail="Scan comparison failed") from exc

    @ctx.app.post("/web/report")
    async def web_report(data: Dict[str, Any]):
        gen = WSHawkReportGenerator()
        fmt = data.get("format", "html")
        try:
            report_data = data.get("report", {})
            if fmt == "json":
                path = gen.generate_json(report_data)
            elif fmt == "pdf":
                path = gen.generate_pdf(report_data)
            else:
                path = gen.generate_html(report_data)
            return {"status": "success", "path": path, "format": fmt}
        except Exception as exc:
            ctx.logger.exception("Unexpected report generation failure")
            raise HTTPException(status_code=500, detail="Report generation failed") from exc

    @ctx.app.post("/web/fingerprint")
    async def web_fingerprint(data: Dict[str, Any]):
        url = data.get("url", "").strip()
        if not url:
            raise HTTPException(status_code=400, detail="URL required")

        state = _build_state(data, attack_type="tech_fingerprint", target_url=url)
        try:
            result = await WSHawkTechFingerprinter(http_proxy=ctx.http_proxy_service).fingerprint(
                url,
                project_id=state.get("project_id"),
                correlation_id=state["request_context"].correlation_id,
                attack_run_id=state.get("attack_run_id"),
                headers=state["request_context"].headers,
                cookies=state["request_context"].cookies,
                identity_id=state.get("identity_id"),
            )
            _complete_attack(
                state,
                {"fingerprint_keys": sorted(result.keys())},
                note_title="Tech fingerprint completed",
                note_body=f"Captured technology fingerprint for {url}.",
            )
            return _attach_state({"status": "success", **result}, state)
        except Exception as exc:
            _fail_attack(state, exc, title="Tech fingerprint failure")
            raise HTTPException(status_code=500, detail=str(exc))

    @ctx.app.post("/web/ssl")
    async def web_ssl(data: Dict[str, Any]):
        host = data.get("host", "").strip()
        if not host:
            raise HTTPException(status_code=400, detail="Host required")

        state = _build_state(data, attack_type="ssl_analysis", target_url=f"https://{host}")
        try:
            result = await WSHawkSSLAnalyzer().analyze(host, port=int(data.get("port", 443)))
            _complete_attack(
                state,
                {"host": host, "port": int(data.get("port", 443))},
                note_title="SSL analysis completed",
                note_body=f"Collected SSL analysis for {host}.",
            )
            return _attach_state({"status": "success", **result}, state)
        except Exception as exc:
            _fail_attack(state, exc, title="SSL analysis failure")
            raise HTTPException(status_code=500, detail=str(exc))

    @ctx.app.post("/web/sensitive")
    async def web_sensitive(data: Dict[str, Any]):
        url = data.get("url", "").strip()
        if not url:
            raise HTTPException(status_code=400, detail="URL required")

        state = _build_state(data, attack_type="sensitive_data_scan", target_url=url)
        try:
            result = await WSHawkSensitiveFinder(
                sio_instance=ctx.sio,
                http_proxy=ctx.http_proxy_service,
            ).scan_url(
                url,
                project_id=state.get("project_id"),
                correlation_id=state["request_context"].correlation_id,
                attack_run_id=state.get("attack_run_id"),
                headers=state["request_context"].headers,
                cookies=state["request_context"].cookies,
                identity_id=state.get("identity_id"),
            )
            _persist_findings(
                state,
                target_url=url,
                category="sensitive_data",
                findings=[
                    {
                        "title": f"Sensitive data exposure: {item.get('type', 'unknown')}",
                        "detail": f"Potential sensitive value leaked in response ({item.get('value', '')}).",
                        "severity": str(item.get("severity", "Medium")).lower(),
                        "payload": item,
                    }
                    for item in result.get("findings", [])
                ],
                default_severity="medium",
            )
            _complete_attack(
                state,
                {"finding_count": result.get("total", 0)},
                note_title="Sensitive data scan completed",
                note_body=f"Sensitive scan against {url} returned {result.get('total', 0)} findings.",
            )
            return _attach_state({"status": "success", **result}, state)
        except Exception as exc:
            _fail_attack(state, exc, title="Sensitive data scan failure")
            raise HTTPException(status_code=500, detail=str(exc))

    @ctx.app.post("/web/waf")
    async def web_waf_detect(data: Dict[str, Any]):
        url = data.get("url", "").strip()
        if not url:
            raise HTTPException(status_code=400, detail="URL required")

        state = _build_state(data, attack_type="waf_detection", target_url=url)
        try:
            result = await WSHawkWAFDetector(http_proxy=ctx.http_proxy_service).detect(
                url,
                project_id=state.get("project_id"),
                correlation_id=state["request_context"].correlation_id,
                attack_run_id=state.get("attack_run_id"),
                headers=state["request_context"].headers,
                cookies=state["request_context"].cookies,
                identity_id=state.get("identity_id"),
            )
            _complete_attack(
                state,
                {"detected": bool(result.get("detected")), "product": result.get("product", "")},
                note_title="WAF detection completed",
                note_body=f"WAF detection against {url} completed.",
            )
            return _attach_state({"status": "success", **result}, state)
        except ValueError as exc:
            _fail_attack(state, exc, title="WAF detection failure")
            raise HTTPException(status_code=400, detail=str(exc))
        except Exception as exc:
            _fail_attack(state, exc, title="WAF detection failure")
            raise HTTPException(status_code=500, detail=str(exc))

    @ctx.app.post("/web/cors")
    async def web_cors_test(data: Dict[str, Any]):
        url = data.get("url", "").strip()
        if not url:
            raise HTTPException(status_code=400, detail="URL required")

        state = _build_state(data, attack_type="cors_test", target_url=url)
        try:
            result = await WSHawkCORSTester(http_proxy=ctx.http_proxy_service).test(
                url,
                project_id=state.get("project_id"),
                correlation_id=state["request_context"].correlation_id,
                attack_run_id=state.get("attack_run_id"),
                headers=state["request_context"].headers,
                cookies=state["request_context"].cookies,
                identity_id=state.get("identity_id"),
            )
            _persist_findings(
                state,
                target_url=url,
                category="cors_misconfiguration",
                findings=[
                    {
                        "title": f"CORS misconfiguration: {item.get('test', 'unknown')}",
                        "detail": item.get("detail", ""),
                        "severity": str(item.get("severity", "Medium")).lower(),
                        "payload": item,
                    }
                    for item in result.get("findings", [])
                ],
                default_severity="medium",
            )
            _complete_attack(
                state,
                {"risk_score": result.get("risk_score"), "finding_count": result.get("total", 0)},
                note_title="CORS testing completed",
                note_body=f"CORS testing against {url} produced risk score {result.get('risk_score')}.",
            )
            return _attach_state({"status": "success", **result}, state)
        except ValueError as exc:
            _fail_attack(state, exc, title="CORS testing failure")
            raise HTTPException(status_code=400, detail=str(exc))
        except Exception as exc:
            _fail_attack(state, exc, title="CORS testing failure")
            raise HTTPException(status_code=500, detail=str(exc))

    @ctx.app.post("/web/portscan")
    async def web_portscan(data: Dict[str, Any]):
        host = data.get("host", "").strip()
        if not host:
            raise HTTPException(status_code=400, detail="Host required")
        asyncio.create_task(
            WSHawkPortScanner(sio_instance=ctx.sio).scan(
                host=host,
                ports=data.get("ports"),
                preset=data.get("preset", "top100"),
                timeout_s=float(data.get("timeout", 2.0)),
                grab_banners=data.get("banners", True),
            )
        )
        return {"status": "started", "msg": "Port scan submitted"}

    @ctx.app.post("/web/dns")
    async def web_dns_lookup(data: Dict[str, Any]):
        domain = data.get("domain", "").strip()
        if not domain:
            raise HTTPException(status_code=400, detail="Domain required")
        try:
            return {"status": "success", **await WSHawkDNSLookup().lookup(domain)}
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        except Exception as exc:
            ctx.logger.exception("Unexpected DNS lookup failure")
            raise HTTPException(status_code=500, detail="DNS lookup failed") from exc

    @ctx.app.post("/web/csrf")
    async def web_csrf_forge(data: Dict[str, Any]):
        url = data.get("url", "").strip()
        if not url:
            raise HTTPException(status_code=400, detail="URL required")

        body = _normalize_body(data.get("body", ""))
        state = _build_state(
            data,
            attack_type="csrf_forge" if not data.get("replay") else "csrf_replay",
            target_url=url,
            parameters={"method": data.get("method", "POST")},
        )
        try:
            engine = WSHawkCSRFForge()
            if data.get("replay"):
                result = await engine.replay(
                    method=data.get("method", "POST"),
                    url=url,
                    headers=runtime.build_headers_string(state["request_context"].headers),
                    body=body,
                    content_type=data.get("content_type", ""),
                    http_proxy=ctx.http_proxy_service,
                    project_id=state.get("project_id"),
                    correlation_id=state["request_context"].correlation_id,
                    attack_run_id=state.get("attack_run_id"),
                    cookies=state["request_context"].cookies,
                    identity_id=state.get("identity_id"),
                )
            else:
                result = await engine.generate(
                    method=data.get("method", "POST"),
                    url=url,
                    headers=runtime.build_headers_string(state["request_context"].headers),
                    body=body,
                    content_type=data.get("content_type", ""),
                )

            findings = []
            if result.get("exploitable"):
                findings.append(
                    {
                        "title": "Potential CSRF replay path",
                        "detail": "Generated a CSRF proof-of-concept without detecting a required anti-CSRF token.",
                        "severity": "high",
                        "payload": {
                            "csrf_tokens_found": result.get("csrf_tokens_found", []),
                            "replayed": result.get("replayed", False),
                            "replay_status": result.get("replay_status"),
                        },
                    }
                )
            _persist_findings(
                state,
                target_url=url,
                category="csrf",
                findings=findings,
                default_severity="high",
            )
            _complete_attack(
                state,
                {
                    "csrf_tokens_found": len(result.get("csrf_tokens_found", [])),
                    "replayed": bool(result.get("replayed")),
                    "replay_status": result.get("replay_status"),
                },
                note_title="CSRF analysis completed",
                note_body=f"CSRF {'replay' if data.get('replay') else 'forge'} completed for {url}.",
            )
            return _attach_state({"status": "success", **result}, state)
        except ValueError as exc:
            _fail_attack(state, exc, title="CSRF analysis failure")
            raise HTTPException(status_code=400, detail=str(exc))
        except Exception as exc:
            _fail_attack(state, exc, title="CSRF analysis failure")
            raise HTTPException(status_code=500, detail=str(exc))

    @ctx.app.post("/web/ssrf")
    async def web_ssrf_probe(data: Dict[str, Any]):
        url = data.get("url", "").strip()
        if not url:
            raise HTTPException(status_code=400, detail="URL required")

        body = _normalize_body(data.get("body", ""))
        state = _build_state(
            data,
            attack_type="ssrf_probe",
            target_url=url,
            parameters={"method": data.get("method", "GET"), "param": data.get("param", "")},
        )

        async def _task():
            result = await WSHawkBlindProbe(sio_instance=ctx.sio, http_proxy=ctx.http_proxy_service).probe(
                url=url,
                param=data.get("param", ""),
                method=data.get("method", "GET"),
                body=body,
                custom_payloads=data.get("custom_payloads", []),
                project_id=state.get("project_id"),
                correlation_id=state["request_context"].correlation_id,
                attack_run_id=state.get("attack_run_id"),
                headers=state["request_context"].headers,
                cookies=state["request_context"].cookies,
                identity_id=state.get("identity_id"),
            )
            _persist_findings(
                state,
                target_url=url,
                category="ssrf",
                findings=[
                    {
                        "title": f"Potential SSRF via parameter {item.get('param', 'unknown')}",
                        "detail": f"Payload {item.get('payload', '')} triggered SSRF indicators: {', '.join(item.get('indicators', [])) or 'response anomaly'}.",
                        "severity": str(item.get("severity", "Medium")).lower(),
                        "payload": item,
                    }
                    for item in result.get("findings", [])
                ],
                default_severity="medium",
            )
            _complete_attack(
                state,
                {
                    "params_tested": result.get("params_tested", []),
                    "payloads_sent": result.get("payloads_sent", 0),
                    "finding_count": result.get("total_findings", 0),
                },
                note_title="SSRF probe completed",
                note_body=f"SSRF probing against {url} tested {result.get('payloads_sent', 0)} payloads.",
            )

        asyncio.create_task(_run_background("ssrf_probe", state, _task()))
        return _attach_state({"status": "started", "msg": "SSRF probe started"}, state)

    @ctx.app.post("/web/redirect")
    async def web_redirect_scan(data: Dict[str, Any]):
        url = data.get("url", "").strip()
        if not url:
            raise HTTPException(status_code=400, detail="URL required")

        state = _build_state(
            data,
            attack_type="redirect_scan",
            target_url=url,
            parameters={"param": data.get("param", "")},
        )
        try:
            result = await WSHawkRedirectHunter(sio_instance=ctx.sio, http_proxy=ctx.http_proxy_service).scan(
                url=url,
                param=data.get("param", ""),
                custom_payloads=data.get("custom_payloads", []),
                project_id=state.get("project_id"),
                correlation_id=state["request_context"].correlation_id,
                attack_run_id=state.get("attack_run_id"),
                headers=state["request_context"].headers,
                cookies=state["request_context"].cookies,
                identity_id=state.get("identity_id"),
            )
            _persist_findings(
                state,
                target_url=url,
                category="open_redirect",
                findings=[
                    {
                        "title": f"Open redirect via {item.get('param', 'unknown')}",
                        "detail": f"{item.get('redirect_type', 'Redirect')} to {item.get('redirect_to', '')}.",
                        "severity": str(item.get("severity", "Medium")).lower(),
                        "payload": item,
                    }
                    for item in result.get("findings", [])
                ],
                default_severity="medium",
            )
            _complete_attack(
                state,
                {
                    "params_tested": result.get("params_tested", []),
                    "payloads_sent": result.get("payloads_sent", 0),
                    "finding_count": result.get("total_findings", 0),
                },
                note_title="Redirect scan completed",
                note_body=f"Redirect testing against {url} produced {result.get('total_findings', 0)} findings.",
            )
            return _attach_state({"status": "success", **result}, state)
        except ValueError as exc:
            _fail_attack(state, exc, title="Redirect scan failure")
            raise HTTPException(status_code=400, detail=str(exc))
        except Exception as exc:
            _fail_attack(state, exc, title="Redirect scan failure")
            raise HTTPException(status_code=500, detail=str(exc))

    @ctx.app.post("/web/proto")
    async def web_proto_pollute(data: Dict[str, Any]):
        url = data.get("url", "").strip()
        if not url:
            raise HTTPException(status_code=400, detail="URL required")

        body = _normalize_body(data.get("body", ""))
        state = _build_state(
            data,
            attack_type="prototype_pollution",
            target_url=url,
            parameters={"method": data.get("method", "GET")},
        )
        try:
            result = await WSHawkProtoPolluter(
                sio_instance=ctx.sio,
                http_proxy=ctx.http_proxy_service,
            ).test(
                url=url,
                method=data.get("method", "GET"),
                body=body,
                content_type=data.get("content_type", ""),
                project_id=state.get("project_id"),
                correlation_id=state["request_context"].correlation_id,
                attack_run_id=state.get("attack_run_id"),
                headers=state["request_context"].headers,
                cookies=state["request_context"].cookies,
                identity_id=state.get("identity_id"),
            )
            _persist_findings(
                state,
                target_url=url,
                category="prototype_pollution",
                findings=[
                    {
                        "title": f"Prototype pollution via {item.get('vector', 'unknown')}",
                        "detail": f"Payload {item.get('payload', '')} triggered indicators {item.get('indicators', [])}.",
                        "severity": str(item.get("severity", "Medium")).lower(),
                        "payload": item,
                    }
                    for item in result.get("findings", [])
                ],
                default_severity="medium",
            )
            _complete_attack(
                state,
                {
                    "tests_run": result.get("tests_run", 0),
                    "finding_count": result.get("total_findings", 0),
                },
                note_title="Prototype pollution testing completed",
                note_body=f"Prototype pollution testing against {url} ran {result.get('tests_run', 0)} probes.",
            )
            return _attach_state({"status": "success", **result}, state)
        except ValueError as exc:
            _fail_attack(state, exc, title="Prototype pollution failure")
            raise HTTPException(status_code=400, detail=str(exc))
        except Exception as exc:
            _fail_attack(state, exc, title="Prototype pollution failure")
            raise HTTPException(status_code=500, detail=str(exc))

    register_web_workflow_routes(ctx, helpers)
    register_session_routes(ctx)
