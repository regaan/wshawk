import asyncio
import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import HTTPException

from wshawk.web_pentest import (
    WebPentestPlatformRuntime,
    WSHawkAttackChainer,
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
    WSHawkProxyCA,
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


def _sanitize_session_snapshot(raw_session: Dict[str, Any]) -> Dict[str, Any]:
    session = raw_session if isinstance(raw_session, dict) else {}
    snapshots = session.get("snapshots") if isinstance(session.get("snapshots"), dict) else {}

    tables = {}
    for key, rows in list((snapshots.get("tables") or {}).items())[:32]:
        if not isinstance(rows, list):
            continue
        sanitized_rows = []
        for row in rows[:500]:
            if not isinstance(row, list):
                continue
            sanitized_rows.append([str(cell)[:4096] for cell in row[:16]])
        tables[str(key)[:128]] = sanitized_rows

    sections = {}
    for key, value in list((snapshots.get("sections") or {}).items())[:32]:
        sections[str(key)[:128]] = str(value)[:65536]

    stats = {}
    for key, value in list((snapshots.get("stats") or {}).items())[:64]:
        stats[str(key)[:128]] = str(value)[:256]

    return {
        "target": str(session.get("target", ""))[:4096],
        "snapshots": {
            "tables": tables,
            "sections": sections,
            "stats": stats,
        },
    }


def register_web_routes(ctx: BridgeContext) -> None:
    runtime = WebPentestPlatformRuntime(ctx.db, ctx.platform_store, ctx.http_proxy_service)

    def _normalize_headers(raw: Any) -> Dict[str, str]:
        if isinstance(raw, dict):
            return {str(key): str(value) for key, value in raw.items() if value is not None}
        if isinstance(raw, str):
            return ctx.http_proxy_service.parse_headers(raw)
        return {}

    def _normalize_cookies(raw: Any) -> Dict[str, str]:
        if isinstance(raw, dict):
            return {str(key): str(value) for key, value in raw.items() if value is not None}
        if isinstance(raw, list):
            cookies: Dict[str, str] = {}
            for item in raw:
                if isinstance(item, dict) and item.get("name"):
                    cookies[str(item["name"])] = str(item.get("value", ""))
            return cookies
        if isinstance(raw, str):
            cookies = {}
            for pair in raw.split(";"):
                if "=" not in pair:
                    continue
                key, value = pair.split("=", 1)
                cookies[key.strip()] = value.strip()
            return cookies
        return {}

    def _normalize_body(raw: Any) -> str:
        if raw is None:
            return ""
        if isinstance(raw, (dict, list)):
            return json.dumps(raw)
        return str(raw)

    def _is_json_content_type(headers: Dict[str, str]) -> bool:
        content_type = ""
        for key, value in headers.items():
            if str(key).lower() == "content-type":
                content_type = str(value).lower()
                break
        return "application/json" in content_type or content_type.endswith("+json")

    def _decode_nested_json(raw: Any, max_depth: int = 2) -> Any:
        value = raw
        for _ in range(max_depth):
            if not isinstance(value, str):
                break
            stripped = value.strip()
            if not stripped:
                break
            try:
                decoded = json.loads(stripped)
            except (TypeError, ValueError, json.JSONDecodeError):
                break
            if decoded == value:
                break
            value = decoded
        return value

    def _normalize_http_request_body(raw: Any, headers: Dict[str, str]) -> Any:
        if raw is None:
            return ""
        if isinstance(raw, (dict, list)):
            return raw
        if isinstance(raw, str):
            decoded = _decode_nested_json(raw)
            if isinstance(decoded, (dict, list)):
                return decoded
        return raw

    def _build_state(
        data: Dict[str, Any],
        *,
        attack_type: str,
        target_url: str = "",
        parameters: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        project_id = data.get("project_id")
        if project_id:
            ctx.require_platform_project(project_id)

        request_context = runtime.resolve_request_context(
            project_id=project_id,
            identity_id=data.get("identity_id"),
            identity_alias=data.get("identity_alias"),
            headers=_normalize_headers(data.get("headers")),
            cookies=_normalize_cookies(data.get("cookies")),
            correlation_id=str(data.get("correlation_id", "") or ""),
        )

        attack_run = runtime.start_attack(
            project_id=project_id,
            attack_type=attack_type,
            target_url=target_url,
            identity=request_context.identity,
            parameters=parameters or {},
        )
        return {
            "project_id": project_id,
            "request_context": request_context,
            "attack_run": attack_run,
            "attack_run_id": attack_run.get("id") if attack_run else None,
            "identity_id": request_context.identity.get("id") if request_context.identity else None,
            "identity_alias": request_context.identity.get("alias") if request_context.identity else None,
        }

    def _attach_state(payload: Dict[str, Any], state: Dict[str, Any]) -> Dict[str, Any]:
        enriched = dict(payload)
        enriched["project_id"] = state.get("project_id")
        enriched["attack_run_id"] = state.get("attack_run_id")
        enriched["correlation_id"] = state["request_context"].correlation_id
        if state.get("identity_id"):
            enriched["identity_id"] = state["identity_id"]
        if state.get("identity_alias"):
            enriched["identity_alias"] = state["identity_alias"]
        return enriched

    def _complete_attack(
        state: Dict[str, Any],
        summary: Dict[str, Any],
        *,
        note_title: str = "",
        note_body: str = "",
        status: str = "completed",
    ) -> None:
        runtime.complete_attack(state.get("attack_run_id"), summary, status=status)
        if state.get("project_id") and note_title and note_body:
            runtime.add_note(state["project_id"], note_title, note_body)

    def _fail_attack(state: Dict[str, Any], exc: Exception, *, title: str) -> None:
        summary = {"error": str(exc)}
        runtime.fail_attack(state.get("attack_run_id"), summary)
        if state.get("project_id"):
            runtime.add_note(state["project_id"], title, str(exc))

    def _persist_findings(
        state: Dict[str, Any],
        *,
        target_url: str,
        category: str,
        findings: List[Dict[str, Any]],
        default_severity: str = "medium",
    ) -> List[Dict[str, Any]]:
        stored = runtime.add_findings(
            project_id=state.get("project_id"),
            attack_run_id=state.get("attack_run_id"),
            target_url=target_url,
            category=category,
            findings=findings,
            default_severity=default_severity,
        )
        if findings and state.get("project_id"):
            ctx.maybe_store_platform_evidence(
                state["project_id"],
                title=f"{category.replace('_', ' ').title()} findings",
                category=category,
                payload={"findings": findings, "stored_count": len(stored)},
                severity=default_severity,
            )
        return stored

    async def _run_background(label: str, state: Dict[str, Any], coro):
        try:
            await coro
        except Exception as exc:  # pragma: no cover - defensive logging path
            _fail_attack(state, exc, title=f"{label} failure")
            if ctx.sio:
                await ctx.sio.emit(
                    "web_attack_error",
                    _attach_state(
                        {
                            "attack_type": label,
                            "error": str(exc),
                        },
                        state,
                    ),
                )

    def _normalize_dir_findings(result: Dict[str, Any]) -> List[Dict[str, Any]]:
        normalized: List[Dict[str, Any]] = []
        for finding in result.get("findings", []):
            path = str(finding.get("path", ""))
            status = int(finding.get("status", 0) or 0)
            lowered = path.lower()
            if lowered in {"/.env", "/.git/config"}:
                severity = "high"
            elif lowered in {"/robots.txt", "/sitemap.xml"} or status in (200, 403):
                severity = "medium"
            else:
                severity = "low"
            normalized.append(
                {
                    "title": f"Exposed path discovered: {path or '/'}",
                    "detail": f"Directory scanner found {path or '/'} with HTTP {status}.",
                    "severity": severity,
                    "path": path,
                    "status": status,
                    "url": finding.get("url", ""),
                    "payload": finding,
                }
            )
        return normalized

    async def _run_vuln_wrapper(url: str, options: Dict[str, Any]):
        report = await ctx._vuln_scanner.run_scan(url, options)
        try:
            scan_id = ctx.db.save_scan(url, report)
            print(f"Scan saved to DB: {scan_id}")
        except Exception as exc:  # pragma: no cover - legacy history save
            print(f"Failed to save scan to DB: {exc}")

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
            raise HTTPException(status_code=500, detail=str(exc))

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
            raise HTTPException(status_code=500, detail=str(exc))

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
            raise HTTPException(status_code=500, detail=str(exc))

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
            raise HTTPException(status_code=500, detail=str(exc))

    @ctx.app.post("/web/fingerprint")
    async def web_fingerprint(data: Dict[str, Any]):
        url = data.get("url", "").strip()
        if not url:
            raise HTTPException(status_code=400, detail="URL required")

        state = _build_state(data, attack_type="tech_fingerprint", target_url=url)
        try:
            result = await WSHawkTechFingerprinter().fingerprint(url)
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
            result = await WSHawkWAFDetector().detect(url)
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
            raise HTTPException(status_code=500, detail=str(exc))

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

    @ctx.app.post("/proxy/ca/generate")
    async def proxy_ca_generate(data: Dict[str, Any]):
        try:
            return {"status": "success", **await WSHawkProxyCA().generate_ca(force=data.get("force", False))}
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc))

    @ctx.app.get("/proxy/ca/info")
    async def proxy_ca_info():
        try:
            return await WSHawkProxyCA().get_ca_info()
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc))

    @ctx.app.post("/proxy/ca/host")
    async def proxy_ca_host_cert(data: Dict[str, Any]):
        hostname = data.get("hostname", "").strip()
        if not hostname:
            raise HTTPException(status_code=400, detail="Hostname required")
        try:
            return {"status": "success", **await WSHawkProxyCA().generate_host_cert(hostname)}
        except FileNotFoundError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc))

    @ctx.app.get("/proxy/ca/certs")
    async def proxy_ca_list_certs():
        try:
            return await WSHawkProxyCA().list_certs()
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc))

    @ctx.app.post("/web/chain")
    async def web_attack_chain(data: Dict[str, Any]):
        steps = data.get("steps", [])
        playbook = str(data.get("playbook") or "").strip()
        if not steps and not playbook:
            raise HTTPException(status_code=400, detail="Steps or playbook required")

        state = _build_state(
            data,
            attack_type="attack_chain",
            target_url=(steps[0].get("url", "") if steps else ""),
            parameters={"step_count": len(steps), "playbook": playbook or None},
        )
        try:
            result = await WSHawkAttackChainer(
                sio_instance=ctx.sio,
                store=ctx.platform_store,
            ).execute_chain(
                steps=steps,
                playbook=playbook,
                initial_vars=data.get("variables", {}),
                project_id=state.get("project_id"),
                correlation_id=state["request_context"].correlation_id,
                attack_run_id=state.get("attack_run_id"),
                default_headers=state["request_context"].headers,
                default_cookies=state["request_context"].cookies,
                default_url=data.get("default_url", ""),
                default_ws_url=data.get("default_ws_url", ""),
                default_identity=state["request_context"].identity,
            )
            ws_candidates = sorted(
                {
                    value
                    for value in result.get("variables", {}).values()
                    if isinstance(value, str) and value.startswith(("ws://", "wss://"))
                }
            )
            if state.get("project_id") and ws_candidates:
                runtime.add_note(
                    state["project_id"],
                    "Cross-protocol pivot candidates",
                    f"HTTP attack chain extracted potential WS targets: {', '.join(ws_candidates)}",
                )
            _complete_attack(
                state,
                {
                    "steps": len(result.get("results", [])),
                    "variables": sorted(result.get("variables", {}).keys()),
                    "ws_candidates": ws_candidates,
                    "playbook": result.get("playbook"),
                },
                note_title="Attack chain completed",
                note_body=(
                    f"Executed {len(result.get('results', []))} chained steps"
                    f"{' via playbook ' + result.get('playbook') if result.get('playbook') else ''}."
                ),
            )
            return _attach_state({"status": "success", **result, "ws_candidates": ws_candidates}, state)
        except ValueError as exc:
            _fail_attack(state, exc, title="Attack chain failure")
            raise HTTPException(status_code=400, detail=str(exc))
        except Exception as exc:
            _fail_attack(state, exc, title="Attack chain failure")
            raise HTTPException(status_code=500, detail=str(exc))

    @ctx.app.post("/web/extract")
    async def web_quick_extract(data: Dict[str, Any]):
        url = data.get("url", "").strip()
        if not url:
            raise HTTPException(status_code=400, detail="URL required")
        try:
            return {
                "status": "success",
                **await WSHawkAttackChainer().quick_extract(
                    url=url,
                    patterns=data.get("patterns", []),
                ),
            }
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc))

    @ctx.app.post("/web/crawl-sensitive")
    async def web_crawl_sensitive(data: Dict[str, Any]):
        url = data.get("url", "").strip()
        if not url:
            raise HTTPException(status_code=400, detail="URL required")

        state = _build_state(
            data,
            attack_type="crawl_sensitive_pipeline",
            target_url=url,
            parameters={
                "max_depth": int(data.get("max_depth", 2)),
                "max_pages": int(data.get("max_pages", 50)),
            },
        )

        async def _pipeline():
            await ctx.sio.emit("pipeline_phase", _attach_state({"phase": "crawl", "status": "running"}, state))
            crawler = WSHawkCrawler(sio_instance=ctx.sio, http_proxy=ctx.http_proxy_service)
            crawl_result = await crawler.crawl(
                start_url=url,
                max_depth=int(data.get("max_depth", 2)),
                max_pages=int(data.get("max_pages", 50)),
                headers=state["request_context"].headers,
                cookies=state["request_context"].cookies,
                project_id=state.get("project_id"),
                correlation_id=state["request_context"].correlation_id,
                attack_run_id=state.get("attack_run_id"),
                identity_id=state.get("identity_id"),
            )

            pages = crawl_result.get("pages", [])
            await ctx.sio.emit(
                "pipeline_phase",
                _attach_state({"phase": "crawl", "status": "done", "pages_crawled": len(pages)}, state),
            )

            await ctx.sio.emit("pipeline_phase", _attach_state({"phase": "sensitive", "status": "running"}, state))
            finder = WSHawkSensitiveFinder(sio_instance=ctx.sio, http_proxy=ctx.http_proxy_service)
            page_urls = [p["url"] for p in pages if p.get("url")]

            all_findings = []
            for i, page_url in enumerate(page_urls):
                try:
                    result = await finder.scan_url(
                        page_url,
                        project_id=state.get("project_id"),
                        correlation_id=state["request_context"].correlation_id,
                        attack_run_id=state.get("attack_run_id"),
                        headers=state["request_context"].headers,
                        cookies=state["request_context"].cookies,
                        identity_id=state.get("identity_id"),
                    )
                    findings = result.get("findings", [])
                    all_findings.extend(findings)
                    await ctx.sio.emit(
                        "pipeline_page_scanned",
                        _attach_state(
                            {
                                "url": page_url,
                                "findings_count": len(findings),
                                "progress": i + 1,
                                "total": len(page_urls),
                            },
                            state,
                        ),
                    )
                except Exception:
                    pass

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
                    for item in all_findings
                ],
                default_severity="medium",
            )

            await ctx.sio.emit(
                "pipeline_phase",
                _attach_state({"phase": "sensitive", "status": "done", "total_findings": len(all_findings)}, state),
            )
            await ctx.sio.emit(
                "pipeline_complete",
                _attach_state(
                    {
                        "pages_crawled": len(pages),
                        "pages_scanned": len(page_urls),
                        "total_findings": len(all_findings),
                        "findings": all_findings,
                    },
                    state,
                ),
            )

            _complete_attack(
                state,
                {
                    "pages_crawled": len(pages),
                    "pages_scanned": len(page_urls),
                    "finding_count": len(all_findings),
                },
                note_title="Crawl-sensitive pipeline completed",
                note_body=f"Crawl-sensitive pipeline against {url} scanned {len(page_urls)} pages.",
            )

        asyncio.create_task(_run_background("crawl_sensitive_pipeline", state, _pipeline()))
        return _attach_state({"status": "started", "msg": "Crawl → Sensitive pipeline started"}, state)

    @ctx.app.post("/session/save")
    async def session_save(data: Dict[str, Any]):
        name = data.get("name", "").strip() or f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        safe_name = "".join(c for c in name if c.isalnum() or c in "-_").strip()
        if not safe_name:
            safe_name = f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        session_data = {
            "type": "session_snapshot",
            "name": safe_name,
            "created": datetime.now().isoformat(),
            "version": "4.0.0",
            "data": _sanitize_session_snapshot(data.get("session", {})),
        }
        try:
            project = ctx.db.save_project(
                name=safe_name,
                target_url=session_data["data"].get("target", ""),
                metadata=session_data,
                project_id=data.get("project_id"),
            )
            return {"status": "success", "path": f"db:{project['id']}", "name": safe_name, "project_id": project["id"]}
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc))

    @ctx.app.post("/session/load")
    async def session_load(data: Dict[str, Any]):
        name = data.get("name", "").strip()
        if not name:
            raise HTTPException(status_code=400, detail="Session name required")

        project = ctx.db.get_project_by_name(name)
        if not project:
            raise HTTPException(status_code=404, detail=f"Session '{name}' not found")

        metadata = project.get("metadata") or {}
        if "data" not in metadata:
            metadata = {
                "type": "session_snapshot",
                "name": project["name"],
                "created": project["created_at"],
                "version": "4.0.0",
                "data": _sanitize_session_snapshot(metadata),
            }
        metadata["data"] = _sanitize_session_snapshot(metadata.get("data", {}))
        return {"status": "success", "session": metadata, "project_id": project["id"]}

    @ctx.app.get("/session/list")
    async def session_list():
        sessions = []
        for project in ctx.db.list_projects(limit=500):
            metadata = project.get("metadata") or {}
            if metadata.get("type") not in ("session_snapshot", None):
                continue
            sessions.append(
                {
                    "name": project["name"],
                    "created": metadata.get("created", project["created_at"]),
                    "size": len(json.dumps(metadata)),
                    "project_id": project["id"],
                }
            )

        return {"status": "success", "sessions": sessions, "count": len(sessions)}

    @ctx.app.delete("/session/delete")
    async def session_delete(data: Dict[str, Any]):
        name = data.get("name", "").strip()
        if not name:
            raise HTTPException(status_code=400, detail="Session name required")

        if ctx.db.delete_project_by_name(name):
            return {"status": "success"}
        raise HTTPException(status_code=404, detail="Session not found")
