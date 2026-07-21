"""Shared state, normalization, and persistence helpers for web routes."""

import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from wshawk.web_pentest import WebPentestPlatformRuntime

from .context import BridgeContext


def build_web_route_helpers(ctx: BridgeContext):
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
        if isinstance(exc, (OSError, TimeoutError, ValueError)):
            ctx.logger.warning("%s: %s", title, exc)
        else:
            ctx.logger.exception("Unexpected %s", title.lower())
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
            variant_paths = [str(item) for item in finding.get("variant_paths", []) if item]
            variant_note = ""
            if variant_paths:
                variant_note = f" Grouped {len(variant_paths)} near-identical variant path(s): {', '.join(variant_paths)}."
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
                    "detail": f"Directory scanner found {path or '/'} with HTTP {status}.{variant_note}",
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
        except Exception:  # pragma: no cover - legacy history save
            ctx.logger.exception("Unexpected legacy scan history persistence failure")

    return {
        "runtime": runtime,
        "_normalize_headers": _normalize_headers,
        "_normalize_cookies": _normalize_cookies,
        "_normalize_body": _normalize_body,
        "_is_json_content_type": _is_json_content_type,
        "_decode_nested_json": _decode_nested_json,
        "_normalize_http_request_body": _normalize_http_request_body,
        "_build_state": _build_state,
        "_attach_state": _attach_state,
        "_complete_attack": _complete_attack,
        "_fail_attack": _fail_attack,
        "_persist_findings": _persist_findings,
        "_run_background": _run_background,
        "_normalize_dir_findings": _normalize_dir_findings,
        "_run_vuln_wrapper": _run_vuln_wrapper,
    }


__all__ = ["build_web_route_helpers"]
