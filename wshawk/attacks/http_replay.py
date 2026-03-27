from time import perf_counter
from typing import Any, Dict, Optional

from wshawk.store import ProjectStore
from wshawk.transport import WSHawkHTTPProxy

from .http_common import (
    build_http_template,
    merge_http_identity,
    normalize_http_body,
    render_http_template,
)


async def replay_http_request(
    *,
    http_proxy: WSHawkHTTPProxy,
    method: str,
    url: str,
    headers: Optional[Dict[str, Any]] = None,
    body: Any = "",
    cookies: Optional[Dict[str, Any]] = None,
    identity: Optional[Dict[str, Any]] = None,
    project_id: Optional[str] = None,
    correlation_id: str = "",
    attack_run_id: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
    allow_redirects: bool = False,
    timeout_s: int = 30,
    verify_ssl: bool = True,
) -> Dict[str, Any]:
    request_headers, request_cookies = merge_http_identity(identity=identity, headers=headers, cookies=cookies)
    request_body = normalize_http_body(body)
    started = perf_counter()
    raw_result = await http_proxy.send_request(
        method=method,
        url=url,
        headers=request_headers,
        body=request_body,
        cookies=request_cookies,
        project_id=project_id,
        correlation_id=correlation_id,
        attack_run_id=attack_run_id,
        metadata=metadata,
        allow_redirects=allow_redirects,
        timeout_s=timeout_s,
        verify_ssl=verify_ssl,
    )

    result = {
        "method": method.upper(),
        "url": url,
        "status": "error" if raw_result.get("error") else "received",
        "http_status": str(raw_result.get("status", "")),
        "headers": raw_result.get("headers_dict") or {},
        "body": raw_result.get("body", ""),
        "response": raw_result.get("body", ""),
        "response_length": len(raw_result.get("body", "")),
        "response_preview": raw_result.get("body", "")[:320],
        "error": raw_result.get("error", ""),
        "flow_id": raw_result.get("flow_id"),
        "identity_id": identity.get("id") if identity else None,
        "identity_alias": identity.get("alias") if identity else None,
        "timing_ms": round((perf_counter() - started) * 1000, 2),
    }
    return result


class HTTPReplayService:
    """Project-aware HTTP replay and template generation."""

    def __init__(
        self,
        store: Optional[ProjectStore] = None,
        http_proxy: Optional[WSHawkHTTPProxy] = None,
    ):
        self.store = store
        self.http_proxy = http_proxy or WSHawkHTTPProxy(store=store)

    def build_template(
        self,
        *,
        method: str,
        url: str,
        headers: Optional[Any] = None,
        body: Optional[Any] = None,
        source_flow_id: Optional[str] = None,
        correlation_id: str = "",
        name: str = "",
    ) -> Dict[str, Any]:
        return build_http_template(
            method=method,
            url=url,
            headers=headers,
            body=body,
            source_flow_id=source_flow_id,
            correlation_id=correlation_id,
            name=name,
        )

    def build_template_from_flow(self, *, project_id: str, flow_id: str) -> Dict[str, Any]:
        if not self.store:
            raise ValueError("Project store is required for flow-backed templates")
        flow = self.store.get_http_flow(flow_id)
        if not flow or flow.get("project_id") != project_id:
            raise ValueError("HTTP flow not found")
        template = self.build_template(
            method=flow.get("method", "GET"),
            url=flow.get("url", ""),
            headers=flow.get("request_headers") or {},
            body=flow.get("request_body", ""),
            source_flow_id=flow.get("id"),
            correlation_id=flow.get("correlation_id", ""),
            name=f"{flow.get('method', 'GET')} {flow.get('url', '')}",
        )
        template["baseline"] = {
            "http_status": flow.get("response_status", ""),
            "response_length": len(flow.get("response_body", "")),
            "error": flow.get("error", ""),
        }
        return template

    async def replay(
        self,
        *,
        project_id: str,
        method: Optional[str] = None,
        url: Optional[str] = None,
        headers: Optional[Any] = None,
        body: Optional[Any] = None,
        cookies: Optional[Any] = None,
        identity: Optional[Dict[str, Any]] = None,
        template: Optional[Dict[str, Any]] = None,
        flow_id: Optional[str] = None,
        variables: Optional[Dict[str, Any]] = None,
        correlation_id: str = "",
        allow_redirects: bool = False,
        timeout_s: int = 30,
        verify_ssl: bool = True,
    ) -> Dict[str, Any]:
        if flow_id and not template:
            template = self.build_template_from_flow(project_id=project_id, flow_id=flow_id)

        if template:
            rendered = render_http_template(
                template,
                variables=variables,
                method=method,
                url=url,
                headers=headers,
                body=body,
            )
        else:
            if not method or not url:
                raise ValueError("Method and URL are required when no template or flow_id is provided")
            rendered = self.build_template(
                method=method,
                url=url,
                headers=headers,
                body=body,
                correlation_id=correlation_id,
            )

        target = self.store.ensure_target(project_id, rendered["url"], kind="http") if self.store else None
        run = self.store.start_attack_run(
            project_id=project_id,
            attack_type="http_replay",
            target_id=target["id"] if target else None,
            identity_id=identity.get("id") if identity else None,
            parameters={
                "method": rendered["method"],
                "url": rendered["url"],
                "source_flow_id": rendered.get("source_flow_id"),
                "template_name": rendered.get("name", ""),
                "allow_redirects": allow_redirects,
            },
        ) if self.store else None

        effective_correlation_id = (
            correlation_id
            or rendered.get("correlation_id", "")
            or (f"http-replay-{run['id'][:12]}" if run else "")
        )
        result = await replay_http_request(
            http_proxy=self.http_proxy,
            method=rendered["method"],
            url=rendered["url"],
            headers=rendered.get("headers") or {},
            body=rendered.get("body") or "",
            cookies=cookies,
            identity=identity,
            project_id=project_id,
            correlation_id=effective_correlation_id,
            attack_run_id=run["id"] if run else None,
            metadata={
                "source": "http_replay",
                "identity_alias": identity.get("alias") if identity else "",
                "source_flow_id": rendered.get("source_flow_id"),
                "template_name": rendered.get("name", ""),
            },
            allow_redirects=allow_redirects,
            timeout_s=timeout_s,
            verify_ssl=verify_ssl,
        )

        if self.store and run:
            self.store.update_attack_run(
                run["id"],
                status="completed" if result.get("status") != "error" else "failed",
                summary={
                    "http_status": result.get("http_status"),
                    "flow_id": result.get("flow_id"),
                    "response_length": result.get("response_length"),
                    "response_preview": result.get("response_preview", ""),
                    "correlation_id": effective_correlation_id,
                },
                completed=True,
            )

        result["attack_run_id"] = run.get("id") if run else None
        result["correlation_id"] = effective_correlation_id
        result["template"] = rendered
        return result
