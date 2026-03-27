from typing import Any, Dict, List, Optional

from wshawk.store import ProjectStore
from wshawk.transport import WSHawkHTTPProxy

from .http_common import render_http_template, summarize_http_authz_diff
from .http_replay import HTTPReplayService, replay_http_request


class HTTPAuthzDiffService:
    """Replay the same HTTP template across identities and compare behavior."""

    def __init__(
        self,
        store: Optional[ProjectStore] = None,
        http_proxy: Optional[WSHawkHTTPProxy] = None,
    ):
        self.store = store
        self.http_proxy = http_proxy or WSHawkHTTPProxy(store=store)
        self.replay_service = HTTPReplayService(store=store, http_proxy=self.http_proxy)

    async def compare(
        self,
        *,
        project_id: str,
        identities: List[Optional[Dict[str, Any]]],
        method: Optional[str] = None,
        url: Optional[str] = None,
        headers: Optional[Any] = None,
        body: Optional[Any] = None,
        cookies: Optional[Any] = None,
        template: Optional[Dict[str, Any]] = None,
        flow_id: Optional[str] = None,
        variables: Optional[Dict[str, Any]] = None,
        correlation_id: str = "",
        allow_redirects: bool = False,
        timeout_s: int = 30,
        verify_ssl: bool = True,
    ) -> Dict[str, Any]:
        if flow_id and not template:
            template = self.replay_service.build_template_from_flow(project_id=project_id, flow_id=flow_id)
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
            rendered = self.replay_service.build_template(method=method, url=url, headers=headers, body=body)

        target = self.store.ensure_target(project_id, rendered["url"], kind="http") if self.store else None
        run = self.store.start_attack_run(
            project_id=project_id,
            attack_type="http_authz_diff",
            target_id=target["id"] if target else None,
            parameters={
                "method": rendered["method"],
                "url": rendered["url"],
                "identity_count": len(identities),
                "source_flow_id": rendered.get("source_flow_id"),
                "template_name": rendered.get("name", ""),
            },
        ) if self.store else None

        effective_correlation_id = (
            correlation_id
            or rendered.get("correlation_id", "")
            or (f"http-authz-{run['id'][:12]}" if run else "")
        )

        results: List[Dict[str, Any]] = []
        for identity in identities:
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
                    "source": "http_authz_diff",
                    "identity_alias": identity.get("alias") if identity else "",
                    "source_flow_id": rendered.get("source_flow_id"),
                    "template_name": rendered.get("name", ""),
                },
                allow_redirects=allow_redirects,
                timeout_s=timeout_s,
                verify_ssl=verify_ssl,
            )
            results.append(result)

        summary = summarize_http_authz_diff(results)
        if self.store and run:
            self.store.update_attack_run(
                run["id"],
                status="completed",
                summary={
                    **summary,
                    "correlation_id": effective_correlation_id,
                    "source_flow_id": rendered.get("source_flow_id"),
                },
                completed=True,
            )

        return {
            "attack_run_id": run.get("id") if run else None,
            "method": rendered["method"],
            "url": rendered["url"],
            "template": rendered,
            "correlation_id": effective_correlation_id,
            "results": results,
            "summary": summary,
        }
