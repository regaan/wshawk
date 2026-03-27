import asyncio
import hashlib
from typing import Any, Dict, List, Optional

from wshawk.store import ProjectStore
from wshawk.transport import WSHawkHTTPProxy

from .http_common import render_http_template
from .http_replay import HTTPReplayService, replay_http_request


async def _http_race_attempt(
    *,
    http_proxy: WSHawkHTTPProxy,
    method: str,
    url: str,
    headers: Optional[Dict[str, Any]],
    body: Any,
    cookies: Optional[Dict[str, Any]],
    identity: Optional[Dict[str, Any]],
    project_id: str,
    correlation_id: str,
    attack_run_id: Optional[str],
    metadata: Optional[Dict[str, Any]],
    allow_redirects: bool,
    timeout_s: int,
    verify_ssl: bool,
    wave: int,
    attempt: int,
    start_event: asyncio.Event,
    stagger_ms: int,
) -> Dict[str, Any]:
    await start_event.wait()
    if stagger_ms > 0:
        await asyncio.sleep((stagger_ms * max(attempt - 1, 0)) / 1000.0)

    result = await replay_http_request(
        http_proxy=http_proxy,
        method=method,
        url=url,
        headers=headers,
        body=body,
        cookies=cookies,
        identity=identity,
        project_id=project_id,
        correlation_id=correlation_id,
        attack_run_id=attack_run_id,
        metadata=metadata,
        allow_redirects=allow_redirects,
        timeout_s=timeout_s,
        verify_ssl=verify_ssl,
    )
    result["wave"] = wave
    result["attempt"] = attempt
    return result


class HTTPRaceService:
    """Run concurrent HTTP replay waves against the same request template."""

    def __init__(
        self,
        store: Optional[ProjectStore] = None,
        http_proxy: Optional[WSHawkHTTPProxy] = None,
    ):
        self.store = store
        self.http_proxy = http_proxy or WSHawkHTTPProxy(store=store)
        self.replay_service = HTTPReplayService(store=store, http_proxy=self.http_proxy)

    async def run(
        self,
        *,
        project_id: str,
        identities: Optional[List[Optional[Dict[str, Any]]]] = None,
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
        concurrency: int = 5,
        waves: int = 2,
        wave_delay_ms: int = 0,
        stagger_ms: int = 0,
        mode: str = "duplicate_action",
    ) -> Dict[str, Any]:
        identities = identities or [None]
        concurrency = max(1, int(concurrency))
        waves = max(1, int(waves))

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
            attack_type="http_race",
            target_id=target["id"] if target else None,
            parameters={
                "method": rendered["method"],
                "url": rendered["url"],
                "mode": mode,
                "concurrency": concurrency,
                "waves": waves,
                "wave_delay_ms": wave_delay_ms,
                "stagger_ms": stagger_ms,
                "source_flow_id": rendered.get("source_flow_id"),
            },
        ) if self.store else None

        effective_correlation_id = (
            correlation_id
            or rendered.get("correlation_id", "")
            or (f"http-race-{run['id'][:12]}" if run else "")
        )

        results: List[Dict[str, Any]] = []
        for wave in range(1, waves + 1):
            start_event = asyncio.Event()
            tasks = []
            for attempt in range(1, concurrency + 1):
                identity = identities[(wave + attempt - 2) % len(identities)]
                tasks.append(
                    asyncio.create_task(
                        _http_race_attempt(
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
                                "source": "http_race",
                                "mode": mode,
                                "wave": wave,
                                "attempt": attempt,
                                "identity_alias": identity.get("alias") if identity else "",
                                "source_flow_id": rendered.get("source_flow_id"),
                            },
                            allow_redirects=allow_redirects,
                            timeout_s=timeout_s,
                            verify_ssl=verify_ssl,
                            wave=wave,
                            attempt=attempt,
                            start_event=start_event,
                            stagger_ms=stagger_ms,
                        )
                    )
                )
            start_event.set()
            wave_results = await asyncio.gather(*tasks)
            results.extend(wave_results)
            if wave < waves and wave_delay_ms > 0:
                await asyncio.sleep(wave_delay_ms / 1000.0)

        behavior_keys = {
            hashlib.sha256(
                "\n".join(
                    [
                        str(item.get("status", "")),
                        str(item.get("http_status", "")),
                        str(item.get("response_preview", "")),
                        str(item.get("error", "")),
                    ]
                ).encode("utf-8", errors="replace")
            ).hexdigest()[:16]
            for item in results
        }
        success_count = sum(
            1
            for item in results
            if str(item.get("http_status", "")).isdigit() and int(str(item.get("http_status"))) < 400
        )
        error_count = sum(1 for item in results if item.get("status") == "error")
        wave_success = {}
        for item in results:
            key = f"wave_{item['wave']}"
            wave_success[key] = wave_success.get(key, 0) + (
                1 if str(item.get("http_status", "")).isdigit() and int(str(item.get("http_status"))) < 400 else 0
            )

        multi_success = success_count > 1
        later_wave_success = any(count > 0 for key, count in wave_success.items() if key != "wave_1")
        suspicious = multi_success and (
            mode in {"duplicate_action", "replay_before_invalidation", "stale_token_window", "business_logic"}
            or len(behavior_keys) > 1
        )
        recommended_severity = "info"
        if suspicious and later_wave_success:
            recommended_severity = "high"
        elif suspicious:
            recommended_severity = "medium"

        summary = {
            "mode": mode,
            "wave_count": waves,
            "concurrency": concurrency,
            "attempt_count": len(results),
            "success_count": success_count,
            "error_count": error_count,
            "behavior_group_count": len(behavior_keys),
            "wave_success": wave_success,
            "duplicate_success_observed": multi_success,
            "later_wave_success_observed": later_wave_success,
            "suspicious_race_window": suspicious,
            "recommended_severity": recommended_severity,
        }

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
