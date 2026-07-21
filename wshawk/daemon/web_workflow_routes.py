"""Proxy-certificate and multi-step web workflow routes."""

import asyncio
from typing import Any, Dict

from fastapi import HTTPException

from wshawk.web_pentest import (
    WSHawkAttackChainer,
    WSHawkCrawler,
    WSHawkProxyCA,
    WSHawkSensitiveFinder,
)

from .context import BridgeContext


def register_web_workflow_routes(ctx: BridgeContext, helpers: Dict[str, Any]) -> None:
    runtime = helpers["runtime"]
    _attach_state = helpers["_attach_state"]
    _build_state = helpers["_build_state"]
    _complete_attack = helpers["_complete_attack"]
    _fail_attack = helpers["_fail_attack"]
    _persist_findings = helpers["_persist_findings"]
    _run_background = helpers["_run_background"]

    @ctx.app.post("/proxy/ca/generate")
    async def proxy_ca_generate(data: Dict[str, Any]):
        try:
            return {"status": "success", **await WSHawkProxyCA().generate_ca(force=data.get("force", False))}
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except OSError as exc:
            ctx.logger.warning("Proxy CA filesystem operation failed: %s", exc)
            raise HTTPException(status_code=500, detail="Proxy CA filesystem operation failed") from exc
        except Exception as exc:
            ctx.logger.exception("Unexpected proxy CA generation failure")
            raise HTTPException(status_code=500, detail="Proxy CA generation failed") from exc

    @ctx.app.get("/proxy/ca/info")
    async def proxy_ca_info():
        try:
            return await WSHawkProxyCA().get_ca_info()
        except OSError as exc:
            ctx.logger.warning("Proxy CA inspection filesystem failure: %s", exc)
            raise HTTPException(status_code=500, detail="Proxy CA inspection failed") from exc
        except Exception as exc:
            ctx.logger.exception("Unexpected proxy CA inspection failure")
            raise HTTPException(status_code=500, detail="Proxy CA inspection failed") from exc

    @ctx.app.post("/proxy/ca/host")
    async def proxy_ca_host_cert(data: Dict[str, Any]):
        hostname = data.get("hostname", "").strip()
        if not hostname:
            raise HTTPException(status_code=400, detail="Hostname required")
        try:
            return {"status": "success", **await WSHawkProxyCA().generate_host_cert(hostname)}
        except FileNotFoundError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except OSError as exc:
            ctx.logger.warning("Host certificate filesystem operation failed: %s", exc)
            raise HTTPException(status_code=500, detail="Host certificate filesystem operation failed") from exc
        except Exception as exc:
            ctx.logger.exception("Unexpected host certificate generation failure")
            raise HTTPException(status_code=500, detail="Host certificate generation failed") from exc

    @ctx.app.get("/proxy/ca/certs")
    async def proxy_ca_list_certs():
        try:
            return await WSHawkProxyCA().list_certs()
        except OSError as exc:
            ctx.logger.warning("Proxy certificate listing filesystem failure: %s", exc)
            raise HTTPException(status_code=500, detail="Proxy certificate listing failed") from exc
        except Exception as exc:
            ctx.logger.exception("Unexpected proxy certificate listing failure")
            raise HTTPException(status_code=500, detail="Proxy certificate listing failed") from exc

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
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except (OSError, TimeoutError) as exc:
            ctx.logger.warning("Quick extraction target failure: %s", exc)
            raise HTTPException(status_code=502, detail="Quick extraction target failed") from exc
        except Exception as exc:
            ctx.logger.exception("Unexpected quick extraction failure")
            raise HTTPException(status_code=500, detail="Quick extraction failed") from exc

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
                except (OSError, TimeoutError, ValueError) as exc:
                    ctx.logger.warning("Sensitive scan failed for %s: %s", page_url, exc)
                except Exception:
                    ctx.logger.exception("Unexpected sensitive scan implementation failure for %s", page_url)

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


__all__ = ["register_web_workflow_routes"]
