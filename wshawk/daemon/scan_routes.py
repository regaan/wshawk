import asyncio
from typing import Any, Dict, List, Optional

import websockets
from fastapi import HTTPException

from wshawk.__main__ import WSPayloads
from wshawk.scanner_v2 import WSHawkV2

from .context import BridgeContext


def register_scan_routes(ctx: BridgeContext) -> None:
    async def scanner_event_callback(event_type: str, data: Any):
        await ctx.sio.emit(event_type, data)

        context = ctx.state.scan_context or {}
        project_id = context.get("project_id")
        target_url = context.get("target_url", "")
        if not project_id:
            return

        if event_type == "message_sent":
            outbound = data.get("msg")
            inbound = data.get("response")

            if outbound is not None:
                event = ctx.maybe_log_platform_event(
                    project_id,
                    "ws_scan_frame",
                    payload={"message": outbound, "source": "scanner"},
                    direction="out",
                    target=target_url,
                )
                ctx.platform_store.add_ws_frame(
                    project_id=project_id,
                    connection_id=None,
                    direction="out",
                    payload=outbound,
                    metadata={"source": "scanner", "scan_id": context.get("scan_id")},
                )
                if event:
                    await ctx.sio.emit("platform_event", {"project_id": project_id, "event": event})

            if inbound is not None:
                event = ctx.maybe_log_platform_event(
                    project_id,
                    "ws_scan_frame",
                    payload={"message": inbound, "source": "scanner"},
                    direction="in",
                    target=target_url,
                )
                ctx.platform_store.add_ws_frame(
                    project_id=project_id,
                    connection_id=None,
                    direction="in",
                    payload=inbound,
                    metadata={"source": "scanner", "scan_id": context.get("scan_id")},
                )
                if event:
                    await ctx.sio.emit("platform_event", {"project_id": project_id, "event": event})

        elif event_type == "vulnerability_found":
            event = ctx.maybe_log_platform_event(
                project_id,
                "scanner_vulnerability_found",
                payload=data if isinstance(data, dict) else {"value": data},
                target=target_url,
            )
            finding = data if isinstance(data, dict) else {"type": "Scanner Finding", "description": str(data)}
            severity = str(finding.get("severity", "info")).lower()
            evidence = ctx.maybe_store_platform_evidence(
                project_id=project_id,
                title=finding.get("type") or finding.get("title") or "Scanner finding",
                category="scanner_finding",
                severity=severity,
                related_event_id=event.get("id") if event else None,
                payload={
                    "target": target_url,
                    "scan_id": context.get("scan_id"),
                    "finding": finding,
                },
            )
            if event:
                await ctx.sio.emit("platform_event", {"project_id": project_id, "event": event})
            if evidence:
                await ctx.sio.emit("platform_evidence", {"project_id": project_id, "evidence": evidence})
            ctx.platform_store.add_finding(
                project_id=project_id,
                attack_run_id=None,
                title=finding.get("type") or finding.get("title") or "Scanner finding",
                category="scanner_finding",
                severity=severity,
                description=finding.get("description") or finding.get("detail") or "",
                payload={
                    "target": target_url,
                    "scan_id": context.get("scan_id"),
                    "finding": finding,
                },
            )

        elif event_type == "scan_progress":
            event = ctx.maybe_log_platform_event(
                project_id,
                "scan_progress",
                payload=data if isinstance(data, dict) else {"value": data},
                target=target_url,
            )
            if event:
                await ctx.sio.emit("platform_event", {"project_id": project_id, "event": event})

        elif event_type == "scan_error":
            event = ctx.maybe_log_platform_event(
                project_id,
                "scan_error",
                payload=data if isinstance(data, dict) else {"value": data},
                target=target_url,
            )
            evidence = ctx.maybe_store_platform_evidence(
                project_id=project_id,
                title="Scan execution error",
                category="scanner_error",
                severity="medium",
                related_event_id=event.get("id") if event else None,
                payload={
                    "target": target_url,
                    "scan_id": context.get("scan_id"),
                    "error": data if isinstance(data, dict) else {"message": str(data)},
                },
            )
            if event:
                await ctx.sio.emit("platform_event", {"project_id": project_id, "event": event})
            if evidence:
                await ctx.sio.emit("platform_evidence", {"project_id": project_id, "evidence": evidence})

    async def run_scan_task(scan_id: str):
        try:
            if not ctx.state.scanner:
                return

            ctx.state.scanner.event_callback = scanner_event_callback
            await ctx.sio.emit("scan_update", {"id": scan_id, "status": "running"})

            vulns = await ctx.state.scanner.run_heuristic_scan()
            if vulns is None:
                vulns = []

            await ctx.sio.emit(
                "scan_update",
                {"id": scan_id, "status": "completed", "vulnerabilities_count": len(vulns)},
            )
            ctx.maybe_log_platform_event(
                ctx.state.scan_context.get("project_id"),
                "scan_completed",
                payload={"scan_id": scan_id, "vulnerabilities_count": len(vulns)},
                target=ctx.state.scan_context.get("target_url", ""),
            )
            ctx.state.scanner = None
            ctx.state.scan_context = {}
        except asyncio.CancelledError:
            print("[*] Scan cancelled by user.")
            await ctx.sio.emit("scan_error", {"id": scan_id, "error": "Scan Cancelled."})
            ctx.state.scanner = None
            ctx.maybe_log_platform_event(
                ctx.state.scan_context.get("project_id"),
                "scan_cancelled",
                payload={"scan_id": scan_id},
                target=ctx.state.scan_context.get("target_url", ""),
            )
            ctx.state.scan_context = {}
        except Exception as e:
            print(f"[!] Scan Task Error: {e}")
            await ctx.sio.emit("scan_error", {"id": scan_id, "error": str(e)})
            ctx.state.scanner = None
            ctx.maybe_log_platform_event(
                ctx.state.scan_context.get("project_id"),
                "scan_failed",
                payload={"scan_id": scan_id, "error": str(e)},
                target=ctx.state.scan_context.get("target_url", ""),
            )
            ctx.state.scan_context = {}

    async def run_blaster_task(
        url: str,
        payloads: List[str],
        template: str = "",
        use_spe: bool = False,
        auth_payload: str = None,
        dom_verify: bool = False,
        auth_flow: Optional[Dict[str, Any]] = None,
    ):
        evolver = None
        if use_spe:
            try:
                from wshawk.smart_payloads.payload_evolver import PayloadEvolver

                evolver = PayloadEvolver()
            except ImportError:
                pass

        invader = None
        replay_service = None
        if dom_verify:
            try:
                capture_service = ctx.get_browser_capture()
                replay_service = ctx.get_browser_replay()
                if capture_service.is_available:
                    await capture_service.ensure_started()
                    invader = capture_service.engine
            except Exception as e:
                ctx.logger.warning(f"DOM Invader init failed: {e}")
                invader = None

        def apply_template(p: str) -> str:
            if template and "§inject§" in template:
                return template.replace("§inject§", p)
            return p

        async def get_ws_headers() -> dict:
            if not auth_flow or not replay_service:
                return {}
            try:
                tokens = await replay_service.replay_auth_flow(auth_flow)
                if tokens.valid:
                    return tokens.headers
            except Exception as e:
                ctx.logger.warning(f"Auth replay failed: {e}")
            return {}

        ws_headers = {}
        if auth_flow:
            ws_headers = await get_ws_headers()

        remaining_payloads = [p for p in payloads if p.strip()]
        max_reconnects = 3
        reconnect_count = 0
        payload_idx = 0

        try:
            while payload_idx < len(remaining_payloads) and reconnect_count <= max_reconnects:
                try:
                    connect_kwargs = {"ping_interval": None}
                    if ws_headers:
                        connect_kwargs["extra_headers"] = ws_headers

                    async with websockets.connect(url, **connect_kwargs) as ws:
                        if auth_payload and auth_payload.strip():
                            try:
                                await ws.send(auth_payload)
                                await asyncio.sleep(0.5)
                            except Exception as e:
                                print(f"[!] Blaster auth payload failed: {e}")

                        while payload_idx < len(remaining_payloads):
                            p = remaining_payloads[payload_idx]
                            payload_idx += 1

                            if evolver and len(p) > 2:
                                import random

                                if random.random() > 0.3:
                                    try:
                                        p = evolver._mutate(p)
                                    except Exception:
                                        pass

                            final_packet = apply_template(p)

                            await ctx.sio.emit("blaster_progress", {"payload": final_packet, "status": "sending"})
                            await asyncio.sleep(0.3)
                            await ws.send(final_packet)

                            try:
                                resp = await asyncio.wait_for(ws.recv(), timeout=3.0)
                                resp_str = str(resp)

                                dom_result = {}
                                if invader and invader.is_available:
                                    try:
                                        vr = await invader.verify_response(
                                            payload=final_packet,
                                            response=resp_str,
                                            timeout_ms=2500,
                                        )
                                        dom_result = {
                                            "dom_verified": vr.executed,
                                            "dom_evidence": vr.evidence,
                                            "dom_technique": vr.technique.value,
                                        }
                                        if vr.executed:
                                            await ctx.sio.emit(
                                                "dom_xss_confirmed",
                                                {
                                                    "payload": final_packet,
                                                    "evidence": vr.evidence,
                                                    "technique": vr.technique.value,
                                                    "response_snippet": resp_str[:200],
                                                },
                                            )
                                    except Exception as e:
                                        ctx.logger.warning(f"DOM verify inline failed: {e}")

                                await ctx.sio.emit(
                                    "blaster_result",
                                    {
                                        "payload": final_packet,
                                        "status": "success",
                                        "length": len(resp_str),
                                        "response": resp_str[:100],
                                        **dom_result,
                                    },
                                )
                                await ctx.sio.emit("message_sent", {"msg": final_packet, "response": resp_str})
                            except asyncio.TimeoutError:
                                await ctx.sio.emit(
                                    "blaster_result",
                                    {
                                        "payload": final_packet,
                                        "status": "timeout",
                                        "length": 0,
                                        "response": "No response",
                                        "dom_verified": False,
                                        "dom_evidence": "",
                                    },
                                )
                            except Exception as e:
                                err_str = str(e)
                                if "ConnectionClosed" in err_str or "1000" in err_str or "1001" in err_str:
                                    payload_idx -= 1
                                    raise
                                await ctx.sio.emit(
                                    "blaster_result",
                                    {
                                        "payload": final_packet,
                                        "status": "error",
                                        "length": 0,
                                        "response": err_str,
                                    },
                                )
                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    err_str = str(e)
                    if auth_flow and reconnect_count < max_reconnects:
                        reconnect_count += 1
                        await ctx.sio.emit(
                            "blaster_result",
                            {
                                "payload": "SESSION_EXPIRED",
                                "status": "info",
                                "length": 0,
                                "response": f"Session expired. Replaying auth flow (attempt {reconnect_count})...",
                            },
                        )
                        ws_headers = await get_ws_headers()
                        await asyncio.sleep(1)
                    else:
                        await ctx.sio.emit(
                            "blaster_result",
                            {
                                "payload": "CONNECTION ERROR",
                                "status": "fatal",
                                "length": 0,
                                "response": err_str,
                            },
                        )
                        break
        except asyncio.CancelledError:
            print("[*] Blaster cancelled by user.")
            await ctx.sio.emit(
                "blaster_result",
                {"payload": "CANCELLED", "status": "error", "length": 0, "response": "Stopped."},
            )
        finally:
            await ctx.sio.emit("blaster_completed", {"status": "done"})

    @ctx.app.post("/scan/start")
    async def start_scan(config: Dict[str, Any]):
        if ctx.state.scanner:
            raise HTTPException(status_code=400, detail="A scan is already running")

        target_url = config.get("url")
        if not target_url:
            raise HTTPException(status_code=400, detail="Target URL is required")

        scan_id = str(__import__("uuid").uuid4())[:8]
        auth_payload = config.get("auth_payload")
        ctx.state.scanner = WSHawkV2(target_url, auth_sequence=auth_payload, max_rps=config.get("rate", 10))
        ctx.state.scan_context = {
            "scan_id": scan_id,
            "project_id": config.get("project_id"),
            "target_url": target_url,
        }
        if config.get("project_id"):
            ctx.platform_store.ensure_target(
                config["project_id"],
                target_url,
                kind="websocket",
                metadata={"source": "scan_start"},
            )

        task = asyncio.create_task(run_scan_task(scan_id))
        ctx.state.active_scans["scan_task"] = task

        ctx.maybe_log_platform_event(
            config.get("project_id"),
            "scan_started",
            payload={"scan_id": scan_id, "config": {k: v for k, v in config.items() if k != "auth_payload"}},
            target=target_url,
        )

        return {"scan_id": scan_id, "status": "started"}

    @ctx.app.post("/reqforge/send")
    async def forge_send(data: Dict[str, Any]):
        target_url = data.get("url")
        payload = data.get("payload")
        if not target_url or not payload:
            raise HTTPException(status_code=400, detail="Target URL and payload are required")

        try:
            async with websockets.connect(target_url, ping_interval=None) as ws:
                await ws.send(payload)
                ctx.maybe_log_platform_event(
                    data.get("project_id"),
                    "ws_reqforge_sent",
                    payload={"payload": payload},
                    direction="out",
                    target=target_url,
                )
                response = await asyncio.wait_for(ws.recv(), timeout=120.0)
                ctx.maybe_log_platform_event(
                    data.get("project_id"),
                    "ws_reqforge_response",
                    payload={"response": response},
                    direction="in",
                    target=target_url,
                )
                await ctx.sio.emit("message_sent", {"msg": payload, "response": response})
                return {"status": "success", "response": response}
        except asyncio.TimeoutError:
            await ctx.sio.emit("message_sent", {"msg": payload, "response": "TIMEOUT"})
            return {"status": "timeout", "response": "No response received from target."}
        except Exception as e:
            return {"status": "error", "response": str(e)}

    @ctx.app.post("/blaster/start")
    async def blaster_start(data: Dict[str, Any]):
        target_url = data.get("url")
        payloads = data.get("payloads", [])
        if not target_url or not payloads:
            raise HTTPException(status_code=400, detail="Target URL and payloads array required")

        task = asyncio.create_task(
            run_blaster_task(
                target_url,
                payloads,
                data.get("template", ""),
                data.get("spe", False),
                data.get("auth_payload"),
                data.get("dom_verify", False),
                data.get("auth_flow", None),
            )
        )
        ctx.state.active_scans["blaster_task"] = task
        return {"status": "started", "count": len(payloads)}

    @ctx.app.get("/blaster/payloads/{category}")
    async def get_payloads(category: str):
        all_sqli = WSPayloads.get_sql_injection
        all_xss = WSPayloads.get_xss

        payload_map = {
            "sqli_all": all_sqli,
            "sqli_time": lambda: [p for p in all_sqli() if any(k in p.lower() for k in ["sleep", "waitfor", "benchmark"])],
            "sqli_error": lambda: [p for p in all_sqli() if "union" in p.lower() or "select" in p.lower() or "error" in p.lower()][:200],
            "sqli_boolean": lambda: [p for p in all_sqli() if ("and" in p.lower() or "or" in p.lower()) and "sleep" not in p.lower()][:200],
            "xss_all": all_xss,
            "xss_ws": lambda: [p for p in all_xss() if any(k in p.lower() for k in ["websocket", "onmessage", "javascript:", "alert"])][:150],
            "cmd": WSPayloads.get_command_injection,
            "nosql": WSPayloads.get_nosql_injection,
            "lfi": WSPayloads.get_path_traversal,
            "ssti": WSPayloads.get_ssti,
            "xxe": WSPayloads.get_xxe,
        }

        if category not in payload_map:
            raise HTTPException(status_code=404, detail="Payload category not found")

        payloads = payload_map[category]()
        return {"category": category, "count": len(payloads), "payloads": payloads}

    @ctx.app.post("/scan/stop")
    async def stop_scan():
        if "scan_task" in ctx.state.active_scans and not ctx.state.active_scans["scan_task"].done():
            ctx.state.active_scans["scan_task"].cancel()
            return {"status": "success", "msg": "Scan cancelled"}
        return {"status": "error", "msg": "No scan running"}

    @ctx.app.post("/blaster/stop")
    async def stop_blaster():
        if "blaster_task" in ctx.state.active_scans and not ctx.state.active_scans["blaster_task"].done():
            ctx.state.active_scans["blaster_task"].cancel()
            return {"status": "success", "msg": "Blaster cancelled"}
        return {"status": "error", "msg": "No blaster running"}

    @ctx.app.post("/discovery/scan")
    async def discovery_scan(data: Dict[str, Any]):
        target = data.get("target")
        if not target:
            raise HTTPException(status_code=400, detail="Target URL is required")

        try:
            from wshawk.ws_discovery import WSEndpointDiscovery

            discovery = WSEndpointDiscovery(target, timeout=10, max_depth=2)
            endpoints = await discovery.discover()
            return {"status": "success", "endpoints": endpoints, "count": len(endpoints)}
        except ImportError:
            return {"status": "error", "endpoints": [], "msg": "aiohttp not installed. Run: pip install aiohttp"}
        except Exception as e:
            return {"status": "error", "endpoints": [], "msg": str(e)}

    @ctx.app.post("/discovery/probe")
    async def discovery_probe(data: Dict[str, Any]):
        url = data.get("url")
        if not url:
            raise HTTPException(status_code=400, detail="WebSocket URL is required")

        try:
            async with websockets.connect(url, ping_interval=None, close_timeout=5):
                return {"alive": True, "status": "connected"}
        except Exception as e:
            return {"alive": False, "status": str(e)}

    @ctx.app.post("/auth/test")
    async def auth_test(data: Dict[str, Any]):
        import re

        url = data.get("url")
        steps = data.get("steps", [])
        rules = data.get("rules", [])
        if not url or not steps:
            raise HTTPException(status_code=400, detail="URL and steps required")

        results = []
        extracted_tokens = {}
        try:
            async with websockets.connect(url, ping_interval=None) as ws:
                for i, step in enumerate(steps):
                    action = step.get("action", "send")
                    payload = step.get("payload", "")
                    delay = int(step.get("delay", 500))

                    for token_name, token_val in extracted_tokens.items():
                        payload = payload.replace(f"§{token_name}§", token_val)

                    if action == "send":
                        await ws.send(payload)
                        try:
                            response = await asyncio.wait_for(ws.recv(), timeout=10.0)
                            results.append({"step": i + 1, "sent": payload, "response": str(response), "status": "success"})
                            for rule in rules:
                                name = rule.get("name", "")
                                pattern = rule.get("pattern", "")
                                if not name or not pattern:
                                    continue
                                try:
                                    match = re.search(pattern, str(response))
                                    if match:
                                        extracted_tokens[name] = match.group(1) if match.lastindex else match.group(0)
                                except re.error:
                                    pass
                        except asyncio.TimeoutError:
                            results.append({"step": i + 1, "sent": payload, "response": "TIMEOUT", "status": "timeout"})
                    elif action == "wait":
                        delay = int(payload) if payload.isdigit() else delay

                    await asyncio.sleep(delay / 1000.0)

            return {
                "status": "success",
                "results": results,
                "extracted_tokens": extracted_tokens,
                "steps_executed": len(results),
            }
        except Exception as e:
            return {
                "status": "error",
                "results": results,
                "extracted_tokens": extracted_tokens,
                "error": str(e),
            }

    @ctx.app.get("/oast/poll")
    async def oast_poll():
        try:
            from wshawk.oast_provider import OASTProvider

            provider = OASTProvider()
            callbacks = await provider.poll_callbacks()
            return {"callbacks": callbacks or [], "count": len(callbacks or [])}
        except ImportError:
            return {"callbacks": [], "count": 0, "msg": "OAST provider not available"}
        except Exception as e:
            return {"callbacks": [], "count": 0, "msg": str(e)}

    @ctx.app.post("/mutate")
    async def mutate_payload(data: Dict[str, Any]):
        payload = data.get("payload", "")
        strategy = data.get("strategy", "all")
        count = min(int(data.get("count", 10)), 50)
        if not payload:
            raise HTTPException(status_code=400, detail="Base payload is required")

        try:
            from wshawk.payload_mutator import MutationStrategy, PayloadMutator

            mutator = PayloadMutator()
            strategy_map = {
                "case": MutationStrategy.CASE_VARIATION,
                "encode": MutationStrategy.ENCODING,
                "comment": MutationStrategy.COMMENT_INJECTION,
                "whitespace": MutationStrategy.WHITESPACE,
                "concat": MutationStrategy.CONCATENATION,
                "bypass": MutationStrategy.BYPASS_FILTER,
                "tag_break": MutationStrategy.TAG_BREAKING,
                "polyglot": MutationStrategy.POLYGLOT,
            }

            if strategy == "all":
                results = mutator.generate_adaptive_payloads(payload, max_count=count)
                mutations = [{"strategy": "ADAPTIVE", "value": r} for r in results]
            elif strategy in strategy_map:
                results = mutator.mutate_payload(payload, strategy_map[strategy], count=count)
                mutations = [{"strategy": strategy.upper(), "value": r} for r in results]
            else:
                results = mutator.generate_adaptive_payloads(payload, max_count=count)
                mutations = [{"strategy": "ADAPTIVE", "value": r} for r in results]

            return {"status": "success", "mutations": mutations, "count": len(mutations), "engine": "SPE"}
        except ImportError:
            return {"status": "fallback", "mutations": [], "count": 0, "msg": "PayloadMutator not available. Using client-side mutations."}
        except Exception as e:
            return {"status": "error", "mutations": [], "count": 0, "msg": str(e)}
