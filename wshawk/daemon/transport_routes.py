from typing import Any, Dict

from fastapi import HTTPException, Request, WebSocket

from wshawk.bridge_security import (
    EXTENSION_PAIRING,
    extract_extension_id,
    websocket_client_is_local,
    websocket_has_valid_token,
)

from .context import BridgeContext


def _sanitize_handshake_value(value: Any, limit: int = 4096) -> str:
    if value is None:
        return ""
    return str(value)[:limit]


def _sanitize_handshake_payload(data: Dict[str, Any]) -> Dict[str, Any]:
    payload = data if isinstance(data, dict) else {}
    headers = payload.get("headers") if isinstance(payload.get("headers"), dict) else {}
    sanitized_headers = {}
    for key, value in list(headers.items())[:80]:
        header_name = _sanitize_handshake_value(key, 128)
        if not header_name:
            continue
        sanitized_headers[header_name] = _sanitize_handshake_value(value, 2048)

    return {
        "url": _sanitize_handshake_value(payload.get("url"), 4096),
        "method": _sanitize_handshake_value(payload.get("method"), 32),
        "headers": sanitized_headers,
        "timestamp": _sanitize_handshake_value(payload.get("timestamp"), 64),
        "initiator": _sanitize_handshake_value(payload.get("initiator"), 4096),
        "documentUrl": _sanitize_handshake_value(payload.get("documentUrl"), 4096),
        "tabId": int(payload.get("tabId", -1)) if str(payload.get("tabId", "")).lstrip("-").isdigit() else -1,
        "frameId": int(payload.get("frameId", -1)) if str(payload.get("frameId", "")).lstrip("-").isdigit() else -1,
        "source": _sanitize_handshake_value(payload.get("source"), 64),
        "extension_version": _sanitize_handshake_value(payload.get("extension_version"), 64),
        "project_id": _sanitize_handshake_value(payload.get("project_id"), 128),
    }


def register_transport_routes(ctx: BridgeContext) -> None:
    @ctx.app.get("/api/extension/status")
    async def api_extension_status(request: Request):
        pairing_state = EXTENSION_PAIRING.describe()
        return {
            "status": "online",
            "bridge_version": ctx.bridge_version,
            "pair_path": "/api/extension/pair",
            "handshake_path": "/api/extension/ingest/handshake",
            "token_header": "X-WSHawk-Extension-Token",
            "token_supported": True,
            "token_optional": False,
            "project_id_supported": True,
            "capture_scope_required": True,
            "pairing": {
                **pairing_state,
                "requested_origin": request.headers.get("origin", ""),
            },
        }

    @ctx.app.post("/api/extension/pair")
    async def api_extension_pair(request: Request, data: Dict[str, Any]):
        try:
            session = EXTENSION_PAIRING.issue_token(
                request.headers.get("origin"),
                extension_id=data.get("extension_id") or extract_extension_id(request),
            )
            return {
                "status": "success",
                "paired": True,
                "pairing": session,
                "handshake_path": "/api/extension/ingest/handshake",
                "token_header": "X-WSHawk-Extension-Token",
            }
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @ctx.app.get("/dom/status")
    async def dom_status():
        capture = ctx.get_browser_capture()
        return {"status": "success", **await capture.status()}

    @ctx.app.post("/dom/verify")
    async def dom_verify(data: Dict[str, Any]):
        try:
            capture = ctx.get_browser_capture()
            if not capture.is_available:
                return {"status": "error", "msg": "Playwright not installed"}

            result = await capture.verify_response(
                payload=data.get("payload", ""),
                response=data.get("response", ""),
                timeout_ms=data.get("timeout_ms", 3000),
            )
            return {"status": "success", **result.to_dict()}
        except Exception as e:
            return {"status": "error", "msg": str(e)}

    @ctx.app.post("/dom/verify/batch")
    async def dom_verify_batch(data: Dict[str, Any]):
        try:
            capture = ctx.get_browser_capture()
            if not capture.is_available:
                return {"status": "error", "msg": "Playwright not installed"}

            verified = await capture.batch_verify_responses(
                data.get("results", []),
                data.get("timeout_ms", 3000),
            )
            return {"status": "success", "results": verified}
        except Exception as e:
            return {"status": "error", "msg": str(e)}

    @ctx.app.post("/dom/auth/record")
    async def dom_auth_record(data: Dict[str, Any]):
        try:
            capture = ctx.get_browser_capture()
            if not capture.is_available:
                return {"status": "error", "msg": "Playwright not installed"}

            flow = await capture.record_auth_flow(
                login_url=data.get("login_url", ""),
                target_ws_url=data.get("target_ws_url", ""),
                timeout_s=data.get("timeout_s", 120),
            )
            if data.get("project_id"):
                ctx.platform_store.add_browser_artifact(
                    project_id=data["project_id"],
                    artifact_type="auth_flow_recorded",
                    source="browser_capture",
                    url=data.get("target_ws_url", "") or data.get("login_url", ""),
                    payload={
                        **flow,
                        "login_url": data.get("login_url", ""),
                        "target_ws_url": data.get("target_ws_url", ""),
                    },
                )
            ctx.maybe_log_platform_event(
                data.get("project_id"),
                "auth_flow_recorded",
                payload={
                    "login_url": data.get("login_url", ""),
                    "target_ws_url": data.get("target_ws_url", ""),
                    "cookie_count": len((flow.get("cookies") or [])),
                    "token_keys": sorted((flow.get("extracted_tokens") or {}).keys()),
                },
                target=data.get("target_ws_url", "") or data.get("login_url", ""),
            )
            return {"status": "success", "flow": flow}
        except Exception as e:
            return {"status": "error", "msg": str(e)}

    @ctx.app.post("/dom/auth/replay")
    async def dom_auth_replay(data: Dict[str, Any]):
        try:
            replay = ctx.get_browser_replay()
            if not replay.is_available:
                return {"status": "error", "msg": "Playwright not installed"}

            tokens = await replay.replay_auth_flow(data.get("flow"))
            identity = ctx.store_identity_from_tokens(
                project_id=data.get("project_id"),
                alias=data.get("identity_alias"),
                source="dom_replay",
                cookies=tokens.cookies,
                headers=tokens.headers,
                session_token=tokens.session_token,
                storage=(data.get("flow") or {}).get("local_storage", {}),
            )
            if data.get("project_id") and not identity:
                return {
                    "status": "error",
                    "msg": "Identity vault save failed",
                    "project_id": data.get("project_id"),
                    "identity_alias": data.get("identity_alias"),
                }
            if data.get("project_id"):
                ctx.platform_store.add_browser_artifact(
                    project_id=data["project_id"],
                    identity_id=identity.get("id") if identity else None,
                    artifact_type="auth_flow_replayed",
                    source="browser_replay",
                    url=(data.get("flow") or {}).get("target_ws_url", ""),
                    payload={
                        "valid": tokens.valid,
                        "cookies": tokens.cookies,
                        "headers": tokens.headers,
                        "session_token": tokens.session_token,
                        "flow": data.get("flow") or {},
                    },
                )
            ctx.maybe_log_platform_event(
                data.get("project_id"),
                "auth_flow_replayed",
                payload={
                    "valid": tokens.valid,
                    "identity_alias": data.get("identity_alias"),
                    "stored_identity_id": identity.get("id") if identity else None,
                    "cookie_count": len(tokens.cookies or []),
                    "header_keys": sorted((tokens.headers or {}).keys()),
                },
            )
            return {
                "status": "success",
                "valid": tokens.valid,
                "cookies": tokens.cookies,
                "headers": tokens.headers,
                "session_token": tokens.session_token,
                "identity": identity,
            }
        except Exception as e:
            return {"status": "error", "msg": str(e)}

    @ctx.app.post("/interceptor/toggle")
    async def interceptor_toggle(data: Dict[str, Any]):
        ctx.state.interception_enabled = data.get("enabled", False)
        if not ctx.state.interception_enabled:
            for fut in ctx.state.interception_queue.values():
                if not fut.done():
                    fut.set_result({"action": "drop"})
            ctx.state.interception_queue.clear()
        return {"status": "success", "interception": ctx.state.interception_enabled}

    @ctx.app.post("/interceptor/action")
    async def interceptor_action(data: Dict[str, Any]):
        i_id = data.get("id")
        action = data.get("action")
        payload = data.get("payload")

        if i_id in ctx.state.interception_queue:
            fut = ctx.state.interception_queue[i_id]
            if not fut.done():
                fut.set_result({"action": action, "payload": payload})
            del ctx.state.interception_queue[i_id]
            return {"status": "success"}
        return {"status": "not_found"}

    @ctx.app.post("/api/extension/ingest/handshake")
    async def api_extension_handshake(data: Dict[str, Any]):
        try:
            sanitized = _sanitize_handshake_payload(data)
            event = ctx.maybe_log_platform_event(
                sanitized.get("project_id"),
                "ws_handshake_captured",
                payload=sanitized,
                target=sanitized.get("url", ""),
            )
            if sanitized.get("project_id"):
                ctx.platform_store.ensure_target(
                    sanitized["project_id"],
                    sanitized.get("url", ""),
                    kind="websocket",
                    metadata={"source": "extension_handshake"},
                )
                ctx.platform_store.add_browser_artifact(
                    project_id=sanitized["project_id"],
                    artifact_type="ws_handshake",
                    source="extension",
                    url=sanitized.get("url", ""),
                    payload={"headers": sanitized.get("headers", {}), "event_id": event.get("id") if event else None},
                )
            await ctx.sio.emit("new_handshake", sanitized)
            return {"status": "success", "received": True}
        except Exception as e:
            return {"status": "error", "msg": str(e)}

    @ctx.app.get("/api/interceptor/status")
    async def api_interceptor_status_legacy():
        return {
            "status": "deprecated",
            "detail": "Use /api/extension/status and /api/extension/ingest/handshake instead.",
        }

    @ctx.app.post("/api/interceptor/handshake")
    async def api_interceptor_handshake_legacy():
        raise HTTPException(
            status_code=410,
            detail="Legacy extension handshake route retired. Use /api/extension/ingest/handshake.",
        )

    @ctx.app.websocket("/proxy")
    async def websocket_proxy(websocket: WebSocket, url: str):
        if not websocket_client_is_local(websocket):
            await websocket.close(code=4403)
            return

        if not websocket_has_valid_token(websocket):
            await websocket.close(code=4401)
            return

        project_id = websocket.query_params.get("project_id")
        try:
            await ctx.ws_proxy_service.proxy(
                websocket,
                url=url,
                sio=ctx.sio,
                state=ctx.state,
                project_id=project_id,
                correlation_id=websocket.query_params.get("correlation_id", ""),
                shadow_url=websocket.query_params.get("shadow_url", ""),
                delay_ms=int(websocket.query_params.get("delay_ms", "0")),
            )
        except Exception as e:
            print(f"[!] Proxy Error: {e}")
            ctx.maybe_log_platform_event(
                project_id,
                "ws_proxy_error",
                payload={"error": str(e)},
                target=url,
            )
            try:
                await websocket.close()
            except Exception:
                pass
