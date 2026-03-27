#!/usr/bin/env python3
"""
WSHawk GUI Bridge
High-speed FastAPI + Socket.IO server to communicate with the Electron frontend.

This module is now the composition layer only: it initializes bridge services,
registers route/socket modules, and starts the daemon.
"""

import os
import sys
from pathlib import Path

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import socketio

sys.path.insert(0, str(Path(__file__).parent.parent))

if "--plugin-runner" in sys.argv:
    from wshawk.plugin_runner import main as plugin_runner_main

    plugin_runner_main()
    raise SystemExit(0)

from wshawk.attacks import (
    HTTPAuthzDiffService,
    HTTPRaceService,
    HTTPReplayService,
    WebSocketAuthzDiffService,
    WebSocketRaceService,
    WebSocketReplayService,
    WebSocketSubscriptionAbuseService,
    WorkflowExecutionService,
)
from wshawk.bridge_security import (
    BRIDGE_TOKEN,
    TOKEN_HEADER,
    EXTENSION_ID_HEADER,
    EXTENSION_PAIRING,
    EXTENSION_TOKEN_HEADER,
    extract_extension_id,
    is_extension_path,
    is_extension_protected_path,
    is_http_public_path,
    is_trusted_browser_origin,
    is_valid_bridge_token,
    request_is_local,
    request_has_valid_extension_token,
    request_origin_is_extension,
    request_origin_is_trusted,
)
from wshawk.daemon import BridgeContext, GlobalState, run_daemon
from wshawk.daemon.platform_routes import register_platform_routes
from wshawk.daemon.scan_routes import register_scan_routes
from wshawk.daemon.socketio_events import register_socketio_events
from wshawk.daemon.system_routes import register_system_routes
from wshawk.daemon.team_routes import register_team_routes
from wshawk.daemon.transport_routes import register_transport_routes
from wshawk.daemon.web_routes import register_web_routes
from wshawk.db_manager import WSHawkDatabase, init_db
from wshawk.evidence import EvidenceBundleBuilder, EvidenceExportService, TimelineService
from wshawk.protocol import ProtocolGraphService, ProtocolInferenceService, ProtocolTemplateService
from wshawk.session import IdentityVaultService
from wshawk.store import ProjectStore
from wshawk.transport import WSHawkHTTPProxy, WSHawkWebSocketProxy

db = WSHawkDatabase()
platform_store = ProjectStore(db)
identity_vault = IdentityVaultService(db=db, store=platform_store)
http_proxy_service = WSHawkHTTPProxy(store=platform_store)
http_replay_service = HTTPReplayService(store=platform_store, http_proxy=http_proxy_service)
http_authz_diff_service = HTTPAuthzDiffService(store=platform_store, http_proxy=http_proxy_service)
http_race_service = HTTPRaceService(store=platform_store, http_proxy=http_proxy_service)
ws_replay_service = WebSocketReplayService(store=platform_store)
ws_authz_diff_service = WebSocketAuthzDiffService(store=platform_store)
ws_subscription_abuse_service = WebSocketSubscriptionAbuseService(store=platform_store)
ws_race_service = WebSocketRaceService(store=platform_store)
ws_proxy_service = WSHawkWebSocketProxy(store=platform_store)
workflow_service = WorkflowExecutionService(db=db, store=platform_store, http_proxy=http_proxy_service)
protocol_inference = ProtocolInferenceService()
protocol_templates = ProtocolTemplateService()
protocol_graph = ProtocolGraphService(platform_store, protocol_inference, protocol_templates)
timeline_service = TimelineService(platform_store)
evidence_bundle_builder = EvidenceBundleBuilder(db=db, store=platform_store)
evidence_exporter = EvidenceExportService(evidence_bundle_builder, protocol_graph=protocol_graph)

app = FastAPI(title="WSHawk GUI Bridge")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["null"],
    allow_origin_regex=r"^(https?://(127\.0\.0\.1|localhost|\[::1\])(?::\d+)?|chrome-extension://[a-z]+|edge-extension://[a-z]+|moz-extension://[-0-9a-f]+|safari-web-extension://[A-Za-z0-9.-]+)$",
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

sio = socketio.AsyncServer(async_mode="asgi", cors_allowed_origins=is_trusted_browser_origin)
socket_app = socketio.ASGIApp(sio, app)
state = GlobalState()

try:
    init_db()
except Exception as e:
    print(f"Error initializing database: {e}")

ctx = BridgeContext(
    app=app,
    sio=sio,
    db=db,
    state=state,
    platform_store=platform_store,
    identity_vault=identity_vault,
    http_replay_service=http_replay_service,
    http_authz_diff_service=http_authz_diff_service,
    http_race_service=http_race_service,
    ws_replay_service=ws_replay_service,
    ws_authz_diff_service=ws_authz_diff_service,
    ws_subscription_abuse_service=ws_subscription_abuse_service,
    ws_race_service=ws_race_service,
    workflow_service=workflow_service,
    ws_proxy_service=ws_proxy_service,
    http_proxy_service=http_proxy_service,
    protocol_inference=protocol_inference,
    protocol_templates=protocol_templates,
    protocol_graph=protocol_graph,
    timeline_service=timeline_service,
    evidence_bundle_builder=evidence_bundle_builder,
    evidence_exporter=evidence_exporter,
)


@app.middleware("http")
async def enforce_bridge_auth(request: Request, call_next):
    if not request_is_local(request):
        return JSONResponse(
            status_code=403,
            content={"status": "error", "detail": "Bridge only accepts local clients"},
        )

    if is_extension_path(request.url.path):
        if not request_origin_is_extension(request):
            return JSONResponse(
                status_code=403,
                content={"status": "error", "detail": "Bridge rejected an untrusted extension origin"},
            )

        if request.method == "OPTIONS":
            response = await call_next(request)
            response.headers[EXTENSION_ID_HEADER] = EXTENSION_PAIRING.get_trusted_extension_id() or ""
            return response

        if is_http_public_path(request.url.path):
            response = await call_next(request)
            response.headers[EXTENSION_ID_HEADER] = EXTENSION_PAIRING.get_trusted_extension_id() or ""
            return response

        if is_extension_protected_path(request.url.path) and request_has_valid_extension_token(request):
            return await call_next(request)

        return JSONResponse(
            status_code=401,
            content={"status": "error", "detail": "Extension pairing token required"},
            headers={EXTENSION_ID_HEADER: EXTENSION_PAIRING.get_trusted_extension_id() or ""},
        )

    if not request_origin_is_trusted(request):
        return JSONResponse(
            status_code=403,
            content={"status": "error", "detail": "Bridge rejected an untrusted browser origin"},
        )

    if request.method == "OPTIONS":
        return await call_next(request)

    candidate = request.headers.get(TOKEN_HEADER) or request.query_params.get("token")
    if not is_valid_bridge_token(candidate):
        return JSONResponse(
            status_code=401,
            content={"status": "error", "detail": "Bridge authentication required"},
        )

    return await call_next(request)


register_socketio_events(ctx)
register_system_routes(ctx)
register_platform_routes(ctx)
register_transport_routes(ctx)
register_scan_routes(ctx)
register_web_routes(ctx)
register_team_routes(ctx)


def _find_free_port(start: int, attempts: int = 10) -> int:
    import socket

    for offset in range(attempts):
        port = start + offset
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    return start


def main():
    requested_port = int(os.environ.get("WSHAWK_BRIDGE_PORT", 8080))
    port = _find_free_port(requested_port)
    if port != requested_port:
        print(f"[!] Port {requested_port} in use — using port {port} instead", flush=True)
    print(f"[BRIDGE_PORT] {port}", flush=True)
    print(f"[BRIDGE_TOKEN] {BRIDGE_TOKEN}", flush=True)
    print(f"[*] Starting WSHawk GUI Bridge on port {port}...", flush=True)
    run_daemon(socket_app, host="127.0.0.1", port=port)


if __name__ == "__main__":
    main()
