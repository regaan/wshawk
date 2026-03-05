#!/usr/bin/env python3
"""
WSHawk GUI Bridge
High-speed FastAPI + Socket.IO server to communicate with the Electron frontend.

This module acts as the 'Sidecar' backend, managing the scanner lifecycle
and streaming real-time events (intercepted messages, findings) to the UI.
"""

import asyncio
import json
import os
import sys
import uuid
from typing import Dict, List, Any, Optional
from datetime import datetime

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import socketio
import websockets

# Import WSHawk core
from pathlib import Path

# Add parent directory to path to allow absolute imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from wshawk.scanner_v2 import WSHawkV2
from wshawk.__main__ import WSPayloads
from wshawk.db_manager import WSHawkDatabase, init_db

# Initialize Database
db = WSHawkDatabase()

# Initialize FastAPI app
app = FastAPI(title="WSHawk GUI Bridge")

# Enable CORS for Electron
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize Socket.IO with async support
sio = socketio.AsyncServer(async_mode='asgi', cors_allowed_origins='*')
socket_app = socketio.ASGIApp(sio, app)

# Global scanner state
class GlobalState:
    scanner: Optional[WSHawkV2] = None
    active_scans: Dict[str, Any] = {}
    history: List[Dict] = []
    interception_enabled: bool = False
    interception_queue: dict = {}

state = GlobalState()

# Initialize Database
try:
    init_db()
except Exception as e:
    print(f"Error initializing database: {e}")

# ─── Socket.IO Events ───────────────────────────────────────────

@sio.event
async def connect(sid, environ):
    print(f"[*] Frontend connected: {sid}")
    await sio.emit('system_info', {
        'os': sys.platform,
        'version': '3.0.4',
        'status': 'ready'
    }, room=sid)

@sio.event
async def disconnect(sid):
    print(f"[*] Frontend disconnected: {sid}")
    # Team cleanup: remove from any room on disconnect
    try:
        from wshawk.team_engine import TeamEngine
        # Use the module-level team instance (defined in team routes section below)
        if 'team' in globals():
            room, op = team.leave_room(sid)
            if room and op:
                await sio.leave_room(sid, room.sio_room)
                await sio.emit("team_roster", {"operators": room.roster(), "room_code": room.code}, room=room.sio_room)
                activity = {"type": "leave", "operator": op.name, "color": op.color, "time": datetime.now().isoformat()}
                await sio.emit("team_activity", activity, room=room.sio_room)
    except Exception:
        pass

# ─── REST API Endpoints ─────────────────────────────────────────

from fastapi import WebSocket, WebSocketDisconnect

@app.get("/status")
async def get_status():
    return {
        "status": "online",
        "scanning": state.scanner is not None,
        "interception": state.interception_enabled,
        "active_scans": len(state.active_scans)
    }

@app.post("/scan/start")
async def start_scan(config: Dict[str, Any]):
    """Start a new WebSocket scan."""
    if state.scanner:
        raise HTTPException(status_code=400, detail="A scan is already running")
    
    target_url = config.get('url')
    if not target_url:
        raise HTTPException(status_code=400, detail="Target URL is required")
    
    # Initialize scanner
    scan_id = str(uuid.uuid4())[:8]
    auth_payload = config.get("auth_payload")
    state.scanner = WSHawkV2(target_url, auth_sequence=auth_payload, max_rps=config.get('rate', 10))
    
    # Attach event listeners to core (we'll implement this bridge in scanner_v2.py)
    # For now, we simulate the run in a background task
    task = asyncio.create_task(run_scan_task(scan_id))
    state.active_scans['scan_task'] = task
    
    return {"scan_id": scan_id, "status": "started"}

@app.post("/reqforge/send")
async def forge_send(data: Dict[str, Any]):
    """Send a manual payload via the request forge."""
    target_url = data.get("url")
    payload = data.get("payload")
    if not target_url or not payload:
        raise HTTPException(status_code=400, detail="Target URL and payload are required")
        
    try:
        async with websockets.connect(target_url, ping_interval=None) as ws:
            await ws.send(payload)
            # Increased timeout to 120 seconds to allow for manual interception delays!
            response = await asyncio.wait_for(ws.recv(), timeout=120.0)
            await sio.emit('message_sent', {'msg': payload, 'response': response})
            return {"status": "success", "response": response}
    except asyncio.TimeoutError:
        await sio.emit('message_sent', {'msg': payload, 'response': 'TIMEOUT'})
        return {"status": "timeout", "response": "No response received from target."}
    except Exception as e:
        return {"status": "error", "response": str(e)}

@app.post("/blaster/start")
async def blaster_start(data: Dict[str, Any]):
    """Start a Payload Blaster fuzzing session."""
    target_url = data.get("url")
    payloads = data.get("payloads", [])
    template = data.get("template", "")
    use_spe = data.get("spe", False)
    auth_payload = data.get("auth_payload")
    dom_verify = data.get("dom_verify", False)   # NEW: DOM XSS verification
    auth_flow = data.get("auth_flow", None)       # NEW: recorded auth flow for auto-reconnect

    if not target_url or not payloads:
        raise HTTPException(status_code=400, detail="Target URL and payloads array required")

    task = asyncio.create_task(
        run_blaster_task(
            target_url, payloads, template, use_spe,
            auth_payload, dom_verify, auth_flow,
        )
    )
    state.active_scans['blaster_task'] = task
    return {"status": "started", "count": len(payloads)}

@app.get("/blaster/payloads/{category}")
async def get_payloads(category: str):
    """Retrieve internal WSHawk payload lists."""
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
        "xxe": WSPayloads.get_xxe
    }
    
    if category not in payload_map:
        raise HTTPException(status_code=404, detail="Payload category not found")
        
    payloads = payload_map[category]()
    return {"category": category, "count": len(payloads), "payloads": payloads}

@app.get("/config/get")
async def get_config():
    """Get the current configuration from wshawk.yaml."""
    try:
        from .config import WSHawkConfig
        config = WSHawkConfig.load()
        return {
            "status": "success",
            "jiraUrl": config.get('integrations.jira.url', ''),
            "jiraEmail": config.get('integrations.jira.email', ''),
            "jiraToken": config.get('integrations.jira.api_token', ''),
            "jiraProject": config.get('integrations.jira.project_key', 'SEC'),
            "ddUrl": config.get('integrations.defectdojo.url', ''),
            "ddKey": config.get('integrations.defectdojo.api_key', ''),
            # AI settings
            "ai_provider": config.get('ai.provider', 'ollama'),
            "ai_model": config.get('ai.model', ''),
            "ai_base_url": config.get('ai.base_url', ''),
            "ai_api_key": config.get('ai.api_key', ''),
        }
    except Exception as e:
        return {"status": "error", "msg": str(e)}

@app.post("/config/save")
async def save_config(data: Dict[str, Any]):
    """Save configuration to wshawk.yaml."""
    try:
        import yaml
        from .config import WSHawkConfig
        config = WSHawkConfig.load()
        
        # In this implementation, we will update the config and save it back to wshawk.yaml
        config_path = Path('./wshawk.yaml')
        if not config_path.exists():
            config_path = Path('./wshawk.yml')
            if not config_path.exists():
                config_path = Path('./wshawk.yaml') # Default new file
        
        current_data = {}
        if config_path.exists():
            with open(config_path, 'r') as f:
                current_data = yaml.safe_load(f) or {}
                
        if 'integrations' not in current_data:
            current_data['integrations'] = {}
            
        if 'jira' not in current_data['integrations']:
            current_data['integrations']['jira'] = {}
            
        if 'defectdojo' not in current_data['integrations']:
            current_data['integrations']['defectdojo'] = {}
            
        # Update Jira
        jira_data = current_data['integrations']['jira']
        jira_data['enabled'] = bool(data.get('jiraUrl') and data.get('jiraToken'))
        if data.get('jiraUrl'): jira_data['url'] = data.get('jiraUrl')
        if data.get('jiraEmail'): jira_data['email'] = data.get('jiraEmail')
        if data.get('jiraToken'): jira_data['api_token'] = data.get('jiraToken')
        if data.get('jiraProject'): jira_data['project_key'] = data.get('jiraProject')
        
        # Update DefectDojo
        dd_data = current_data['integrations']['defectdojo']
        dd_data['enabled'] = bool(data.get('ddUrl') and data.get('ddKey'))
        if data.get('ddUrl'): dd_data['url'] = data.get('ddUrl')
        if data.get('ddKey'): dd_data['api_key'] = data.get('ddKey')

        # Update AI settings
        if 'ai' not in current_data:
            current_data['ai'] = {}
        ai_data = current_data['ai']
        if data.get('ai_provider'): ai_data['provider'] = data.get('ai_provider')
        if data.get('ai_model'): ai_data['model'] = data.get('ai_model')
        if data.get('ai_base_url'): ai_data['base_url'] = data.get('ai_base_url')
        if data.get('ai_api_key'): ai_data['api_key'] = data.get('ai_api_key')
        
        with open(config_path, 'w') as f:
            yaml.dump(current_data, f, default_flow_style=False)
            
        return {"status": "success"}
    except Exception as e:
        return {"status": "error", "msg": str(e)}

# ─── AI Context Exploit (Heuristic Auto-Exploit) ────────────────

@app.post("/ai/context-exploit")
async def ai_context_exploit(data: Dict[str, Any]):
    """
    Highlight-to-Hack: Generate context-aware exploit payloads.
    Receives the full message, highlighted selection, and cursor position.
    Returns payloads + a ready-to-use Blaster template.
    """
    try:
        import yaml
        from .ai_engine import AIEngine
        from .ai_exploit_engine import AIExploitEngine

        full_text = data.get("full_text", "")
        selection = data.get("selection", "")
        cursor_pos = data.get("cursor_pos", 0)
        vuln_types = data.get("vuln_types", None)
        count = data.get("count", 10)

        if not selection:
            return {"status": "error", "msg": "No text selected"}

        # Load AI config from wshawk.yaml
        ai_engine = None
        try:
            config_path = Path('./wshawk.yaml')
            if not config_path.exists():
                config_path = Path('./wshawk.yml')
            if config_path.exists():
                with open(config_path, 'r') as f:
                    cfg = yaml.safe_load(f) or {}
                ai_cfg = cfg.get('ai', {})
                provider = ai_cfg.get('provider', 'ollama')
                model = ai_cfg.get('model', '')
                base_url = ai_cfg.get('base_url', '')
                api_key = ai_cfg.get('api_key', '')
                if model:  # Only initialize if a model is configured
                    ai_engine = AIEngine(
                        provider=provider,
                        model=model,
                        base_url=base_url or None,
                        api_key=api_key or None,
                    )
        except Exception as e:
            logger.warning(f"AI engine init failed, using fallback payloads: {e}")

        exploit_engine = AIExploitEngine(ai_engine=ai_engine)
        result = await exploit_engine.generate_exploits(
            full_text=full_text,
            selection=selection,
            cursor_pos=cursor_pos,
            vuln_types=vuln_types,
            count=count,
        )

        return {"status": "success", **result}

    except Exception as e:
        logger.error(f"AI context-exploit error: {e}")
        return {"status": "error", "msg": str(e)}

# ─── DOM Invader (Headless Playwright Integration) ──────────────

# Lazy singleton — initialized on first use
_dom_invader = None

def _get_dom_invader():
    global _dom_invader
    if _dom_invader is None:
        from .dom_invader import DOMInvader
        _dom_invader = DOMInvader()
    return _dom_invader

@app.get("/dom/status")
async def dom_status():
    """Check if Playwright is installed and browser pool status."""
    invader = _get_dom_invader()
    return {"status": "success", **invader.status()}

@app.post("/dom/verify")
async def dom_verify(data: Dict[str, Any]):
    """
    Verify a single XSS payload via headless browser execution.
    Receives: { payload, response, timeout_ms? }
    Returns:  { executed, evidence, technique, ... }
    """
    try:
        invader = _get_dom_invader()
        if not invader.is_available:
            return {"status": "error", "msg": "Playwright not installed"}

        if not invader.pool.is_started:
            await invader.start()

        result = await invader.verify_response(
            payload=data.get("payload", ""),
            response=data.get("response", ""),
            timeout_ms=data.get("timeout_ms", 3000),
        )
        return {"status": "success", **result.to_dict()}

    except Exception as e:
        return {"status": "error", "msg": str(e)}

@app.post("/dom/verify/batch")
async def dom_verify_batch(data: Dict[str, Any]):
    """
    Verify multiple Blaster results concurrently.
    Receives: { results: [{ payload, response }], timeout_ms? }
    Returns:  { results: [{ ...original, dom_verified, dom_evidence }] }
    """
    try:
        invader = _get_dom_invader()
        if not invader.is_available:
            return {"status": "error", "msg": "Playwright not installed"}

        if not invader.pool.is_started:
            await invader.start()

        results = data.get("results", [])
        timeout_ms = data.get("timeout_ms", 3000)

        verified = await invader.batch_verify_responses(results, timeout_ms)
        return {"status": "success", "results": verified}

    except Exception as e:
        return {"status": "error", "msg": str(e)}

@app.post("/dom/auth/record")
async def dom_auth_record(data: Dict[str, Any]):
    """
    Start recording an auth flow. Opens a visible browser for user to log in.
    Receives: { login_url, target_ws_url?, timeout_s? }
    Returns:  { flow: AuthFlow dict }
    """
    try:
        invader = _get_dom_invader()
        if not invader.is_available:
            return {"status": "error", "msg": "Playwright not installed"}

        flow = await invader.record_auth_flow(
            login_url=data.get("login_url", ""),
            target_ws_url=data.get("target_ws_url", ""),
            timeout_s=data.get("timeout_s", 120),
        )
        return {"status": "success", "flow": flow}

    except Exception as e:
        return {"status": "error", "msg": str(e)}

@app.post("/dom/auth/replay")
async def dom_auth_replay(data: Dict[str, Any]):
    """
    Replay a saved auth flow to get fresh tokens.
    Receives: { flow? } (optional, uses saved flow if omitted)
    Returns:  { valid, cookies, headers, session_token }
    """
    try:
        invader = _get_dom_invader()
        if not invader.is_available:
            return {"status": "error", "msg": "Playwright not installed"}

        if not invader.pool.is_started:
            await invader.start()

        tokens = await invader.replay_auth_flow(data.get("flow"))
        return {
            "status": "success",
            "valid": tokens.valid,
            "cookies": tokens.cookies,
            "headers": tokens.headers,
            "session_token": tokens.session_token,
        }

    except Exception as e:
        return {"status": "error", "msg": str(e)}

@app.post("/interceptor/toggle")
async def interceptor_toggle(data: Dict[str, Any]):
    """Toggle the interceptor state."""
    state.interception_enabled = data.get("enabled", False)
    # If turned off, automatically drop all pending blocked requests
    if not state.interception_enabled:
        for fut in state.interception_queue.values():
            if not fut.done():
                fut.set_result({"action": "drop"})
        state.interception_queue.clear()
    return {"status": "success", "interception": state.interception_enabled}


@app.post("/interceptor/action")
async def interceptor_action(data: Dict[str, Any]):
    """Take action on a pending intercepted frame."""
    i_id = data.get("id")
    action = data.get("action")
    payload = data.get("payload")
    
    if i_id in state.interception_queue:
        fut = state.interception_queue[i_id]
        if not fut.done():
            fut.set_result({"action": action, "payload": payload})
        del state.interception_queue[i_id]
        return {"status": "success"}
    return {"status": "not_found"}

@app.post("/api/interceptor/handshake")
async def api_interceptor_handshake(data: Dict[str, Any]):
    """Receive WebSocket handshake from browser extension."""
    try:
        # Emit to Socket.IO so the UI can display it
        await sio.emit('new_handshake', data)
        return {"status": "success", "received": True}
    except Exception as e:
        return {"status": "error", "msg": str(e)}

@app.websocket("/proxy")
async def websocket_proxy(websocket: WebSocket, url: str):
    """The MitM WebSocket Proxy Endpoint."""
    await websocket.accept()
    
    # Connect to the real target
    try:
        async with websockets.connect(url, ping_interval=None) as target_ws:
            
            async def client_to_target():
                try:
                    while True:
                        msg = await websocket.receive_text()
                        if state.interception_enabled:
                            i_id = str(uuid.uuid4())
                            fut = asyncio.Future()
                            state.interception_queue[i_id] = fut
                            
                            await sio.emit('intercepted_frame', {
                                'id': i_id,
                                'direction': 'OUT',
                                'payload': msg,
                                'url': url
                            })
                            
                            result = await fut
                            if result.get('action') == 'forward':
                                f_payload = result.get('payload', msg)
                                await target_ws.send(f_payload)
                                await sio.emit('message_sent', {'msg': f_payload, 'url': url})
                        else:
                            await target_ws.send(msg)
                            await sio.emit('message_sent', {'msg': msg, 'url': url})
                except Exception:
                    pass

            async def target_to_client():
                try:
                    while True:
                        msg = await target_ws.recv()
                        if state.interception_enabled:
                            i_id = str(uuid.uuid4())
                            fut = asyncio.Future()
                            state.interception_queue[i_id] = fut
                            
                            await sio.emit('intercepted_frame', {
                                'id': i_id,
                                'direction': 'IN',
                                'payload': msg,
                                'url': url
                            })
                            
                            result = await fut
                            if result.get('action') == 'forward':
                                f_payload = result.get('payload', msg)
                                await websocket.send_text(f_payload)
                                await sio.emit('message_sent', {'response': f_payload, 'url': url})
                        else:
                            await websocket.send_text(msg)
                            await sio.emit('message_sent', {'response': msg, 'url': url})
                except Exception:
                    pass

            await asyncio.gather(client_to_target(), target_to_client())
    except Exception as e:
        print(f"[!] Proxy Error: {e}")
        try:
            await websocket.close()
        except:
            pass

# ─── Background Tasks ───────────────────────────────────────────

async def scanner_event_callback(event_type: str, data: Any):
    """Callback triggered by the scanner core to emit events to Socket.IO."""
    await sio.emit(event_type, data)

async def run_scan_task(scan_id: str):
    """Background task to manage the scanner and stream results."""
    try:
        if not state.scanner:
            return

        # Inject the callback into the existing scanner instance
        state.scanner.event_callback = scanner_event_callback
        
        # Emit scan start event
        await sio.emit('scan_update', {'id': scan_id, 'status': 'running'})
        
        # Run the actual heuristic scan
        # This will now trigger scanner_event_callback for every finding
        vulns = await state.scanner.run_heuristic_scan()
        
        await sio.emit('scan_update', {
            'id': scan_id, 
            'status': 'completed',
            'vulnerabilities_count': len(vulns)
        })
        state.scanner = None
        
    except asyncio.CancelledError:
        print(f"[*] Scan cancelled by user.")
        await sio.emit('scan_error', {'id': scan_id, 'error': "Scan Cancelled."})
        state.scanner = None
    except Exception as e:
        print(f"[!] Scan Task Error: {e}")
        await sio.emit('scan_error', {'id': scan_id, 'error': str(e)})
        state.scanner = None
        
async def run_blaster_task(
    url: str,
    payloads: List[str],
    template: str = "",
    use_spe: bool = False,
    auth_payload: str = None,
    dom_verify: bool = False,
    auth_flow: Optional[Dict[str, Any]] = None,
):
    """
    Background task to run payload blaster fuzzing loops.

    New params:
        dom_verify: If True, pass each successful response through the
                    DOMInvader XSSVerifier and attach dom_verified/evidence.
        auth_flow:  Recorded auth flow dict. If the WS connection drops
                    (token expired), replay the flow headlessly for fresh
                    tokens and auto-reconnect.
    """
    # ── Initialise helpers ───────────────────────────────────────
    evolver = None
    if use_spe:
        try:
            from .smart_payloads.payload_evolver import PayloadEvolver
            evolver = PayloadEvolver()
        except ImportError:
            pass

    # DOMInvader — start the browser pool once if verification is requested
    invader = None
    if dom_verify:
        try:
            invader = _get_dom_invader()
            if invader.is_available and not invader.pool.is_started:
                await invader.start()
        except Exception as e:
            logger.warning(f"DOM Invader init failed: {e}")
            invader = None

    # ── Helper: build final WS message from template + payload ───
    def apply_template(p: str) -> str:
        if template and "§inject§" in template:
            return template.replace("§inject§", p)
        return p

    # ── Helper: get extra headers from auth flow tokens ──────────
    async def get_ws_headers() -> dict:
        if not auth_flow or not invader:
            return {}
        try:
            tokens = await invader.replay_auth_flow(auth_flow)
            if tokens.valid:
                return tokens.headers
        except Exception as e:
            logger.warning(f"Auth replay failed: {e}")
        return {}

    # ── Build initial connection headers ─────────────────────────
    ws_headers = {}
    if auth_flow:
        ws_headers = await get_ws_headers()

    # ── Retry loop — re-connects on auth expiry ──────────────────
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
                    # Send static auth payload if provided
                    if auth_payload and auth_payload.strip():
                        try:
                            await ws.send(auth_payload)
                            await asyncio.sleep(0.5)
                        except Exception as e:
                            print(f"[!] Blaster auth payload failed: {e}")

                    # Fuzz remaining payloads
                    while payload_idx < len(remaining_payloads):
                        p = remaining_payloads[payload_idx]
                        payload_idx += 1

                        # SPE mutation
                        if evolver and len(p) > 2:
                            import random
                            if random.random() > 0.3:
                                try:
                                    p = evolver._mutate(p)
                                except Exception:
                                    pass

                        final_packet = apply_template(p)

                        await sio.emit('blaster_progress', {
                            'payload': final_packet, 'status': 'sending'
                        })
                        await asyncio.sleep(0.3)

                        await ws.send(final_packet)

                        try:
                            resp = await asyncio.wait_for(ws.recv(), timeout=3.0)
                            resp_str = str(resp)

                            # ── DOM XSS Verification ────────────────
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
                                    # If confirmed XSS — emit a dedicated event
                                    if vr.executed:
                                        await sio.emit('dom_xss_confirmed', {
                                            "payload": final_packet,
                                            "evidence": vr.evidence,
                                            "technique": vr.technique.value,
                                            "response_snippet": resp_str[:200],
                                        })
                                except Exception as e:
                                    logger.warning(f"DOM verify inline failed: {e}")

                            await sio.emit('blaster_result', {
                                'payload': final_packet,
                                'status': 'success',
                                'length': len(resp_str),
                                'response': resp_str[:100],
                                **dom_result,
                            })
                            await sio.emit('message_sent', {
                                'msg': final_packet, 'response': resp_str
                            })

                        except asyncio.TimeoutError:
                            await sio.emit('blaster_result', {
                                'payload': final_packet, 'status': 'timeout',
                                'length': 0, 'response': 'No response',
                                'dom_verified': False, 'dom_evidence': '',
                            })
                        except Exception as e:
                            # Connection error mid-fuzz → break to retry
                            err_str = str(e)
                            if "ConnectionClosed" in err_str or "1000" in err_str or "1001" in err_str:
                                # Likely session expired — step back so we retry this payload
                                payload_idx -= 1
                                raise
                            await sio.emit('blaster_result', {
                                'payload': final_packet, 'status': 'error',
                                'length': 0, 'response': err_str,
                            })

            except asyncio.CancelledError:
                raise
            except Exception as e:
                err_str = str(e)
                # Attempt auth replay and reconnect
                if auth_flow and reconnect_count < max_reconnects:
                    reconnect_count += 1
                    await sio.emit('blaster_result', {
                        'payload': 'SESSION_EXPIRED',
                        'status': 'info',
                        'length': 0,
                        'response': f'Session expired. Replaying auth flow (attempt {reconnect_count})...',
                    })
                    ws_headers = await get_ws_headers()
                    await asyncio.sleep(1)
                else:
                    await sio.emit('blaster_result', {
                        'payload': 'CONNECTION ERROR', 'status': 'fatal',
                        'length': 0, 'response': err_str,
                    })
                    break

    except asyncio.CancelledError:
        print("[*] Blaster cancelled by user.")
        await sio.emit('blaster_result', {
            'payload': 'CANCELLED', 'status': 'error',
            'length': 0, 'response': 'Stopped.',
        })
    finally:
        await sio.emit('blaster_completed', {'status': 'done'})

@app.post("/scan/stop")
async def stop_scan():
    if 'scan_task' in state.active_scans and not state.active_scans['scan_task'].done():
        state.active_scans['scan_task'].cancel()
        return {"status": "success", "msg": "Scan cancelled"}
    return {"status": "error", "msg": "No scan running"}

@app.post("/blaster/stop")
async def stop_blaster():
    if 'blaster_task' in state.active_scans and not state.active_scans['blaster_task'].done():
        state.active_scans['blaster_task'].cancel()
        return {"status": "success", "msg": "Blaster cancelled"}
    return {"status": "error", "msg": "No blaster running"}
# ─── Endpoint Discovery API ──────────────────────────────────────

@app.post("/discovery/scan")
async def discovery_scan(data: Dict[str, Any]):
    """Discover WebSocket endpoints from an HTTP target."""
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

@app.post("/discovery/probe")
async def discovery_probe(data: Dict[str, Any]):
    """Probe a WebSocket endpoint to check if it's alive."""
    url = data.get("url")
    if not url:
        raise HTTPException(status_code=400, detail="WebSocket URL is required")

    try:
        async with websockets.connect(url, ping_interval=None, close_timeout=5) as ws:
            return {"alive": True, "status": "connected"}
    except Exception as e:
        return {"alive": False, "status": str(e)}

# ─── Auth Sequence API ───────────────────────────────────────────

@app.post("/auth/test")
async def auth_test(data: Dict[str, Any]):
    """Execute a multi-step authentication sequence and extract tokens."""
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

                # Substitute any previously extracted tokens
                for token_name, token_val in extracted_tokens.items():
                    payload = payload.replace(f"§{token_name}§", token_val)

                if action == "send":
                    await ws.send(payload)
                    try:
                        response = await asyncio.wait_for(ws.recv(), timeout=10.0)
                        results.append({
                            "step": i + 1,
                            "sent": payload,
                            "response": str(response),
                            "status": "success"
                        })

                        # Apply extraction rules
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
                        results.append({
                            "step": i + 1,
                            "sent": payload,
                            "response": "TIMEOUT",
                            "status": "timeout"
                        })

                elif action == "wait":
                    delay = int(payload) if payload.isdigit() else delay

                await asyncio.sleep(delay / 1000.0)

        return {
            "status": "success",
            "results": results,
            "extracted_tokens": extracted_tokens,
            "steps_executed": len(results)
        }
    except Exception as e:
        return {
            "status": "error",
            "results": results,
            "extracted_tokens": extracted_tokens,
            "error": str(e)
        }

# ─── OAST Callback API ──────────────────────────────────────────

@app.get("/oast/poll")
async def oast_poll():
    """Poll for Out-of-Band Application Security Testing callbacks."""
    try:
        from wshawk.oast_provider import OASTProvider
        provider = OASTProvider()
        callbacks = await provider.poll_callbacks()
        return {"callbacks": callbacks or [], "count": len(callbacks or [])}
    except ImportError:
        return {"callbacks": [], "count": 0, "msg": "OAST provider not available"}
    except Exception as e:
        return {"callbacks": [], "count": 0, "msg": str(e)}

# ─── Mutation Lab API ────────────────────────────────────────────

@app.post("/mutate")
async def mutate_payload(data: Dict[str, Any]):
    """Generate payload mutations using the real SPE engine."""
    payload = data.get("payload", "")
    strategy = data.get("strategy", "all")
    count = min(int(data.get("count", 10)), 50)

    if not payload:
        raise HTTPException(status_code=400, detail="Base payload is required")

    try:
        from wshawk.payload_mutator import PayloadMutator, MutationStrategy

        mutator = PayloadMutator()
        mutations = []

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

        return {
            "status": "success",
            "mutations": mutations,
            "count": len(mutations),
            "engine": "SPE"
        }
    except ImportError:
        return {"status": "fallback", "mutations": [], "count": 0, "msg": "PayloadMutator not available. Using client-side mutations."}
    except Exception as e:
        return {"status": "error", "mutations": [], "count": 0, "msg": str(e)}

# ─────────────────────────────────────────────────────────────────────
# Web Pentest API — All HTTP-based security tools
# Engines are imported from the wshawk.web_pentest package.
# ─────────────────────────────────────────────────────────────────────

from wshawk.web_pentest import (
    # Phase 1: Core
    WSHawkHTTPProxy, WSHawkFuzzer, WSHawkDirScanner,
    WSHawkHeaderAnalyzer, WSHawkSubdomainFinder,
    # Phase 2: Automation
    WSHawkCrawler, WSHawkVulnScanner, WSHawkReportGenerator,
    # Phase 3: Recon
    WSHawkTechFingerprinter, WSHawkSSLAnalyzer, WSHawkSensitiveFinder,
    # Phase 4: Offensive
    WSHawkWAFDetector, WSHawkCORSTester, WSHawkPortScanner, WSHawkDNSLookup,
    # Phase 5: Exploit & Validation
    WSHawkCSRFForge, WSHawkBlindProbe, WSHawkRedirectHunter, WSHawkProtoPolluter,
    # Phase 6: Interception & Chaining
    WSHawkProxyCA, WSHawkAttackChainer,
)

# Mutable reference for stop support on long-running scans
_vuln_scanner: Optional[WSHawkVulnScanner] = None


# ── HTTP Forge ───────────────────────────────────────────────────────

@app.post("/web/request")
async def web_request(data: Dict[str, Any]):
    """Proxy a single HTTP request to bypass browser CORS."""
    url = data.get("url", "").strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")

    engine = WSHawkHTTPProxy()
    try:
        return await engine.send_request(
            method=data.get("method", "GET"),
            url=url,
            headers_str=data.get("headers", ""),
            body=data.get("body", ""),
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── HTTP Fuzzer ──────────────────────────────────────────────────────

@app.post("/web/fuzz")
async def web_fuzz(data: Dict[str, Any]):
    """Start an asynchronous HTTP fuzzing task with §FUZZ§ markers."""
    url = data.get("url", "")
    if not url or "§FUZZ§" not in url:
        raise HTTPException(status_code=400, detail="URL must contain §FUZZ§ marker.")

    engine = WSHawkFuzzer(sio_instance=sio)
    asyncio.create_task(engine.run_fuzz(
        method=data.get("method", "GET"),
        url=url,
        wordlist_name=data.get("wordlist", "common"),
        custom_file=data.get("custom_file"),
        encoder=data.get("encoder", "none"),
        grep_regex=data.get("grep_regex", ""),
    ))
    return {"status": "started", "msg": "Fuzz task submitted"}


# ── Directory Scanner ────────────────────────────────────────────────

@app.post("/web/dirscan")
async def web_dirscan(data: Dict[str, Any]):
    """Start an asynchronous directory brute-force scan."""
    url = data.get("url", "").strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL required")

    engine = WSHawkDirScanner(sio_instance=sio)
    asyncio.create_task(engine.scan_directories(
        url=url,
        exts_raw=data.get("exts", ""),
        custom_file=data.get("custom_file", ""),
        recursive=data.get("recursive", False),
        throttle_ms=int(data.get("throttle_ms", 0)),
    ))
    return {"status": "started", "msg": "Dirscan task submitted"}


# ── Header Analyzer ──────────────────────────────────────────────────

@app.post("/web/headers")
async def web_headers(data: Dict[str, Any]):
    """Analyze HTTP security headers and return risk assessment."""
    url = data.get("url", "").strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL required")

    try:
        engine = WSHawkHeaderAnalyzer()
        result = await engine.analyze(url)
        return {"status": "success", "headers": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Subdomain Finder ─────────────────────────────────────────────────

@app.post("/web/subdomains")
async def web_subdomains(data: Dict[str, Any]):
    """Enumerate subdomains via crt.sh, OTX, and optional brute-force."""
    target = data.get("target", "").strip()
    if not target:
        raise HTTPException(status_code=400, detail="Target domain required")

    try:
        engine = WSHawkSubdomainFinder(sio_instance=sio)
        subs = await engine.list_subdomains(
            target=target,
            active_brute=data.get("active_brute", False),
            active_resolve=data.get("active_resolve", True),
        )
        return {"status": "success", "subdomains": subs}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Web Crawler ──────────────────────────────────────────────────────

@app.post("/web/crawl")
async def web_crawl(data: Dict[str, Any]):
    """Start a BFS web crawler to discover pages, forms, and endpoints."""
    url = data.get("url", "").strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL required")

    engine = WSHawkCrawler(sio_instance=sio)
    asyncio.create_task(engine.crawl(
        start_url=url,
        max_depth=int(data.get("max_depth", 3)),
        max_pages=int(data.get("max_pages", 100)),
    ))
    return {"status": "started", "msg": "Crawl task submitted"}


# ── Vulnerability Scanner ────────────────────────────────────────────

async def _run_vuln_wrapper(url, options):
    global _vuln_scanner
    report = await _vuln_scanner.run_scan(url, options)
    try:
        scan_id = db.save_scan(url, report)
        print(f"Scan saved to DB: {scan_id}")
    except Exception as e:
        print(f"Failed to save scan to DB: {e}")

@app.post("/web/vulnscan")
async def web_vulnscan(data: Dict[str, Any]):
    """Launch the automated vuln scanner (Crawl → Headers → DirScan → Fuzz)."""
    global _vuln_scanner
    url = data.get("url", "").strip()
    if not url:
        raise HTTPException(status_code=400, detail="Target URL required")

    _vuln_scanner = WSHawkVulnScanner(sio_instance=sio)
    asyncio.create_task(_run_vuln_wrapper(url, data.get("options", {})))
    return {"status": "started", "msg": "Vulnerability scan submitted"}


@app.post("/web/vulnscan/stop")
async def web_vulnscan_stop():
    """Stop a running vulnerability scan."""
    global _vuln_scanner
    if _vuln_scanner:
        _vuln_scanner.stop()
    return {"status": "stopped"}

# ── Scan History (DB) ────────────────────────────────────────────────

@app.get("/history")
async def api_get_history():
    """Return all historical scans."""
    try:
        return {"status": "success", "history": db.list_all()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/history/{scan_id}")
async def api_get_scan(scan_id: str):
    """Return an individual scan with full findings."""
    try:
        scan = db.get(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        return {"status": "success", "scan": scan}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/history/compare/{id1}/{id2}")
async def api_compare_scans(id1: str, id2: str):
    """Compare two historical scans for fixed and new vulns."""
    try:
        res = db.compare_scans(id1, id2)
        if "error" in res:
            raise HTTPException(status_code=404, detail=res["error"])
        return {"status": "success", "diff": res}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Report Generator ─────────────────────────────────────────────────

@app.post("/web/report")
async def web_report(data: Dict[str, Any]):
    """Export scan findings to HTML, JSON, or PDF report."""
    report_data = data.get("report", {})
    fmt = data.get("format", "html")

    gen = WSHawkReportGenerator()
    try:
        if fmt == "json":
            path = gen.generate_json(report_data)
        elif fmt == "pdf":
            path = gen.generate_pdf(report_data)
        else:
            path = gen.generate_html(report_data)
        return {"status": "success", "path": path, "format": fmt}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Tech Fingerprinter ───────────────────────────────────────────────

@app.post("/web/fingerprint")
async def web_fingerprint(data: Dict[str, Any]):
    """Detect technology stack (CMS, frameworks, CDN, etc.)."""
    url = data.get("url", "").strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL required")

    try:
        engine = WSHawkTechFingerprinter()
        result = await engine.fingerprint(url)
        return {"status": "success", **result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── SSL/TLS Analyzer ─────────────────────────────────────────────────

@app.post("/web/ssl")
async def web_ssl(data: Dict[str, Any]):
    """Analyze SSL/TLS certificate and protocol configuration."""
    host = data.get("host", "").strip()
    if not host:
        raise HTTPException(status_code=400, detail="Host required")

    try:
        engine = WSHawkSSLAnalyzer()
        result = await engine.analyze(host, port=int(data.get("port", 443)))
        return {"status": "success", **result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Sensitive Data Finder ────────────────────────────────────────────

@app.post("/web/sensitive")
async def web_sensitive(data: Dict[str, Any]):
    """Scan a page for leaked API keys, tokens, and secrets."""
    url = data.get("url", "").strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL required")

    try:
        engine = WSHawkSensitiveFinder(sio_instance=sio)
        result = await engine.scan_url(url)
        return {"status": "success", **result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── WAF Detector ─────────────────────────────────────────────────────

@app.post("/web/waf")
async def web_waf_detect(data: Dict[str, Any]):
    """Detect Web Application Firewalls protecting a target."""
    url = data.get("url", "").strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL required")

    try:
        engine = WSHawkWAFDetector()
        result = await engine.detect(url)
        return {"status": "success", **result}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── CORS Tester ──────────────────────────────────────────────────────

@app.post("/web/cors")
async def web_cors_test(data: Dict[str, Any]):
    """Test for CORS misconfigurations on a target URL."""
    url = data.get("url", "").strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL required")

    try:
        engine = WSHawkCORSTester()
        result = await engine.test(url)
        return {"status": "success", **result}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Port Scanner ─────────────────────────────────────────────────────

@app.post("/web/portscan")
async def web_portscan(data: Dict[str, Any]):
    """Scan TCP ports on a target host."""
    host = data.get("host", "").strip()
    if not host:
        raise HTTPException(status_code=400, detail="Host required")

    engine = WSHawkPortScanner(sio_instance=sio)
    asyncio.create_task(engine.scan(
        host=host,
        ports=data.get("ports"),
        preset=data.get("preset", "top100"),
        timeout_s=float(data.get("timeout", 2.0)),
        grab_banners=data.get("banners", True),
    ))
    return {"status": "started", "msg": "Port scan submitted"}


# ── DNS / WHOIS Lookup ───────────────────────────────────────────────

@app.post("/web/dns")
async def web_dns_lookup(data: Dict[str, Any]):
    """Perform DNS record enumeration and WHOIS lookup."""
    domain = data.get("domain", "").strip()
    if not domain:
        raise HTTPException(status_code=400, detail="Domain required")

    try:
        engine = WSHawkDNSLookup()
        result = await engine.lookup(domain)
        return {"status": "success", **result}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── CSRF Forge ───────────────────────────────────────────────────────

@app.post("/web/csrf")
async def web_csrf_forge(data: Dict[str, Any]):
    """Generate a CSRF proof-of-concept exploit page."""
    url = data.get("url", "").strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL required")

    try:
        engine = WSHawkCSRFForge()
        result = await engine.generate(
            method=data.get("method", "POST"),
            url=url,
            headers=data.get("headers", ""),
            body=data.get("body", ""),
            content_type=data.get("content_type", ""),
        )
        return {"status": "success", **result}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Blind Probe (SSRF) ──────────────────────────────────────────────

@app.post("/web/ssrf")
async def web_ssrf_probe(data: Dict[str, Any]):
    """Test URL parameters for SSRF vulnerabilities."""
    url = data.get("url", "").strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL required")

    try:
        engine = WSHawkBlindProbe(sio_instance=sio)
        asyncio.create_task(engine.probe(
            url=url,
            param=data.get("param", ""),
            method=data.get("method", "GET"),
            body=data.get("body", ""),
            custom_payloads=data.get("custom_payloads", []),
        ))
        return {"status": "started", "msg": "SSRF probe started"}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Redirect Hunter ─────────────────────────────────────────────────

@app.post("/web/redirect")
async def web_redirect_scan(data: Dict[str, Any]):
    """Scan URL parameters for open redirect vulnerabilities."""
    url = data.get("url", "").strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL required")

    try:
        engine = WSHawkRedirectHunter(sio_instance=sio)
        result = await engine.scan(
            url=url,
            param=data.get("param", ""),
        )
        return {"status": "success", **result}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Proto Polluter ───────────────────────────────────────────────────

@app.post("/web/proto")
async def web_proto_pollute(data: Dict[str, Any]):
    """Test for JavaScript Prototype Pollution vulnerabilities."""
    url = data.get("url", "").strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL required")

    try:
        engine = WSHawkProtoPolluter(sio_instance=sio)
        result = await engine.test(
            url=url,
            method=data.get("method", "GET"),
            body=data.get("body", ""),
            content_type=data.get("content_type", ""),
        )
        return {"status": "success", **result}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── HawkProxy CA ────────────────────────────────────────────────────

@app.post("/proxy/ca/generate")
async def proxy_ca_generate(data: Dict[str, Any]):
    """Generate or retrieve the WSHawk root CA certificate."""
    try:
        ca = WSHawkProxyCA()
        result = await ca.generate_ca(force=data.get("force", False))
        return {"status": "success", **result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/proxy/ca/info")
async def proxy_ca_info():
    """Get current CA certificate information."""
    try:
        ca = WSHawkProxyCA()
        result = await ca.get_ca_info()
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/proxy/ca/host")
async def proxy_ca_host_cert(data: Dict[str, Any]):
    """Generate a certificate for a specific hostname."""
    hostname = data.get("hostname", "").strip()
    if not hostname:
        raise HTTPException(status_code=400, detail="Hostname required")
    try:
        ca = WSHawkProxyCA()
        result = await ca.generate_host_cert(hostname)
        return {"status": "success", **result}
    except FileNotFoundError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/proxy/ca/certs")
async def proxy_ca_list_certs():
    """List all generated host certificates."""
    try:
        ca = WSHawkProxyCA()
        return await ca.list_certs()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Attack Chainer ──────────────────────────────────────────────────

@app.post("/web/chain")
async def web_attack_chain(data: Dict[str, Any]):
    """Execute a multi-step attack chain with value extraction."""
    steps = data.get("steps", [])
    if not steps:
        raise HTTPException(status_code=400, detail="Steps required")
    try:
        engine = WSHawkAttackChainer(sio_instance=sio)
        result = await engine.execute_chain(
            steps=steps,
            initial_vars=data.get("variables", {}),
        )
        return {"status": "success", **result}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/web/extract")
async def web_quick_extract(data: Dict[str, Any]):
    """Quick single-URL value extraction."""
    url = data.get("url", "").strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL required")
    try:
        engine = WSHawkAttackChainer()
        result = await engine.quick_extract(
            url=url,
            patterns=data.get("patterns", []),
        )
        return {"status": "success", **result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Crawler → Sensitive Finder Pipeline ──────────────────────────────

@app.post("/web/crawl-sensitive")
async def web_crawl_sensitive(data: Dict[str, Any]):
    """Crawl a target and auto-scan every discovered page for leaked secrets."""
    url = data.get("url", "").strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL required")

    async def _pipeline():
        # Phase 1: Crawl
        await sio.emit("pipeline_phase", {"phase": "crawl", "status": "running"})
        crawler = WSHawkCrawler(sio_instance=sio)
        crawl_result = await crawler.crawl(
            start_url=url,
            max_depth=int(data.get("max_depth", 2)),
            max_pages=int(data.get("max_pages", 50)),
        )

        pages = crawl_result.get("pages", [])
        await sio.emit("pipeline_phase", {
            "phase": "crawl", "status": "done",
            "pages_crawled": len(pages)
        })

        # Phase 2: Scan each discovered page for sensitive data
        await sio.emit("pipeline_phase", {"phase": "sensitive", "status": "running"})
        finder = WSHawkSensitiveFinder(sio_instance=sio)
        page_urls = [p["url"] for p in pages if p.get("url")]

        all_findings = []
        for i, page_url in enumerate(page_urls):
            try:
                result = await finder.scan_url(page_url)
                findings = result.get("findings", [])
                all_findings.extend(findings)

                await sio.emit("pipeline_page_scanned", {
                    "url": page_url,
                    "findings_count": len(findings),
                    "progress": i + 1,
                    "total": len(page_urls),
                })
            except Exception:
                pass  # Skip pages that fail

        await sio.emit("pipeline_phase", {
            "phase": "sensitive", "status": "done",
            "total_findings": len(all_findings)
        })

        # Final result
        await sio.emit("pipeline_complete", {
            "pages_crawled": len(pages),
            "pages_scanned": len(page_urls),
            "total_findings": len(all_findings),
            "findings": all_findings,
        })

    asyncio.create_task(_pipeline())
    return {"status": "started", "msg": "Crawl → Sensitive pipeline started"}


# ─────────────────────────────────────────────────────────────────────
# Project Sessions — Save/Load scan state to disk
# ─────────────────────────────────────────────────────────────────────

SESSIONS_DIR = Path(os.path.expanduser("~/.wshawk/sessions"))


@app.post("/session/save")
async def session_save(data: Dict[str, Any]):
    """Save current scan session data to a JSON file on disk."""
    name = data.get("name", "").strip()
    if not name:
        name = f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    # Sanitize filename
    safe_name = "".join(c for c in name if c.isalnum() or c in "-_").strip()
    if not safe_name:
        safe_name = f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    filepath = SESSIONS_DIR / f"{safe_name}.json"

    session_data = {
        "name": safe_name,
        "created": datetime.now().isoformat(),
        "version": "3.0.1",
        "data": data.get("session", {}),
    }

    try:
        with open(filepath, 'w') as f:
            json.dump(session_data, f, indent=2, default=str)
        return {"status": "success", "path": str(filepath), "name": safe_name}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/session/load")
async def session_load(data: Dict[str, Any]):
    """Load a saved session from disk."""
    name = data.get("name", "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="Session name required")

    filepath = SESSIONS_DIR / f"{name}.json"
    if not filepath.exists():
        raise HTTPException(status_code=404, detail=f"Session '{name}' not found")

    try:
        with open(filepath, 'r') as f:
            session_data = json.load(f)
        return {"status": "success", "session": session_data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/session/list")
async def session_list():
    """List all saved sessions."""
    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    sessions = []
    for f in sorted(SESSIONS_DIR.glob("*.json"), key=os.path.getmtime, reverse=True):
        try:
            with open(f, 'r') as fh:
                meta = json.load(fh)
            sessions.append({
                "name": meta.get("name", f.stem),
                "created": meta.get("created", ""),
                "size": f.stat().st_size,
            })
        except Exception:
            sessions.append({"name": f.stem, "created": "?", "size": f.stat().st_size})

    return {"status": "success", "sessions": sessions, "count": len(sessions)}


@app.delete("/session/delete")
async def session_delete(data: Dict[str, Any]):
    """Delete a saved session."""
    name = data.get("name", "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="Session name required")

    filepath = SESSIONS_DIR / f"{name}.json"
    if filepath.exists():
        filepath.unlink()
        return {"status": "success"}
    raise HTTPException(status_code=404, detail="Session not found")

# ═══════════════════════════════════════════════════════════════════
# Multiplayer: Team Collaboration Routes
# Delegates all logic to wshawk.team_engine.TeamEngine
# ═══════════════════════════════════════════════════════════════════

from wshawk.team_engine import TeamEngine

team = TeamEngine()


@app.post("/team/create")
async def team_create(data: Dict[str, Any]):
    """Create a new team collaboration room."""
    name = data.get("name", "Operator").strip() or "Operator"
    target = data.get("target", "")
    room = team.create_room(name, target)
    return {"status": "success", "room_code": room.code}


@app.post("/team/join")
async def team_join(data: Dict[str, Any]):
    """Validate a room code exists (REST pre-check before Socket.IO join)."""
    code = data.get("room_code", "").strip().upper()
    room = team.get_room(code)
    if not room:
        raise HTTPException(status_code=404, detail="Room not found. Check the room code.")
    return {
        "status": "success",
        "room_code": room.code,
        "operator_count": room.operator_count,
        "target": room.target,
        "created_by": room.created_by,
    }


@app.get("/team/info/{room_code}")
async def team_info(room_code: str):
    """Get current team room state."""
    room = team.get_room(room_code)
    if not room:
        raise HTTPException(status_code=404, detail="Room not found")
    return {"status": "success", **room.info()}


@app.post("/team/leave")
async def team_leave_rest(data: Dict[str, Any]):
    """Leave a team room (REST fallback when SID is unknown)."""
    code = data.get("room_code", "").strip().upper()
    name = data.get("name", "Operator")
    team.leave_room_by_name(code, name)
    return {"status": "success"}


@app.get("/team/stats")
async def team_stats():
    """Diagnostics: active rooms and operator count."""
    return {"status": "success", **team.stats()}


# ── Socket.IO Team Event Wiring ─────────────────────────────────

@sio.on("team_join")
async def sio_team_join(sid, data):
    code = data.get("room_code", "").strip().upper()
    name = data.get("name", "Operator")
    room, op = team.join_room(code, sid, name)
    if not room:
        await sio.emit("team_error", {"error": "Room not found"}, room=sid)
        return

    await sio.enter_room(sid, room.sio_room)
    await sio.emit("team_roster", {"operators": room.roster(), "room_code": room.code}, room=room.sio_room)

    activity = {"type": "join", "operator": op.name, "color": op.color, "time": op.joined_at}
    await sio.emit("team_activity", activity, room=room.sio_room)

    await sio.emit("team_state", {
        "shared_notes": room.shared_notes,
        "shared_endpoints": room.shared_endpoints,
        "target": room.target,
    }, room=sid)

    print(f"[Team] {name} joined room {room.code} ({room.operator_count} operators)")


@sio.on("team_leave")
async def sio_team_leave(sid, data=None):
    room, op = team.leave_room(sid)
    if not room or not op:
        return

    await sio.leave_room(sid, room.sio_room)
    await sio.emit("team_roster", {"operators": room.roster(), "room_code": room.code}, room=room.sio_room)

    activity = {"type": "leave", "operator": op.name, "color": op.color, "time": datetime.now().isoformat()}
    await sio.emit("team_activity", activity, room=room.sio_room)
    print(f"[Team] {op.name} left room {room.code}")


@sio.on("team_notes_update")
async def sio_team_notes_update(sid, data):
    result = team.update_notes(sid, data.get("content", ""))
    if not result:
        return
    room, op = result
    await sio.emit("team_notes_sync", {
        "content": data.get("content", ""),
        "cursor_pos": data.get("cursor_pos", 0),
        "operator": op.name,
        "color": op.color,
    }, room=room.sio_room, skip_sid=sid)


@sio.on("team_cursor_move")
async def sio_team_cursor_move(sid, data):
    result = team.update_cursor(sid, data.get("position"), data.get("tab", "notes"))
    if not result:
        return
    room, op = result
    await sio.emit("team_cursor_sync", {
        "sid": sid,
        "operator": op.name,
        "color": op.color,
        "position": data.get("position"),
        "tab": data.get("tab", "notes"),
    }, room=room.sio_room, skip_sid=sid)


@sio.on("team_endpoint_add")
async def sio_team_endpoint_add(sid, data):
    result = team.add_endpoint(sid, data.get("endpoint", {}))
    if not result:
        return
    room, op = result
    await sio.emit("team_endpoint_sync", {
        "endpoint": data.get("endpoint", {}),
        "operator": op.name,
        "color": op.color,
    }, room=room.sio_room, skip_sid=sid)


@sio.on("team_finding")
async def sio_team_finding(sid, data):
    result = team.log_finding(sid, data.get("finding", {}))
    if not result:
        return
    room, entry = result
    await sio.emit("team_activity", entry.to_dict(), room=room.sio_room)


@sio.on("team_scan_event")
async def sio_team_scan_event(sid, data):
    result = team.log_scan_event(
        sid,
        data.get("scan_type", "unknown"),
        data.get("target", ""),
        data.get("status", "started"),
        data.get("results_count", 0),
    )
    if not result:
        return
    room, entry = result
    await sio.emit("team_activity", entry.to_dict(), room=room.sio_room)


# ─────────────────────────────────────────────────────────────────────
# Server Entry Point
# ─────────────────────────────────────────────────────────────────────

def main():
    """Start the WSHawk GUI Bridge server."""
    port = int(os.environ.get("WSHAWK_BRIDGE_PORT", 8080))
    print(f"[*] Starting WSHawk GUI Bridge on port {port}...")
    uvicorn.run(socket_app, host="127.0.0.1", port=port, log_level="info")


if __name__ == "__main__":
    main()
