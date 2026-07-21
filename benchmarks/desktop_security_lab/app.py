from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote_plus

from fastapi import HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

from benchmarks.industry_lab.app import (
    _http_identity,
    _ws_identity,
    app,
    reset_state as reset_industry_state,
)


HERE = Path(__file__).resolve().parent
GROUND_TRUTH_PATH = HERE / "ground_truth.json"
SUPPORTED_WS_ATTACKS = {"sqli", "xss", "command", "lfi", "xxe", "nosql", "ssrf"}


def ground_truth() -> dict[str, Any]:
    return json.loads(GROUND_TRUTH_PATH.read_text(encoding="utf-8"))


def reset_state() -> None:
    reset_industry_state()


def _require_profile(profile: str) -> str:
    if profile not in {"vulnerable", "hardened"}:
        raise HTTPException(status_code=404, detail="Unknown profile")
    return profile


def _hardened_headers() -> dict[str, str]:
    return {
        "Content-Security-Policy": "default-src 'self'; object-src 'none'; frame-ancestors 'none'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
    }


async def _request_value(request: Request, name: str) -> str:
    query_value = request.query_params.get(name)
    if query_value is not None:
        return query_value

    raw = await request.body()
    if not raw:
        return ""
    text = raw.decode("utf-8", errors="replace")
    content_type = request.headers.get("Content-Type", "").lower()
    if "json" in content_type:
        try:
            payload = json.loads(text)
            if isinstance(payload, dict):
                value = payload.get(name, payload.get("data", payload.get("input", "")))
                return json.dumps(value) if isinstance(value, (dict, list)) else str(value)
        except json.JSONDecodeError:
            return text
    values = parse_qs(text, keep_blank_values=True).get(name)
    return values[0] if values else text


def _looks_like_sqli(value: str) -> bool:
    lowered = _normalized_probe(value)
    return any(token in lowered for token in ("'", " union ", " select ", " or 1=1", "sleep(", "waitfor "))


def _looks_like_xss(value: str) -> bool:
    lowered = _normalized_probe(value)
    return any(token in lowered for token in ("<script", "<svg", "<img", "javascript:", "onerror=", "onload="))


def _looks_like_command(value: str) -> bool:
    lowered = _normalized_probe(value)
    return any(
        token in lowered
        for token in (";", "&&", "|", "`", "$(", "whoami", "cat /etc/passwd", "ipconfig")
    )


def _looks_like_traversal(value: str) -> bool:
    lowered = _normalized_probe(value)
    return any(token in lowered for token in ("../", "..\\", "/etc/passwd", "win.ini", "/proc/self"))


def _looks_like_xxe(value: str) -> bool:
    lowered = _normalized_probe(value)
    return "<!doctype" in lowered or "<!entity" in lowered or "file://" in lowered


def _looks_like_nosql(value: str) -> bool:
    lowered = _normalized_probe(value)
    return "$" in lowered or "mongodb" in lowered


def _looks_like_ssrf(value: str) -> bool:
    lowered = _normalized_probe(value)
    return any(
        token in lowered
        for token in ("127.0.0.1", "localhost", "169.254.169.254", "metadata.google.internal", "file://")
    )


def _normalized_probe(value: str) -> str:
    normalized = value
    for _ in range(3):
        decoded = unquote_plus(normalized)
        if decoded == normalized:
            break
        normalized = decoded
    return normalized.lower().replace("\x00", "")


def _classify_probe(value: str, requested_attack: str = "") -> str | None:
    checks = (
        ("xss", _looks_like_xss),
        ("xxe", _looks_like_xxe),
        ("lfi", _looks_like_traversal),
        ("nosql", _looks_like_nosql),
        ("ssrf", _looks_like_ssrf),
        ("command", _looks_like_command),
        ("sqli", _looks_like_sqli),
    )
    for attack, matcher in checks:
        if matcher(value):
            return attack
    return None


@app.get("/lab/health")
async def lab_health():
    truth = ground_truth()
    return {
        "ok": True,
        "lab": truth["name"],
        "schema_version": truth["schema_version"],
        "case_count": len(truth["cases"]),
        "profiles": ["vulnerable", "hardened"],
        "scope": "localhost-only",
    }


@app.get("/lab/ground-truth")
async def lab_ground_truth():
    return ground_truth()


@app.post("/lab/reset")
async def lab_reset():
    reset_state()
    return {"ok": True}


@app.get("/{profile}/portal")
async def portal(profile: str):
    _require_profile(profile)
    document = f"""
    <!doctype html>
    <html>
      <head><title>WSHawk {profile.title()} Security Lab</title></head>
      <body>
        <h1>{profile.title()} SaaS portal</h1>
        <a href="/{profile}/headers">Security headers</a>
        <a href="/{profile}/cors">CORS API</a>
        <a href="/{profile}/api/config">Application configuration</a>
        <a href="/{profile}/redirect?next=/">Continue</a>
        <a href="/{profile}/.env">Environment file</a>
        <form method="get" action="/{profile}/api/search">
          <input name="q" value="benchmark">
          <button type="submit">Search</button>
        </form>
        <form method="post" action="/{profile}/api/execute">
          <input name="cmd" value="status">
          <button type="submit">Run diagnostic</button>
        </form>
      </body>
    </html>
    """
    headers = _hardened_headers() if profile == "hardened" else {"X-Powered-By": "Express"}
    return HTMLResponse(document, headers=headers)


@app.api_route("/{profile}/api/search", methods=["GET", "POST"])
async def injection_search(profile: str, request: Request):
    _require_profile(profile)
    value = await _request_value(request, "q")
    if profile == "vulnerable" and _looks_like_xss(value):
        return HTMLResponse(f"<p>Search result: {value}</p>")
    if profile == "vulnerable" and _looks_like_sqli(value):
        return PlainTextResponse("mysql SQL syntax error near supplied query; mysql_fetch_array()")
    return HTMLResponse(f"<p>Search result: {html.escape(value)}</p>", headers=_hardened_headers())


@app.api_route("/{profile}/api/execute", methods=["GET", "POST"])
async def command_injection(profile: str, request: Request):
    _require_profile(profile)
    value = await _request_value(request, "cmd")
    if profile == "vulnerable" and _looks_like_command(value):
        return PlainTextResponse("uid=1000(wshawk) gid=1000(wshawk) groups=1000(wshawk)")
    if profile == "hardened" and _looks_like_command(value):
        raise HTTPException(status_code=400, detail="Command input rejected")
    return {"ok": True, "status": "diagnostic complete"}


@app.api_route("/{profile}/api/file", methods=["GET", "POST"])
async def path_traversal(profile: str, request: Request):
    _require_profile(profile)
    value = await _request_value(request, "path")
    if profile == "vulnerable" and _looks_like_traversal(value):
        return PlainTextResponse("root:x:0:0:root:/root:/bin/bash\nmail:x:8:8:mail:/var/mail:/usr/sbin/nologin")
    if profile == "hardened" and _looks_like_traversal(value):
        raise HTTPException(status_code=400, detail="Path rejected")
    return PlainTextResponse("public benchmark document")


@app.api_route("/{profile}/api/nosql", methods=["GET", "POST"])
async def nosql_injection(profile: str, request: Request):
    _require_profile(profile)
    value = await _request_value(request, "filter")
    if profile == "vulnerable" and _looks_like_nosql(value):
        return JSONResponse(
            {"ok": False, "error": "MongoDB query error: BSON operator accepted", "records": ["tenant-alpha", "tenant-beta"]}
        )
    if profile == "hardened" and _looks_like_nosql(value):
        raise HTTPException(status_code=400, detail="Query operator rejected")
    return {"ok": True, "records": []}


@app.post("/{profile}/api/xml")
async def xxe(profile: str, request: Request):
    _require_profile(profile)
    value = (await request.body()).decode("utf-8", errors="replace")
    if profile == "vulnerable" and _looks_like_xxe(value):
        return PlainTextResponse("XML Parse Result\nroot:x:0:0:root:/root:/bin/bash\nSYSTEM file:///etc/passwd")
    if profile == "hardened" and _looks_like_xxe(value):
        raise HTTPException(status_code=400, detail="DTD and external entities are disabled")
    return {"ok": True, "parsed": True}


@app.api_route("/{profile}/merge", methods=["GET", "POST"])
async def prototype_pollution(profile: str, request: Request):
    _require_profile(profile)
    raw = str(request.query_params) + (await request.body()).decode("utf-8", errors="replace")
    polluted = "__proto__" in raw or "constructor" in raw
    if profile == "vulnerable" and polluted:
        return {"polluted": "wshawk_pp_test", "isAdmin": True}
    if profile == "hardened" and polluted:
        raise HTTPException(status_code=400, detail="Unsafe object keys rejected")
    return {"ok": True}


@app.get("/{profile}/.env")
async def exposed_environment(profile: str):
    _require_profile(profile)
    if profile == "vulnerable":
        return PlainTextResponse(
            "DATABASE_URL=postgres://desktop-lab:synthetic@10.20.30.40/security_lab\n"
            "AWS_ACCESS_KEY=AKIAABCDEFGHIJKLMNOP\n"
            "OWNER=desktop-security-lab@example.test\n"
        )
    raise HTTPException(status_code=404, detail="Not found")


@app.websocket("/{profile}/probe-ws")
async def websocket_probe(websocket: WebSocket, profile: str):
    identity = _ws_identity(websocket)
    if profile not in {"vulnerable", "hardened"} or not identity:
        await websocket.close(code=4401)
        return
    if profile == "hardened" and websocket.headers.get("Origin") != "https://trusted.example":
        await websocket.close(code=4403)
        return

    await websocket.accept()
    await websocket.send_json(
        {
            "type": "welcome",
            "profile": profile,
            "action": "probe",
            "attack": "sqli",
            "payload": "benchmark",
            **identity,
        }
    )
    try:
        while True:
            try:
                message = json.loads(await websocket.receive_text())
            except json.JSONDecodeError:
                await websocket.send_json({"type": "error", "error": "invalid_json", "status_code": 400})
                continue

            if not isinstance(message, dict):
                await websocket.send_json({"type": "error", "error": "unknown_action", "status_code": 400})
                continue

            action = str(message.get("action", "")).lower()
            requested_attack = str(message.get("attack", "")).lower()
            if action == "read_file":
                requested_attack = "lfi"
                payload = str(message.get("filename", ""))
            elif action == "parse_xml":
                requested_attack = "xxe"
                payload = str(message.get("xml", ""))
            elif action == "find_user":
                requested_attack = "nosql"
                payload = json.dumps(message.get("query", {}), sort_keys=True)
            elif action == "fetch_url":
                requested_attack = "ssrf"
                payload = str(message.get("url", ""))
            elif action == "probe":
                payload = str(message.get("payload", ""))
            else:
                payload = json.dumps(message, sort_keys=True)

            attack = _classify_probe(payload, requested_attack)
            triggered = attack is not None

            if profile == "hardened" and triggered:
                await websocket.send_json(
                    {"type": "error", "error": "input_rejected", "status_code": 400, "attack": attack}
                )
                continue
            if not triggered:
                if action not in {"probe", "read_file", "parse_xml", "find_user", "fetch_url"}:
                    await websocket.send_json({"type": "error", "error": "unknown_action", "status_code": 400})
                    continue
                safe_attack = requested_attack if requested_attack in SUPPORTED_WS_ATTACKS else "unknown"
                await websocket.send_json({"type": "probe_result", "ok": True, "attack": safe_attack})
                continue

            vulnerable_evidence = {
                "sqli": "SQL syntax error: mysql query failed",
                "xss": payload,
                "command": "uid=1000(wshawk) gid=1000(wshawk) groups=1000(wshawk)",
                "lfi": "root:x:0:0:root:/root:/bin/bash",
                "xxe": "XML Parse Error: SYSTEM file:///etc/passwd root:x:0:0:",
                "nosql": "MongoDB BSON query error caused by $ne operator",
                "ssrf": "ami-id instance-id iam/security-credentials/desktop-lab-role",
            }
            await websocket.send_json(
                {"type": "probe_result", "ok": True, "attack": attack, "evidence": vulnerable_evidence[attack]}
            )
    except WebSocketDisconnect:
        return
