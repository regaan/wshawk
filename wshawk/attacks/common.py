import asyncio
import hashlib
import inspect
import json
from typing import Any, Dict, List, Optional, Tuple

import websockets


WS_HEADER_ARG = (
    "additional_headers"
    if "additional_headers" in inspect.signature(websockets.connect).parameters
    else "extra_headers"
)


def serialize_ws_payload(payload: Any) -> str:
    """Normalize replay payloads into WebSocket text frames."""
    if isinstance(payload, str):
        return payload
    if payload is None:
        return ""
    if isinstance(payload, bytes):
        return payload.decode("utf-8", errors="replace")
    try:
        return json.dumps(payload)
    except (TypeError, ValueError):
        return str(payload)


def build_cookie_header(cookies: Optional[List[Dict[str, Any]]]) -> str:
    """Compose a Cookie header from browser-style cookie objects."""
    parts = []
    for cookie in cookies or []:
        if not isinstance(cookie, dict):
            continue
        name = str(cookie.get("name", "")).strip()
        value = str(cookie.get("value", "")).strip()
        if name:
            parts.append(f"{name}={value}")
    return "; ".join(parts)


def _find_header_name(headers: Dict[str, str], candidate: str) -> Optional[str]:
    lowered = candidate.lower()
    for key in headers:
        if key.lower() == lowered:
            return key
    return None


def build_ws_headers(
    identity: Optional[Dict[str, Any]] = None,
    override_headers: Optional[Dict[str, Any]] = None,
) -> Dict[str, str]:
    """Build outbound WS headers from a stored identity plus per-request overrides."""
    headers: Dict[str, str] = {}

    if identity:
        for key, value in (identity.get("headers") or {}).items():
            if key is None or value is None:
                continue
            headers[str(key)] = str(value)

        cookie_header = build_cookie_header(identity.get("cookies"))
        if cookie_header and not _find_header_name(headers, "Cookie"):
            headers["Cookie"] = cookie_header

        tokens = identity.get("tokens") or {}
        bearer = (
            tokens.get("session_token")
            or tokens.get("access_token")
            or tokens.get("jwt")
            or tokens.get("token")
        )
        if bearer and not _find_header_name(headers, "Authorization"):
            headers["Authorization"] = f"Bearer {bearer}"

    for key, value in (override_headers or {}).items():
        if key is None or value is None:
            continue
        headers[str(key)] = str(value)

    return headers


def normalize_ws_message(message: Any) -> str:
    """Convert inbound WS messages into string form for storage and diffing."""
    if isinstance(message, str):
        return message
    if isinstance(message, bytes):
        return message.decode("utf-8", errors="replace")
    if message is None:
        return ""
    return str(message)


def parse_ws_json_message(message: Any) -> Optional[Any]:
    """Best-effort JSON parsing for text WebSocket frames."""
    normalized = normalize_ws_message(message).strip()
    if not normalized:
        return None
    try:
        return json.loads(normalized)
    except (TypeError, ValueError):
        return None


def is_ws_prelude_message(message: Any) -> bool:
    """Identify connect-time banners that should not be scored as action responses."""
    normalized = normalize_ws_message(message).strip()
    if not normalized:
        return True

    # Socket.IO open packet / server banner.
    if normalized.startswith("0{"):
        return True

    parsed = parse_ws_json_message(normalized)
    if not isinstance(parsed, dict):
        return False

    message_type = str(parsed.get("type", "")).strip().lower()
    if message_type in {"welcome", "hello", "connected", "ready", "session", "banner"}:
        return True

    # Heuristic: some labs/banner frames contain only identity/session metadata.
    handshake_keys = {
        "type",
        "client_id",
        "session_id",
        "sid",
        "username",
        "tenant",
        "role",
        "token_replay_supported",
        "message",
    }
    if "token_replay_supported" in parsed and set(parsed.keys()).issubset(handshake_keys):
        return True

    return False


def is_ws_error_message(message: Any) -> bool:
    """Detect application-layer WS error frames even when transport succeeded."""
    parsed = parse_ws_json_message(message)
    if not isinstance(parsed, dict):
        return False

    message_type = str(parsed.get("type", "")).strip().lower()
    if message_type == "error":
        return True

    status = str(parsed.get("status", "")).strip().lower()
    if status in {"error", "failed", "forbidden", "unauthorized", "denied", "rejected"}:
        return True

    status_code = parsed.get("status_code")
    try:
        if status_code is not None and int(status_code) >= 400:
            return True
    except (TypeError, ValueError):
        pass

    if parsed.get("error") not in (None, "", False):
        return True

    if parsed.get("ok") is False or parsed.get("accepted") is False or parsed.get("success") is False:
        return True

    return False


def ws_result_effective_success(result: Dict[str, Any]) -> bool:
    """Treat WS application error frames as unsuccessful even if a frame was received."""
    status = result.get("status")
    if status == "sent":
        return True
    if status != "received":
        return False
    return not is_ws_error_message(result.get("response", ""))


async def drain_ws_prelude_frames(
    ws: Any,
    *,
    idle_timeout: float = 0.15,
    max_frames: int = 6,
) -> List[str]:
    """Drain unsolicited handshake banners before sending the real payload."""
    frames: List[str] = []
    for _ in range(max_frames):
        try:
            raw_message = await asyncio.wait_for(ws.recv(), timeout=idle_timeout)
        except asyncio.TimeoutError:
            break

        normalized = normalize_ws_message(raw_message)
        if not is_ws_prelude_message(normalized):
            # Keep non-prelude unsolicited frames for debugging, but stop draining.
            frames.append(normalized)
            break
        frames.append(normalized)
    return frames


async def drain_ws_activity_frames(
    ws: Any,
    *,
    idle_timeout: float = 0.15,
    max_frames: int = 6,
) -> List[str]:
    """Drain queued frames after setup messages so the next read belongs to the target action."""
    frames: List[str] = []
    for _ in range(max_frames):
        try:
            raw_message = await asyncio.wait_for(ws.recv(), timeout=idle_timeout)
        except asyncio.TimeoutError:
            break
        frames.append(normalize_ws_message(raw_message))
    return frames


async def recv_meaningful_ws_message(
    ws: Any,
    *,
    timeout: float,
    max_skip_frames: int = 6,
) -> Tuple[str, List[str]]:
    """Read frames until a non-banner response arrives or timeout expires."""
    skipped_frames: List[str] = []
    for _ in range(max_skip_frames):
        raw_response = await asyncio.wait_for(ws.recv(), timeout=timeout)
        response = normalize_ws_message(raw_response)
        if is_ws_prelude_message(response):
            skipped_frames.append(response)
            continue
        return response, skipped_frames
    raise asyncio.TimeoutError("Only handshake/banner frames were received before timeout")


def _behavior_hash(status: str, response: str, error: str) -> str:
    raw = f"{status}\n{response}\n{error}".encode("utf-8", errors="replace")
    return hashlib.sha256(raw).hexdigest()[:16]


def summarize_authz_diff(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Group replay results by behavior so authz drift stands out quickly."""
    behavior_groups: Dict[str, Dict[str, Any]] = {}
    status_breakdown: Dict[str, int] = {}

    for result in results:
        status = result.get("status", "unknown")
        status_breakdown[status] = status_breakdown.get(status, 0) + 1

        behavior_hash = _behavior_hash(
            status,
            result.get("response", ""),
            result.get("error", ""),
        )

        group = behavior_groups.setdefault(
            behavior_hash,
            {
                "behavior_hash": behavior_hash,
                "status": status,
                "response_length": result.get("response_length", 0),
                "response_preview": result.get("response_preview", ""),
                "error": result.get("error", ""),
                "identities": [],
            },
        )
        group["identities"].append(
            {
                "identity_id": result.get("identity_id"),
                "identity_alias": result.get("identity_alias"),
            }
        )

    ordered_groups = sorted(
        behavior_groups.values(),
        key=lambda item: (-len(item["identities"]), item["status"], item["behavior_hash"]),
    )

    baseline_hash = ordered_groups[0]["behavior_hash"] if ordered_groups else None
    interesting_identities = []
    for result in results:
        current_hash = _behavior_hash(
            result.get("status", "unknown"),
            result.get("response", ""),
            result.get("error", ""),
        )
        if baseline_hash and current_hash != baseline_hash:
            interesting_identities.append(
                {
                    "identity_id": result.get("identity_id"),
                    "identity_alias": result.get("identity_alias"),
                    "status": result.get("status"),
                    "response_preview": result.get("response_preview", ""),
                }
            )

    behavior_changed = len(ordered_groups) > 1
    recommended_severity = "medium" if behavior_changed else "info"
    if behavior_changed and any(item["status"] == "received" for item in ordered_groups):
        if any(item["status"] in {"error", "timeout"} for item in ordered_groups):
            recommended_severity = "high"

    return {
        "identity_count": len(results),
        "behavior_changed": behavior_changed,
        "behavior_group_count": len(ordered_groups),
        "status_breakdown": status_breakdown,
        "recommended_severity": recommended_severity,
        "behavior_groups": ordered_groups,
        "interesting_identities": interesting_identities,
    }
