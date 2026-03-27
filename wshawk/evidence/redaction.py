import json
import re
from typing import Any, Dict, Iterable


SECRET_KEY_HINTS = (
    "authorization",
    "cookie",
    "token",
    "session",
    "jwt",
    "secret",
    "api_key",
    "apikey",
    "password",
    "csrf",
    "xsrf",
)

BEARER_RE = re.compile(r"\b(Bearer\s+)([A-Za-z0-9._\-+/=]+)", re.IGNORECASE)
COOKIE_RE = re.compile(r"([A-Za-z0-9_.\-]+)=([^;]+)")
LONG_TOKEN_RE = re.compile(r"\b[A-Za-z0-9_\-]{20,}\b")
SECRET_PARAM_RE = re.compile(
    r"(?i)\b(token|csrf|xsrf|session|jwt|secret|api[_-]?key|apikey|password)=([^&\s\"']+)"
)
FREE_TEXT_SECRET_RE = re.compile(
    r"(?i)\b(approval\s+token|api[_ -]?key|csrf|xsrf)\b(\s*[:=]?\s*)([A-Za-z0-9._\-]{6,})"
)
JSON_SECRET_RE = re.compile(
    r'(?i)("?(?:approval_token|api[_-]?key|csrf|xsrf|bearer|token)"?\s*:\s*")([^"]+)(")'
)


def mask_secret_value(value: Any, keep: int = 4) -> Any:
    if value is None:
        return value
    text = str(value)
    if not text:
        return text
    if len(text) <= keep * 2:
        return "*" * len(text)
    return f"{text[:keep]}***{text[-keep:]}"


def sanitize_header_value(name: str, value: Any) -> Any:
    lowered = str(name or "").lower()
    if any(hint in lowered for hint in SECRET_KEY_HINTS):
        if lowered == "cookie":
            return COOKIE_RE.sub(lambda match: f"{match.group(1)}={mask_secret_value(match.group(2), keep=2)}", str(value))
        if lowered == "authorization":
            return BEARER_RE.sub(lambda match: f"{match.group(1)}{mask_secret_value(match.group(2), keep=4)}", str(value))
        return mask_secret_value(value)
    return sanitize_text(value)


def sanitize_text(value: Any) -> Any:
    if value is None:
        return value
    text = str(value)
    stripped = text.strip()
    if stripped.startswith(("{", "[")):
        try:
            parsed = json.loads(stripped)
        except (TypeError, ValueError, json.JSONDecodeError):
            parsed = None
        if isinstance(parsed, (dict, list)):
            return json.dumps(sanitize_payload(parsed))
    text = BEARER_RE.sub(lambda match: f"{match.group(1)}{mask_secret_value(match.group(2), keep=4)}", text)
    text = COOKIE_RE.sub(lambda match: f"{match.group(1)}={mask_secret_value(match.group(2), keep=2)}", text)
    text = SECRET_PARAM_RE.sub(
        lambda match: f"{match.group(1)}={mask_secret_value(match.group(2), keep=4)}",
        text,
    )
    text = JSON_SECRET_RE.sub(
        lambda match: f"{match.group(1)}{mask_secret_value(match.group(2), keep=4)}{match.group(3)}",
        text,
    )
    text = FREE_TEXT_SECRET_RE.sub(
        lambda match: f"{match.group(1)}{match.group(2)}{mask_secret_value(match.group(3), keep=4)}",
        text,
    )
    text = LONG_TOKEN_RE.sub(lambda match: mask_secret_value(match.group(0), keep=4), text)
    return text


def sanitize_mapping(mapping: Dict[str, Any]) -> Dict[str, Any]:
    return {str(key): sanitize_header_value(str(key), value) for key, value in (mapping or {}).items()}


def sanitize_payload(payload: Any) -> Any:
    if isinstance(payload, dict):
        sanitized: Dict[str, Any] = {}
        for key, value in payload.items():
            lowered = str(key).lower()
            if any(hint in lowered for hint in SECRET_KEY_HINTS):
                sanitized[key] = mask_secret_value(value)
            elif lowered.endswith("headers") and isinstance(value, dict):
                sanitized[key] = sanitize_mapping(value)
            else:
                sanitized[key] = sanitize_payload(value)
        return sanitized
    if isinstance(payload, list):
        return [sanitize_payload(item) for item in payload]
    if isinstance(payload, str):
        return sanitize_text(payload)
    return payload


def sanitize_jsonable(value: Any) -> Any:
    try:
        json.dumps(value)
    except (TypeError, ValueError):
        return sanitize_text(value)
    return sanitize_payload(value)


def summarize_fields(fields: Iterable[str], limit: int = 8) -> str:
    values = [str(item) for item in fields if item]
    return ", ".join(values[:limit]) if values else "none"
