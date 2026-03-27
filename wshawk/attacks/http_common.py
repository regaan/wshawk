import hashlib
import json
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlparse


AUTH_HEADER_NAMES = {"authorization", "x-api-key", "x-auth-token"}
TOKEN_KEYS = ("authorization", "bearer", "access_token", "id_token", "jwt", "session_token", "token")
CSRF_HINTS = ("csrf", "xsrf", "authenticity")
HTTP_METHOD_PREFIX_RE = re.compile(r"^\s*(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(https?://\S+)\s*$", re.IGNORECASE)
DYNAMIC_VALUE_PATTERNS = [
    re.compile(r"\b[0-9a-f]{32,}\b", re.IGNORECASE),
    re.compile(r"\b[0-9a-f]{8}-[0-9a-f-]{27,}\b", re.IGNORECASE),
    re.compile(r"\b\d{10,}\b"),
    re.compile(r'"(?:created|updated|timestamp|expires|iat|exp)"\s*:\s*"?[^",}]+'),
]


def normalize_http_headers(raw: Optional[Any]) -> Dict[str, str]:
    normalized: Dict[str, str] = {}
    if not raw:
        return normalized
    if isinstance(raw, dict):
        for key, value in raw.items():
            if key is None or value is None:
                continue
            normalized[str(key)] = str(value)
        return normalized
    if isinstance(raw, str):
        for line in raw.splitlines():
            line = line.strip()
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            normalized[key.strip()] = value.strip()
    return normalized


def normalize_http_cookies(raw: Optional[Any]) -> Dict[str, str]:
    normalized: Dict[str, str] = {}
    if not raw:
        return normalized
    if isinstance(raw, dict):
        normalized.update({str(key): str(value) for key, value in raw.items() if value is not None})
        return normalized
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict) and item.get("name"):
                normalized[str(item["name"])] = str(item.get("value", ""))
        return normalized
    if isinstance(raw, str):
        for part in raw.split(";"):
            if "=" not in part:
                continue
            key, value = part.split("=", 1)
            normalized[key.strip()] = value.strip()
    return normalized


def normalize_http_body(raw: Optional[Any]) -> str:
    if raw is None:
        return ""
    if isinstance(raw, (dict, list)):
        try:
            return json.dumps(raw)
        except (TypeError, ValueError):
            return str(raw)
    return str(raw)


def normalize_http_url(raw: Optional[Any]) -> str:
    value = str(raw or "").strip()
    if not value:
        return ""
    match = HTTP_METHOD_PREFIX_RE.match(value)
    if match:
        return match.group(2).strip()
    return value


def _find_header_key(headers: Dict[str, str], name: str) -> Optional[str]:
    lowered = name.lower()
    for key in headers:
        if key.lower() == lowered:
            return key
    return None


def compose_cookie_header(cookies: Dict[str, str]) -> str:
    return "; ".join(f"{key}={value}" for key, value in cookies.items() if key)


def merge_http_identity(
    *,
    identity: Optional[Dict[str, Any]],
    headers: Optional[Any] = None,
    cookies: Optional[Any] = None,
) -> Tuple[Dict[str, str], Dict[str, str]]:
    effective_headers = normalize_http_headers(headers)
    effective_cookies = normalize_http_cookies(cookies)

    if identity:
        identity_headers = normalize_http_headers(identity.get("headers"))
        for key, value in identity_headers.items():
            effective_headers[key] = value

        identity_cookies = normalize_http_cookies(identity.get("cookies"))
        merged_cookies = dict(identity_cookies)
        merged_cookies.update(effective_cookies)
        effective_cookies = merged_cookies

        tokens = identity.get("tokens") or {}
        if not any(_find_header_key(effective_headers, candidate) for candidate in AUTH_HEADER_NAMES):
            for key in TOKEN_KEYS:
                value = tokens.get(key)
                if not value:
                    continue
                if key == "authorization":
                    effective_headers["Authorization"] = str(value)
                else:
                    effective_headers["Authorization"] = f"Bearer {value}"
                break

        for token_key, token_value in tokens.items():
            key_lower = str(token_key).lower()
            if any(hint in key_lower for hint in CSRF_HINTS):
                header_name = "X-CSRF-Token" if not _find_header_key(effective_headers, "X-CSRF-Token") else None
                if header_name:
                    effective_headers[header_name] = str(token_value)
                    break

    if effective_cookies:
        effective_headers["Cookie"] = compose_cookie_header(effective_cookies)

    return effective_headers, effective_cookies


def inject_template_vars(value: Any, variables: Optional[Dict[str, Any]] = None) -> Any:
    variables = variables or {}
    if isinstance(value, str):
        def replace(match):
            name = match.group(1)
            return str(variables.get(name, match.group(0)))

        return re.sub(r"\{\{(\w+)\}\}", replace, value)
    if isinstance(value, dict):
        return {key: inject_template_vars(item, variables) for key, item in value.items()}
    if isinstance(value, list):
        return [inject_template_vars(item, variables) for item in value]
    return value


def infer_http_template_fields(
    *,
    url: str,
    headers: Dict[str, str],
    body: str,
) -> List[Dict[str, Any]]:
    fields: List[Dict[str, Any]] = []
    seen = set()

    try:
        parsed = urlparse(url)
        for key, value in parse_qsl(parsed.query, keep_blank_values=True):
            field_key = ("query", key)
            if field_key in seen:
                continue
            fields.append(
                {
                    "location": "query",
                    "name": key,
                    "current_value": value,
                    "suggested_variable": re.sub(r"[^a-zA-Z0-9_]+", "_", key).strip("_") or "query_value",
                }
            )
            seen.add(field_key)
    except Exception:
        pass

    for key, value in headers.items():
        lowered = key.lower()
        if lowered in {"cookie", "content-length"}:
            continue
        if lowered in AUTH_HEADER_NAMES or any(hint in lowered for hint in CSRF_HINTS) or lowered.startswith("x-"):
            field_key = ("header", lowered)
            if field_key in seen:
                continue
            fields.append(
                {
                    "location": "header",
                    "name": key,
                    "current_value": value,
                    "suggested_variable": re.sub(r"[^a-zA-Z0-9_]+", "_", lowered).strip("_") or "header_value",
                }
            )
            seen.add(field_key)

    try:
        parsed_body = json.loads(body) if body.strip().startswith(("{", "[")) else None
    except (TypeError, ValueError):
        parsed_body = None

    def visit_json(node: Any, path: str = "") -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                next_path = f"{path}.{key}" if path else key
                visit_json(value, next_path)
        elif isinstance(node, list):
            for index, value in enumerate(node):
                visit_json(value, f"{path}[{index}]")
        else:
            if node is None:
                return
            field_key = ("body", path)
            if field_key in seen:
                return
            fields.append(
                {
                    "location": "body",
                    "name": path,
                    "current_value": str(node),
                    "suggested_variable": re.sub(r"[^a-zA-Z0-9_]+", "_", path).strip("_") or "body_value",
                }
            )
            seen.add(field_key)

    if parsed_body is not None:
        visit_json(parsed_body)

    return fields[:40]


def build_http_template(
    *,
    method: str,
    url: str,
    headers: Optional[Any] = None,
    body: Optional[Any] = None,
    source_flow_id: Optional[str] = None,
    correlation_id: str = "",
    name: str = "",
) -> Dict[str, Any]:
    normalized_headers = normalize_http_headers(headers)
    normalized_body = normalize_http_body(body)
    normalized_url = normalize_http_url(url)
    template_name = name.strip() if str(name or "").strip() else f"{method.upper()} {normalized_url}"
    return {
        "name": template_name[:160],
        "source_flow_id": source_flow_id,
        "correlation_id": correlation_id,
        "method": str(method or "GET").upper(),
        "url": normalized_url,
        "headers": normalized_headers,
        "body": normalized_body,
        "editable_fields": infer_http_template_fields(url=normalized_url, headers=normalized_headers, body=normalized_body),
    }


def render_http_template(
    template: Dict[str, Any],
    *,
    variables: Optional[Dict[str, Any]] = None,
    method: Optional[str] = None,
    url: Optional[str] = None,
    headers: Optional[Any] = None,
    body: Optional[Any] = None,
) -> Dict[str, Any]:
    rendered = {
        "method": str(method or template.get("method") or "GET").upper(),
        "url": normalize_http_url(inject_template_vars(url or template.get("url") or "", variables)),
        "headers": inject_template_vars(dict(template.get("headers") or {}), variables),
        "body": inject_template_vars(body if body is not None else template.get("body") or "", variables),
        "source_flow_id": template.get("source_flow_id"),
        "correlation_id": template.get("correlation_id", ""),
        "name": template.get("name", ""),
    }
    override_headers = normalize_http_headers(headers)
    rendered["headers"].update(override_headers)
    rendered["body"] = normalize_http_body(rendered["body"])
    return rendered


def _normalize_http_behavior_body(body: str) -> str:
    normalized = str(body or "")
    for pattern in DYNAMIC_VALUE_PATTERNS:
        normalized = pattern.sub("<dynamic>", normalized)
    return normalized[:4000]


def summarize_http_authz_diff(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    behavior_groups: Dict[str, Dict[str, Any]] = {}
    status_breakdown: Dict[str, int] = {}
    http_status_breakdown: Dict[str, int] = {}

    for result in results:
        status = str(result.get("status") or "unknown")
        http_status = str(result.get("http_status") or status)
        status_breakdown[status] = status_breakdown.get(status, 0) + 1
        http_status_breakdown[http_status] = http_status_breakdown.get(http_status, 0) + 1

        signature_source = "\n".join(
            [
                status,
                http_status,
                _normalize_http_behavior_body(result.get("response", "")),
                str(result.get("error", "")),
            ]
        )
        behavior_hash = hashlib.sha256(signature_source.encode("utf-8", errors="replace")).hexdigest()[:16]
        group = behavior_groups.setdefault(
            behavior_hash,
            {
                "behavior_hash": behavior_hash,
                "status": status,
                "http_status": http_status,
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
                "flow_id": result.get("flow_id"),
            }
        )

    ordered_groups = sorted(
        behavior_groups.values(),
        key=lambda item: (-len(item["identities"]), item["http_status"], item["behavior_hash"]),
    )
    baseline_hash = ordered_groups[0]["behavior_hash"] if ordered_groups else None

    interesting_identities = []
    for result in results:
        signature_source = "\n".join(
            [
                str(result.get("status") or "unknown"),
                str(result.get("http_status") or result.get("status") or "unknown"),
                _normalize_http_behavior_body(result.get("response", "")),
                str(result.get("error", "")),
            ]
        )
        behavior_hash = hashlib.sha256(signature_source.encode("utf-8", errors="replace")).hexdigest()[:16]
        if baseline_hash and behavior_hash != baseline_hash:
            interesting_identities.append(
                {
                    "identity_id": result.get("identity_id"),
                    "identity_alias": result.get("identity_alias"),
                    "http_status": result.get("http_status"),
                    "response_preview": result.get("response_preview", ""),
                }
            )

    behavior_changed = len(ordered_groups) > 1
    recommended_severity = "info"
    success_statuses = {
        str(result.get("http_status"))
        for result in results
        if str(result.get("http_status", "")).isdigit() and int(str(result.get("http_status"))) < 400
    }
    if behavior_changed:
        recommended_severity = "medium"
        if len(success_statuses) > 1 or any(str(group.get("http_status", "")).startswith("2") for group in ordered_groups):
            recommended_severity = "high"

    return {
        "identity_count": len(results),
        "behavior_changed": behavior_changed,
        "behavior_group_count": len(ordered_groups),
        "status_breakdown": status_breakdown,
        "http_status_breakdown": http_status_breakdown,
        "recommended_severity": recommended_severity,
        "behavior_groups": ordered_groups,
        "interesting_identities": interesting_identities,
    }
