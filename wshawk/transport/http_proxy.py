"""Structured HTTP proxy/transport engine."""

import json
from http.cookies import SimpleCookie
from typing import Any, Dict, Optional

import aiohttp

from wshawk.store import ProjectStore


class WSHawkHTTPProxy:
    """Native HTTP transport with optional project-backed journaling."""

    MAX_BODY_SIZE = 5 * 1024 * 1024

    def __init__(self, store: Optional[ProjectStore] = None):
        self.store = store

    @staticmethod
    def parse_headers(headers_str: str = "") -> Dict[str, str]:
        headers: Dict[str, str] = {}
        if headers_str:
            for line in headers_str.split("\n"):
                line = line.strip()
                if ":" in line:
                    key, value = line.split(":", 1)
                    headers[key.strip()] = value.strip()
        return headers

    @staticmethod
    def _header_value(headers: Optional[Dict[str, Any]], name: str) -> str:
        if not headers:
            return ""
        lowered = name.lower()
        for key, value in headers.items():
            if str(key).lower() == lowered:
                return str(value)
        return ""

    @classmethod
    def _is_json_request(cls, headers: Optional[Dict[str, Any]]) -> bool:
        content_type = cls._header_value(headers, "Content-Type").lower()
        return "application/json" in content_type or content_type.endswith("+json")

    @classmethod
    def _prepare_request_kwargs(cls, body: Any, headers: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        if body in (None, "", b""):
            return {}

        if isinstance(body, bytes):
            return {"data": body}

        if isinstance(body, (dict, list)):
            return {"json": body}

        if isinstance(body, str):
            stripped = body.strip()
            if stripped:
                decoded: Any = body
                for _ in range(2):
                    if not isinstance(decoded, str):
                        break
                    current = decoded.strip()
                    if not current:
                        break
                    try:
                        next_value = json.loads(current)
                    except ValueError:
                        break
                    if next_value == decoded:
                        break
                    decoded = next_value
                if isinstance(decoded, (dict, list)):
                    return {"json": decoded}

        if isinstance(body, str):
            return {"data": body.encode("utf-8")}

        return {"data": str(body).encode("utf-8")}

    @staticmethod
    def _body_for_storage(body: Any) -> str:
        if body is None:
            return ""
        if isinstance(body, str):
            return body
        if isinstance(body, bytes):
            return body.decode("utf-8", errors="ignore")
        if isinstance(body, (dict, list)):
            try:
                return json.dumps(body)
            except (TypeError, ValueError):
                return str(body)
        return str(body)

    async def send_request(
        self,
        method: str,
        url: str,
        headers_str: str = "",
        headers: Optional[Dict[str, Any]] = None,
        body: Any = "",
        cookies: Optional[Dict[str, Any]] = None,
        project_id: Optional[str] = None,
        correlation_id: str = "",
        attack_run_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        allow_redirects: bool = False,
        timeout_s: int = 30,
        verify_ssl: bool = True,
    ) -> Dict[str, Any]:
        if not url or not url.strip():
            raise ValueError("URL is required")

        method = method.strip().upper()
        valid_methods = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
        if method not in valid_methods:
            raise ValueError(f"Invalid HTTP method: {method}")

        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        merged_headers = self.parse_headers(headers_str)
        if headers:
            for key, value in headers.items():
                merged_headers[str(key)] = str(value)

        normalized_cookies = self._normalize_cookies(cookies, merged_headers)
        timeout = aiohttp.ClientTimeout(total=timeout_s)

        request_kwargs = self._prepare_request_kwargs(body, merged_headers)
        stored_request_body = self._body_for_storage(body)

        result: Dict[str, Any]
        async with aiohttp.ClientSession(headers=merged_headers, cookies=normalized_cookies) as session:
            try:
                async with session.request(
                    method,
                    url,
                    ssl=verify_ssl,
                    allow_redirects=allow_redirects,
                    timeout=timeout,
                    **request_kwargs,
                ) as resp:
                    raw_body = await resp.read()
                    if len(raw_body) > self.MAX_BODY_SIZE:
                        resp_text = raw_body[: self.MAX_BODY_SIZE].decode("utf-8", errors="ignore")
                        resp_text += f"\n\n[TRUNCATED — Response exceeded {self.MAX_BODY_SIZE // 1024}KB]"
                    else:
                        resp_text = raw_body.decode("utf-8", errors="ignore")

                    response_headers = dict(resp.headers.items())
                    response_cookies = {key: morsel.value for key, morsel in resp.cookies.items()}
                    result = {
                        "status": str(resp.status),
                        "headers": "\n".join(f"{k}: {v}" for k, v in response_headers.items()),
                        "headers_dict": response_headers,
                        "cookies": response_cookies,
                        "body": resp_text,
                    }
                    if project_id and self.store:
                        flow = self.store.add_http_flow(
                            project_id=project_id,
                            method=method,
                            url=url,
                            request_headers=merged_headers,
                            request_body=stored_request_body,
                            response_status=str(resp.status),
                            response_headers=response_headers,
                            response_body=resp_text,
                            correlation_id=correlation_id,
                            attack_run_id=attack_run_id,
                            metadata={
                                **(metadata or {}),
                                "response_cookies": response_cookies,
                                "allow_redirects": allow_redirects,
                            },
                        )
                        result["flow_id"] = flow.get("id")
                    return result
            except Exception as exc:
                if project_id and self.store:
                    flow = self.store.add_http_flow(
                        project_id=project_id,
                        method=method,
                        url=url,
                        request_headers=merged_headers,
                        request_body=stored_request_body,
                        error=str(exc),
                        correlation_id=correlation_id,
                        attack_run_id=attack_run_id,
                        metadata={
                            **(metadata or {}),
                            "allow_redirects": allow_redirects,
                        },
                    )
                    return {
                        "status": "error",
                        "headers": "",
                        "headers_dict": {},
                        "cookies": {},
                        "body": "",
                        "error": str(exc),
                        "flow_id": flow.get("id"),
                    }
                raise

    @staticmethod
    def _normalize_cookies(
        cookies: Optional[Dict[str, Any]],
        headers: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, str]:
        normalized: Dict[str, str] = {}

        if isinstance(cookies, dict):
            normalized.update({str(key): str(value) for key, value in cookies.items() if value is not None})
        elif isinstance(cookies, list):
            for item in cookies:
                if isinstance(item, dict) and item.get("name"):
                    normalized[str(item["name"])] = str(item.get("value", ""))

        cookie_header = ""
        if headers:
            for key, value in headers.items():
                if str(key).lower() == "cookie":
                    cookie_header = str(value)
                    break

        if cookie_header:
            parsed = SimpleCookie()
            try:
                parsed.load(cookie_header)
                for morsel in parsed.values():
                    normalized[morsel.key] = morsel.value
            except Exception:
                pass

        return normalized
