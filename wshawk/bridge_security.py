#!/usr/bin/env python3
"""
WSHawk bridge security helpers.

This module centralizes the local daemon authentication model so the
Electron client, REST endpoints, WebSocket proxy, and Socket.IO all
share one token contract.
"""

from __future__ import annotations

import ipaddress
import os
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

from wshawk.secret_store import SecretStore


TOKEN_ENV_VAR = "WSHAWK_BRIDGE_TOKEN"
TOKEN_HEADER = "X-WSHawk-Token"
TOKEN_QUERY_PARAM = "token"
EXTENSION_TOKEN_HEADER = "X-WSHawk-Extension-Token"
EXTENSION_ID_HEADER = "X-WSHawk-Extension-Id"

BRIDGE_TOKEN = os.environ.get(TOKEN_ENV_VAR) or secrets.token_urlsafe(32)

PUBLIC_HTTP_PATHS = frozenset({
    "/api/extension/status",
    "/api/extension/pair",
})

TRUSTED_EXTENSION_SCHEMES = frozenset({
    "chrome-extension",
    "moz-extension",
    "edge-extension",
    "safari-web-extension",
})

EXTENSION_PROTECTED_PATHS = frozenset({
    "/api/extension/ingest/handshake",
})


class ExtensionPairingRegistry:
    def __init__(self):
        self.secret_store = SecretStore("wshawk-bridge")
        self._active_tokens = {}
        self._trusted_origin_key = "trusted-extension-origin"
        self._trusted_extension_id_key = "trusted-extension-id"

    @staticmethod
    def _now() -> datetime:
        return datetime.now(timezone.utc)

    def get_trusted_origin(self) -> str:
        return str(self.secret_store.get(self._trusted_origin_key, "") or "")

    def get_trusted_extension_id(self) -> str:
        return str(self.secret_store.get(self._trusted_extension_id_key, "") or "")

    def issue_token(self, origin: str | None, extension_id: str | None = None, ttl_seconds: int = 8 * 60 * 60) -> dict:
        normalized_origin = normalize_extension_origin(origin)
        if not normalized_origin:
            raise ValueError("extension pairing requires a trusted extension origin")

        normalized_id = str(extension_id or "").strip()
        trusted_origin = self.get_trusted_origin()
        trusted_extension_id = self.get_trusted_extension_id()

        if trusted_origin and trusted_origin != normalized_origin:
            raise PermissionError("extension origin does not match the paired origin")
        if trusted_extension_id and normalized_id and trusted_extension_id != normalized_id:
            raise PermissionError("extension id does not match the paired extension")

        if not trusted_origin:
            self.secret_store.set(self._trusted_origin_key, normalized_origin)
        if normalized_id and not trusted_extension_id:
            self.secret_store.set(self._trusted_extension_id_key, normalized_id)

        token = secrets.token_urlsafe(32)
        expires_at = self._now() + timedelta(seconds=max(60, int(ttl_seconds)))
        self._active_tokens[token] = {
            "origin": normalized_origin,
            "extension_id": normalized_id,
            "expires_at": expires_at,
        }
        self._prune()
        return {
            "token": token,
            "expires_at": expires_at.isoformat(),
            "paired_origin": normalized_origin,
            "extension_id": normalized_id,
        }

    def revoke(self, *, clear_trust: bool = False) -> None:
        self._active_tokens.clear()
        if clear_trust:
            self.secret_store.delete(self._trusted_origin_key)
            self.secret_store.delete(self._trusted_extension_id_key)

    def validate(self, token: str | None, origin: str | None, extension_id: str | None = None) -> bool:
        self._prune()
        if not token:
            return False

        record = self._active_tokens.get(token)
        if not record:
            return False

        normalized_origin = normalize_extension_origin(origin)
        if not normalized_origin or normalized_origin != record.get("origin"):
            return False

        trusted_origin = self.get_trusted_origin()
        if trusted_origin and trusted_origin != normalized_origin:
            return False

        normalized_id = str(extension_id or "").strip()
        trusted_extension_id = self.get_trusted_extension_id()
        if trusted_extension_id and normalized_id and trusted_extension_id != normalized_id:
            return False
        if record.get("extension_id") and normalized_id and record.get("extension_id") != normalized_id:
            return False

        return True

    def describe(self) -> dict:
        self._prune()
        return {
            "paired_origin": self.get_trusted_origin(),
            "paired_extension_id": self.get_trusted_extension_id(),
            "active_token_count": len(self._active_tokens),
        }

    def _prune(self) -> None:
        now = self._now()
        expired = [
            token
            for token, record in self._active_tokens.items()
            if not record.get("expires_at") or record["expires_at"] <= now
        ]
        for token in expired:
            self._active_tokens.pop(token, None)


EXTENSION_PAIRING = ExtensionPairingRegistry()


def is_valid_bridge_token(candidate: str | None) -> bool:
    """Constant-time token validation."""
    return bool(candidate) and secrets.compare_digest(candidate, BRIDGE_TOKEN)


def is_http_public_path(path: str) -> bool:
    return path in PUBLIC_HTTP_PATHS


def is_extension_protected_path(path: str) -> bool:
    return path in EXTENSION_PROTECTED_PATHS


def is_extension_path(path: str) -> bool:
    return is_http_public_path(path) or is_extension_protected_path(path)


def is_trusted_browser_origin(origin: str | None) -> bool:
    """Allow only desktop renderer/browser origins for privileged APIs."""
    if origin is None:
        return True

    candidate = str(origin).strip()
    if not candidate:
        return True
    if candidate.lower() == "null":
        return True

    try:
        parsed = urlparse(candidate)
    except ValueError:
        return False

    scheme = str(parsed.scheme or "").lower()
    if scheme == "file":
        return True
    if scheme in {"http", "https", "ws", "wss"}:
        return is_loopback_host(parsed.hostname)
    return False


def normalize_extension_origin(origin: str | None) -> str:
    if not origin:
        return ""
    try:
        parsed = urlparse(str(origin).strip())
    except ValueError:
        return ""
    scheme = str(parsed.scheme or "").lower()
    netloc = str(parsed.netloc or "").strip()
    if scheme in TRUSTED_EXTENSION_SCHEMES and netloc:
        return f"{scheme}://{netloc}"
    return ""


def is_trusted_extension_origin(origin: str | None) -> bool:
    return bool(normalize_extension_origin(origin))


def is_loopback_host(host: str | None) -> bool:
    """Return True when a client address resolves to local loopback."""
    if not host:
        return False

    candidate = str(host).strip().split(",", 1)[0].strip()
    if not candidate:
        return False

    if candidate.lower() in {"localhost", "127.0.0.1", "::1"}:
        return True

    # Strip IPv6 zone identifiers when present.
    if "%" in candidate:
        candidate = candidate.split("%", 1)[0]

    try:
        return ipaddress.ip_address(candidate).is_loopback
    except ValueError:
        return False


def request_is_local(request) -> bool:
    client = getattr(request, "client", None)
    return is_loopback_host(getattr(client, "host", None))


def request_origin_is_trusted(request) -> bool:
    return is_trusted_browser_origin(request.headers.get("origin"))


def request_origin_is_extension(request) -> bool:
    return is_trusted_extension_origin(request.headers.get("origin"))


def extract_extension_token(request) -> str | None:
    return request.headers.get(EXTENSION_TOKEN_HEADER)


def extract_extension_id(request) -> str:
    return str(request.headers.get(EXTENSION_ID_HEADER) or "").strip()


def request_has_valid_extension_token(request) -> bool:
    return EXTENSION_PAIRING.validate(
        extract_extension_token(request),
        request.headers.get("origin"),
        extract_extension_id(request),
    )


def websocket_client_is_local(websocket) -> bool:
    client = getattr(websocket, "client", None)
    return is_loopback_host(getattr(client, "host", None))


def extract_socketio_token(environ: dict, auth: dict | None = None) -> str | None:
    """Extract a token from Socket.IO auth, headers, or query string."""
    if isinstance(auth, dict):
        token = auth.get("token")
        if token:
            return token

    header_token = environ.get("HTTP_X_WSHAWK_TOKEN")
    if header_token:
        return header_token

    query_string = environ.get("QUERY_STRING", "")
    if query_string:
        params = parse_qs(query_string, keep_blank_values=False)
        values = params.get(TOKEN_QUERY_PARAM)
        if values:
            return values[0]

    return None


def socketio_client_is_local(environ: dict) -> bool:
    forwarded = environ.get("HTTP_X_FORWARDED_FOR")
    if forwarded:
        return is_loopback_host(forwarded.split(",", 1)[0].strip())

    return is_loopback_host(
        environ.get("REMOTE_ADDR")
        or environ.get("HTTP_X_REAL_IP")
        or environ.get("REMOTE_HOST")
    )


def socketio_origin_is_trusted(environ: dict) -> bool:
    return is_trusted_browser_origin(environ.get("HTTP_ORIGIN"))


def socketio_has_valid_token(environ: dict, auth: dict | None = None) -> bool:
    """Validate a Socket.IO client handshake token."""
    return is_valid_bridge_token(extract_socketio_token(environ, auth))


def extract_websocket_token(websocket) -> str | None:
    """Extract a token from FastAPI WebSocket headers or query params."""
    return (
        websocket.headers.get(TOKEN_HEADER)
        or websocket.query_params.get(TOKEN_QUERY_PARAM)
    )


def websocket_has_valid_token(websocket) -> bool:
    """Validate a FastAPI WebSocket token."""
    return is_valid_bridge_token(extract_websocket_token(websocket))
