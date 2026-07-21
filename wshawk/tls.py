"""Shared TLS policy helpers for WebSocket clients."""

import ssl
from typing import Optional


def build_websocket_ssl_context(url: str, *, verify_ssl: bool = True) -> Optional[ssl.SSLContext]:
    """Return a secure-by-default SSL context for WSS URLs."""
    if not str(url or "").lower().startswith("wss://"):
        return None

    context = ssl.create_default_context()
    if not verify_ssl:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


__all__ = ["build_websocket_ssl_context"]
