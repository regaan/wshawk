"""Compatibility wrappers for the newer attacks modules."""

from wshawk.attacks.authz_diff import authz_diff_websocket
from wshawk.attacks.common import (
    build_cookie_header,
    build_ws_headers,
    normalize_ws_message,
    serialize_ws_payload,
    summarize_authz_diff,
)
from wshawk.attacks.replay import replay_websocket_message

__all__ = [
    "authz_diff_websocket",
    "build_cookie_header",
    "build_ws_headers",
    "normalize_ws_message",
    "replay_websocket_message",
    "serialize_ws_payload",
    "summarize_authz_diff",
]
