"""Consistent public error responses for the local daemon API."""

from typing import Any, Dict

from fastapi.responses import JSONResponse


def public_error_message(status_code: int, detail: Any) -> str:
    """Keep actionable client errors while hiding internal server details."""
    if int(status_code) >= 500:
        return "Internal server error"
    text = str(detail or "Request failed").strip()
    return text or "Request failed"


def error_payload(status_code: int, detail: Any, *, code: str = "") -> Dict[str, Any]:
    message = public_error_message(status_code, detail)
    return {
        "status": "error",
        "code": code or f"http_{int(status_code)}",
        "message": message,
        # Retained while desktop clients migrate to the standard `message` field.
        "detail": message,
    }


def error_response(status_code: int, detail: Any, *, code: str = "") -> JSONResponse:
    return JSONResponse(
        status_code=int(status_code),
        content=error_payload(status_code, detail, code=code),
    )


__all__ = ["error_payload", "error_response", "public_error_message"]
