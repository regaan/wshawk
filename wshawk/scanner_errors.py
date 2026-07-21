"""Expected operational exceptions for scanner I/O and optional integrations."""

from websockets.exceptions import WebSocketException


SCANNER_OPERATION_ERRORS = (
    OSError,
    TimeoutError,
    TypeError,
    ValueError,
    RuntimeError,
    WebSocketException,
)

__all__ = ["SCANNER_OPERATION_ERRORS"]
