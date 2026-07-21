"""Deprecated compatibility facade for the pre-v4 scanner API.

New code must import :mod:`wshawk.scanner_v2`.  These explicit exports remain
for existing integrations that still import ``wshawk.legacy_core``.
"""

import warnings
from typing import TYPE_CHECKING

from .console import Colors, Logger
from .cli import build_parser, cli, main
from .payload_catalog import WSPayloads

if TYPE_CHECKING:
    from .legacy_runtime import WSHawk


def __getattr__(name: str):
    """Load the retired scanner only for integrations that still request it."""
    if name == "WSHawk":
        warnings.warn(
            "wshawk.legacy_core.WSHawk is deprecated; use wshawk.scanner_v2.WSHawkV2",
            DeprecationWarning,
            stacklevel=2,
        )
        from .legacy_runtime import WSHawk

        return WSHawk
    raise AttributeError(name)

__all__ = [
    "Colors",
    "Logger",
    "WSPayloads",
    "WSHawk",
    "build_parser",
    "main",
    "cli",
]
