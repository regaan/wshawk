"""Deprecated import path for the modern advanced CLI.

The active ``wshawk-advanced`` entry point targets :mod:`wshawk.advanced_cli`.
This explicit facade remains for integrations that imported the old module.
"""

import warnings

from .advanced_cli import cli, main

warnings.warn(
    "wshawk.legacy_advanced_cli is deprecated; import wshawk.advanced_cli",
    DeprecationWarning,
    stacklevel=2,
)

__all__ = ["main", "cli"]
