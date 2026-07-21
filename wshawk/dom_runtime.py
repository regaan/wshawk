"""Optional Playwright runtime shared by DOM verification components."""

from __future__ import annotations

import asyncio
from typing import Any

from .logger import get_logger


try:
    from playwright.async_api import (
        async_playwright,
        Browser,
        BrowserContext,
        Page,
        Playwright,
        Error as PlaywrightError,
        TimeoutError as PlaywrightTimeoutError,
    )
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False
    async_playwright = None
    Browser = BrowserContext = Page = Playwright = Any

    class PlaywrightError(Exception):
        """Placeholder used when the optional Playwright package is absent."""

    class PlaywrightTimeoutError(PlaywrightError):
        """Placeholder matching Playwright's timeout exception."""


DOM_PROTOCOL_ERRORS = (
    PlaywrightError,
    PlaywrightTimeoutError,
    asyncio.TimeoutError,
    OSError,
)

logger = get_logger("DOMInvader")

__all__ = [
    "HAS_PLAYWRIGHT",
    "async_playwright",
    "Browser",
    "BrowserContext",
    "Page",
    "Playwright",
    "PlaywrightError",
    "PlaywrightTimeoutError",
    "DOM_PROTOCOL_ERRORS",
    "logger",
]
