"""Reusable Playwright browser-context pool."""

from __future__ import annotations

import asyncio
from typing import Any, List, Optional

from .dom_runtime import (
    HAS_PLAYWRIGHT,
    Browser,
    BrowserContext,
    PlaywrightError,
    Playwright,
    async_playwright,
    logger,
)


class BrowserPool:
    """
    Manages a pool of reusable Playwright browser contexts.
    Avoids cold-starting Chromium for every verification request.
    """

    def __init__(self):
        self._playwright: Optional[Any] = None
        self._browser: Optional[Browser] = None
        self._available: List[BrowserContext] = []
        self._in_use: List[BrowserContext] = []
        self._max_contexts: int = 4
        self._started: bool = False
        self._lock = asyncio.Lock()

    @property
    def is_available(self) -> bool:
        return HAS_PLAYWRIGHT

    @property
    def is_started(self) -> bool:
        return self._started and self._browser is not None

    async def start(self, headless: bool = True, max_contexts: int = 4) -> None:
        """Launch the browser and pre-warm contexts."""
        if not HAS_PLAYWRIGHT:
            raise ImportError(
                "Playwright not installed. Run: "
                "pip install playwright && playwright install chromium"
            )

        if self._started:
            return

        self._max_contexts = max_contexts
        self._playwright = await async_playwright().start()
        self._browser = await self._playwright.chromium.launch(
            headless=headless,
            args=[
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
            ],
        )
        self._started = True
        logger.info(f"Browser pool started (headless={headless}, max={max_contexts})")

    async def get_context(self) -> BrowserContext:
        """Get a browser context from the pool (or create one)."""
        async with self._lock:
            if not self._started:
                await self.start()

            if self._available:
                ctx = self._available.pop()
            elif len(self._in_use) < self._max_contexts:
                ctx = await self._browser.new_context(
                    java_script_enabled=True,
                    ignore_https_errors=False,
                    bypass_csp=False,
                )
            else:
                # Wait for a context to be released
                while not self._available:
                    await asyncio.sleep(0.1)
                ctx = self._available.pop()

            self._in_use.append(ctx)
            return ctx

    async def release_context(self, ctx: BrowserContext) -> None:
        """Return a context to the pool, clearing its state."""
        async with self._lock:
            if ctx in self._in_use:
                self._in_use.remove(ctx)

            # Clear all pages in the context
            try:
                for page in ctx.pages:
                    await page.close()
                # Clear cookies/storage for isolation
                await ctx.clear_cookies()
            except PlaywrightError as exc:
                logger.debug("Browser context reset failed; discarding context: %s", exc)
                # Context is broken, close and discard it
                try:
                    await ctx.close()
                except PlaywrightError as close_exc:
                    logger.debug("Broken browser context close failed: %s", close_exc)
                return

            if len(self._available) < self._max_contexts:
                self._available.append(ctx)
            else:
                try:
                    await ctx.close()
                except PlaywrightError as exc:
                    logger.debug("Surplus browser context close failed: %s", exc)

    async def shutdown(self) -> None:
        """Close all contexts and the browser."""
        for ctx in self._available + self._in_use:
            try:
                await ctx.close()
            except PlaywrightError as exc:
                logger.debug("Browser context shutdown failed: %s", exc)
        self._available.clear()
        self._in_use.clear()

        if self._browser:
            try:
                await self._browser.close()
            except PlaywrightError as exc:
                logger.debug("Browser shutdown failed: %s", exc)
            self._browser = None

        if self._playwright:
            try:
                await self._playwright.stop()
            except PlaywrightError as exc:
                logger.debug("Playwright shutdown failed: %s", exc)
            self._playwright = None

        self._started = False
        logger.info("Browser pool shut down")


# ── XSS Verifier ─────────────────────────────────────────────────



__all__ = ["BrowserPool"]
