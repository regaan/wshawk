"""Authentication-flow recording and replay for DOM-backed sessions."""

from __future__ import annotations

import asyncio
import json
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from .dom_browser import BrowserPool
from .dom_models import AuthFlow, AuthStep, AuthTokens
from .dom_runtime import (
    DOM_PROTOCOL_ERRORS,
    HAS_PLAYWRIGHT,
    Browser,
    BrowserContext,
    Page,
    PlaywrightError,
    async_playwright,
    logger,
)


class AuthFlowRecorder:
    """
    Records and replays complex SSO/OAuth authentication flows.

    Recording: Opens a visible browser (headless=False) for the user
    to manually log in. Captures all network requests, cookies,
    and localStorage entries produced during the flow.

    Replay: Executes the recorded flow in headless mode to extract
    fresh session tokens when the current ones expire.
    """

    # Patterns that indicate a successful authentication
    AUTH_SUCCESS_PATTERNS = [
        r'"token"\s*:', r'"access_token"\s*:', r'"session"\s*:',
        r'"jwt"\s*:', r'"auth"\s*:', r'"Bearer\s',
        r'set-cookie', r'"authenticated"\s*:\s*true',
    ]

    def __init__(self, pool: BrowserPool):
        self._pool = pool
        self._recording_playwright: Optional[Any] = None
        self._recording_browser: Optional[Browser] = None

    async def record(
        self,
        login_url: str,
        target_ws_url: str = "",
        timeout_s: int = 120,
    ) -> AuthFlow:
        """
        Open a VISIBLE browser for the user to perform login.
        Records all network activity and extracts auth tokens.

        The browser stays open for `timeout_s` seconds or until
        the user manually closes it.
        """
        flow = AuthFlow(
            name=f"auth_{int(time.time())}",
            login_url=login_url,
            target_ws_url=target_ws_url,
            recorded_at=time.time(),
        )

        if not HAS_PLAYWRIGHT:
            raise ImportError("Playwright required for auth recording")

        # Use a separate browser instance (visible, not headless)
        pw = await async_playwright().start()
        browser = await pw.chromium.launch(
            headless=False,
            args=["--start-maximized"],
        )

        ctx = await browser.new_context(
            viewport={"width": 1280, "height": 900},
            record_har_path=None,  # We'll capture manually
            ignore_https_errors=False,
        )

        page = await ctx.new_page()

        # Track network requests for token extraction
        captured_tokens: Dict[str, str] = {}
        captured_headers: Dict[str, str] = {}

        async def on_response(response):
            try:
                url = response.url
                headers = response.headers

                # Check for Set-Cookie
                if "set-cookie" in headers:
                    for cookie in headers["set-cookie"].split(","):
                        parts = cookie.strip().split("=", 1)
                        if len(parts) == 2:
                            captured_tokens[parts[0].strip()] = parts[1].split(";")[0].strip()

                # Check response body for tokens
                ct = headers.get("content-type", "")
                if "json" in ct or "text" in ct:
                    try:
                        body = await response.text()
                        for pattern in self.AUTH_SUCCESS_PATTERNS:
                            if re.search(pattern, body, re.IGNORECASE):
                                try:
                                    data = json.loads(body)
                                    for key in ("token", "access_token", "jwt",
                                                "session_token", "auth_token",
                                                "sessionId", "sid"):
                                        if key in data:
                                            captured_tokens[key] = str(data[key])
                                except (json.JSONDecodeError, KeyError):
                                    pass
                                break
                    except DOM_PROTOCOL_ERRORS as exc:
                        logger.debug("Auth response body inspection failed: %s", exc)

                # Capture Authorization headers from requests
                req_headers = response.request.headers
                if "authorization" in req_headers:
                    captured_headers["Authorization"] = req_headers["authorization"]

            except DOM_PROTOCOL_ERRORS as exc:
                logger.debug("Auth response capture callback failed: %s", exc)
            except Exception:
                logger.exception("Unexpected failure in auth response capture callback")

        page.on("response", on_response)

        try:
            # Navigate to login URL
            flow.steps.append(AuthStep(action="navigate", url=login_url))
            await page.goto(login_url, wait_until="networkidle", timeout=30000)

            logger.info(f"Auth recording started. User has {timeout_s}s to complete login.")

            # Wait for user to complete login or browser to close
            start_time = time.monotonic()
            while time.monotonic() - start_time < timeout_s:
                try:
                    # Check if browser/page is still open
                    if page.is_closed():
                        break
                    await asyncio.sleep(1)
                except DOM_PROTOCOL_ERRORS as exc:
                    logger.debug("Auth recording page became unavailable: %s", exc)
                    break

            # Extract final state
            if not page.is_closed():
                # Cookies
                cookies = await ctx.cookies()
                flow.cookies = [
                    {"name": c["name"], "value": c["value"],
                     "domain": c["domain"], "path": c["path"]}
                    for c in cookies
                ]

                # localStorage
                try:
                    storage = await page.evaluate("""() => {
                        const items = {};
                        for (let i = 0; i < localStorage.length; i++) {
                            const key = localStorage.key(i);
                            items[key] = localStorage.getItem(key);
                        }
                        return items;
                    }""")
                    flow.local_storage = storage
                except DOM_PROTOCOL_ERRORS as exc:
                    logger.debug("Auth localStorage capture failed: %s", exc)

            flow.extracted_tokens = captured_tokens
            flow.ws_headers = captured_headers

        except DOM_PROTOCOL_ERRORS as e:
            logger.warning("Auth recording browser/protocol failure: %s", e)
        except Exception:
            logger.exception("Unexpected auth recording implementation failure")
        finally:
            try:
                await browser.close()
            except PlaywrightError as exc:
                logger.debug("Auth recording browser close failed: %s", exc)
            try:
                await pw.stop()
            except PlaywrightError as exc:
                logger.debug("Auth recording Playwright stop failed: %s", exc)

        logger.info(
            f"Auth flow recorded: {len(flow.cookies)} cookies, "
            f"{len(flow.extracted_tokens)} tokens"
        )
        return flow

    async def replay(self, flow: AuthFlow) -> AuthTokens:
        """
        Replay a recorded auth flow in headless mode to get fresh tokens.
        """
        tokens = AuthTokens()

        if not HAS_PLAYWRIGHT or not flow.login_url:
            return tokens

        ctx = await self._pool.get_context()

        try:
            page = await ctx.new_page()

            # Set previously captured cookies
            if flow.cookies:
                await ctx.add_cookies(flow.cookies)

            # Navigate to login URL
            await page.goto(flow.login_url, wait_until="networkidle", timeout=30000)
            await page.wait_for_timeout(2000)

            # Execute recorded steps
            for step in flow.steps:
                try:
                    if step.action == "navigate":
                        await page.goto(step.url, wait_until="networkidle")
                    elif step.action == "fill":
                        await page.fill(step.selector, step.value)
                    elif step.action == "click":
                        await page.click(step.selector)
                    elif step.action == "wait":
                        await page.wait_for_timeout(step.wait_ms)

                    await page.wait_for_timeout(500)
                except DOM_PROTOCOL_ERRORS as e:
                    logger.warning("Auth replay step failed: %s - %s", step.action, e)
                except Exception:
                    logger.exception("Unexpected auth replay step failure: %s", step.action)
                    raise

            # Extract fresh cookies
            cookies = await ctx.cookies()
            for c in cookies:
                tokens.cookies[c["name"]] = c["value"]

            # Extract tokens from localStorage
            try:
                storage = await page.evaluate("""() => {
                    const items = {};
                    for (let i = 0; i < localStorage.length; i++) {
                        const key = localStorage.key(i);
                        items[key] = localStorage.getItem(key);
                    }
                    return items;
                }""")
                for key in ("token", "access_token", "jwt",
                            "session_token", "auth_token"):
                    if key in storage:
                        tokens.session_token = storage[key]
                        tokens.headers["Authorization"] = f"Bearer {storage[key]}"
                        break
            except DOM_PROTOCOL_ERRORS as exc:
                logger.debug("Auth replay localStorage extraction failed: %s", exc)

            # Build cookie header
            if tokens.cookies:
                tokens.headers["Cookie"] = "; ".join(
                    f"{k}={v}" for k, v in tokens.cookies.items()
                )

            # Preserve any Authorization header from the original flow
            if flow.ws_headers.get("Authorization") and not tokens.headers.get("Authorization"):
                tokens.headers["Authorization"] = flow.ws_headers["Authorization"]

            tokens.valid = bool(tokens.headers)

            await page.close()

        except DOM_PROTOCOL_ERRORS as e:
            logger.warning("Auth replay browser/protocol failure: %s", e)
        except Exception:
            logger.exception("Unexpected auth replay implementation failure")
        finally:
            await self._pool.release_context(ctx)

        logger.info(f"Auth replay: valid={tokens.valid}, headers={list(tokens.headers.keys())}")
        return tokens


# ── DOMInvader: Orchestrator ─────────────────────────────────────



__all__ = ["AuthFlowRecorder"]
