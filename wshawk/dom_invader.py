#!/usr/bin/env python3
"""
WSHawk DOM Invader Engine
=========================
Headless Playwright integration for DOM XSS verification
and complex SSO authentication flow recording/replay.

Architecture:
    dom_invader.py    →  pure business logic (this file)
    gui_bridge.py     →  thin REST routes
    renderer.js       →  UI controls + verified badge rendering

Components:
    BrowserPool       →  manages reusable Playwright contexts
    XSSVerifier       →  confirms actual JS execution in headless DOM
    AuthFlowRecorder  →  records and replays complex SSO/OAuth flows
    DOMInvader        →  orchestrator class (single entry point)

Replaces: headless_xss_verifier.py (deprecated)
"""

import asyncio
import json
import time
import re
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field, asdict
from enum import Enum

try:
    from playwright.async_api import (
        async_playwright,
        Browser,
        BrowserContext,
        Page,
        Playwright,
    )
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False
    async_playwright = None

from .logger import get_logger

logger = get_logger("DOMInvader")


# ── Data Classes ─────────────────────────────────────────────────

class XSSTechnique(str, Enum):
    REFLECTED = "reflected"
    DOM_BASED = "dom_based"
    STORED = "stored"
    MUTATION = "mutation"
    NONE = "none"


@dataclass
class VerifyResult:
    """Result of a single XSS verification."""
    executed: bool = False
    evidence: str = ""
    technique: XSSTechnique = XSSTechnique.NONE
    alert_message: str = ""
    dom_mutations: int = 0
    injected_scripts: int = 0
    injected_handlers: int = 0
    console_messages: List[str] = field(default_factory=list)
    elapsed_ms: float = 0.0

    def to_dict(self) -> Dict:
        d = asdict(self)
        d["technique"] = self.technique.value
        return d


@dataclass
class AuthStep:
    """A single step in a recorded authentication flow."""
    action: str  # "navigate" | "fill" | "click" | "wait" | "extract"
    selector: str = ""
    value: str = ""
    url: str = ""
    wait_ms: int = 0


@dataclass
class AuthFlow:
    """A recorded, replayable authentication flow."""
    name: str = ""
    login_url: str = ""
    target_ws_url: str = ""
    steps: List[AuthStep] = field(default_factory=list)
    cookies: List[Dict] = field(default_factory=list)
    local_storage: Dict[str, str] = field(default_factory=dict)
    extracted_tokens: Dict[str, str] = field(default_factory=dict)
    ws_headers: Dict[str, str] = field(default_factory=dict)
    recorded_at: float = 0.0

    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "login_url": self.login_url,
            "target_ws_url": self.target_ws_url,
            "steps": [asdict(s) for s in self.steps],
            "cookies": self.cookies,
            "local_storage": self.local_storage,
            "extracted_tokens": self.extracted_tokens,
            "ws_headers": self.ws_headers,
            "recorded_at": self.recorded_at,
        }


@dataclass
class AuthTokens:
    """Fresh tokens from a replayed auth flow."""
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    session_token: str = ""
    ws_protocol: str = ""
    valid: bool = False


# ── Browser Pool ─────────────────────────────────────────────────

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
            except Exception:
                # Context is broken, close and discard it
                try:
                    await ctx.close()
                except Exception:
                    pass
                return

            if len(self._available) < self._max_contexts:
                self._available.append(ctx)
            else:
                try:
                    await ctx.close()
                except Exception:
                    pass

    async def shutdown(self) -> None:
        """Close all contexts and the browser."""
        for ctx in self._available + self._in_use:
            try:
                await ctx.close()
            except Exception:
                pass
        self._available.clear()
        self._in_use.clear()

        if self._browser:
            try:
                await self._browser.close()
            except Exception:
                pass
            self._browser = None

        if self._playwright:
            try:
                await self._playwright.stop()
            except Exception:
                pass
            self._playwright = None

        self._started = False
        logger.info("Browser pool shut down")


# ── XSS Verifier ─────────────────────────────────────────────────

class XSSVerifier:
    """
    Verifies actual XSS execution in a headless browser.

    Unlike string-matching heuristics, this detects:
    - alert()/confirm()/prompt() calls
    - DOM mutations (injected <script> tags, event handlers)
    - console.log beacons
    - Mutation observer detections

    This supplements heuristic detection with sandboxed browser evidence.
    """

    # Token embedded in the test page to detect our payloads
    BEACON_TOKEN = "__WSHAWK_XSS_BEACON__"

    def __init__(self, pool: BrowserPool):
        self._pool = pool

    async def verify(
        self,
        response_content: str,
        payload: str,
        timeout_ms: int = 3000,
    ) -> VerifyResult:
        """
        Verify if an XSS payload actually executes when the server response
        is rendered in a browser.

        Args:
            response_content: The raw WebSocket/HTTP response body
            payload: The original XSS payload that was sent
            timeout_ms: Max time to wait for JS execution

        Returns:
            VerifyResult with execution evidence
        """
        start = time.monotonic()
        result = VerifyResult()

        if not self._pool.is_available:
            result.evidence = "Playwright not available"
            return result

        ctx = await self._pool.get_context()
        page = None

        try:
            page = await ctx.new_page()

            # Track dialog events (alert, confirm, prompt)
            alerts: List[str] = []

            async def on_dialog(dialog):
                alerts.append(dialog.message)
                await dialog.dismiss()

            page.on("dialog", on_dialog)

            # Track console messages
            console_msgs: List[str] = []

            def on_console(msg):
                console_msgs.append(msg.text)

            page.on("console", on_console)

            # Build the sandboxed test page
            test_html = self._build_test_page(response_content)

            # Load the page
            await page.set_content(test_html, wait_until="domcontentloaded")

            # Wait for potential JS execution
            await page.wait_for_timeout(timeout_ms)

            # Check execution indicators
            exec_data = await page.evaluate("""() => {
                return {
                    xssExecuted: window.__xss_executed || false,
                    xssMessage: window.__xss_message || '',
                    scriptCount: document.querySelectorAll('script:not([data-wshawk])').length,
                    handlerCount: (() => {
                        let count = 0;
                        const all = document.querySelectorAll('#ws-response *');
                        for (const el of all) {
                            for (const attr of el.attributes) {
                                if (attr.name.startsWith('on')) count++;
                            }
                        }
                        return count;
                    })(),
                    iframeCount: document.querySelectorAll('#ws-response iframe, #ws-response object, #ws-response embed').length,
                    mutationCount: window.__mutation_count || 0,
                };
            }""")

            # Analyze results
            result.alert_message = alerts[0] if alerts else ""
            result.console_messages = console_msgs
            result.injected_scripts = exec_data.get("scriptCount", 0)
            result.injected_handlers = exec_data.get("handlerCount", 0)
            result.dom_mutations = exec_data.get("mutationCount", 0)

            # Determine if XSS executed
            if alerts:
                result.executed = True
                result.evidence = f"Dialog triggered: {alerts[0]}"
                result.technique = XSSTechnique.REFLECTED
            elif exec_data.get("xssExecuted"):
                result.executed = True
                result.evidence = f"XSS beacon fired: {exec_data.get('xssMessage', '')}"
                result.technique = XSSTechnique.DOM_BASED
            elif any(self.BEACON_TOKEN in m for m in console_msgs):
                result.executed = True
                result.evidence = "Console beacon detected"
                result.technique = XSSTechnique.DOM_BASED
            elif exec_data.get("scriptCount", 0) > 0:
                result.executed = True
                result.evidence = f"Injected {exec_data['scriptCount']} script tag(s)"
                result.technique = XSSTechnique.MUTATION
            elif exec_data.get("handlerCount", 0) > 0:
                result.executed = True
                result.evidence = f"Injected {exec_data['handlerCount']} event handler(s)"
                result.technique = XSSTechnique.MUTATION
            else:
                result.executed = False
                result.evidence = "No execution detected"

        except Exception as e:
            result.evidence = f"Verification error: {str(e)}"
            logger.error(f"XSS verify error: {e}")
        finally:
            if page:
                try:
                    await page.close()
                except Exception:
                    pass
            await self._pool.release_context(ctx)

        result.elapsed_ms = (time.monotonic() - start) * 1000
        return result

    async def batch_verify(
        self,
        results: List[Dict],
        timeout_ms: int = 3000,
        concurrency: int = 3,
    ) -> List[Dict]:
        """
        Verify multiple Blaster results concurrently.

        Each result dict should have: { payload, response }
        Returns the same list with dom_verified, dom_evidence, dom_technique added.
        """
        semaphore = asyncio.Semaphore(concurrency)

        async def verify_one(item: Dict) -> Dict:
            async with semaphore:
                vr = await self.verify(
                    response_content=item.get("response", ""),
                    payload=item.get("payload", ""),
                    timeout_ms=timeout_ms,
                )
                item["dom_verified"] = vr.executed
                item["dom_evidence"] = vr.evidence
                item["dom_technique"] = vr.technique.value
                item["dom_elapsed_ms"] = vr.elapsed_ms
                return item

        verified = await asyncio.gather(
            *(verify_one(r) for r in results),
            return_exceptions=True,
        )

        out = []
        for v in verified:
            if isinstance(v, Exception):
                out.append({
                    "dom_verified": False,
                    "dom_evidence": f"Error: {v}",
                    "dom_technique": "none",
                })
            else:
                out.append(v)
        return out

    def _build_test_page(self, response_content: str) -> str:
        """
        Build a sandboxed HTML page that renders the WebSocket response
        and instruments it for XSS detection.
        """
        return f"""<!DOCTYPE html>
<html>
<head><title>WSHawk DOM Invader</title></head>
<body>
    <!-- Render the server response exactly as a browser would -->
    <div id="ws-response">{response_content}</div>

    <script data-wshawk="instrumentation">
    (function() {{
        // ── Override dialog functions ──
        window.__xss_executed = false;
        window.__xss_message = '';

        const origAlert = window.alert;
        const origConfirm = window.confirm;
        const origPrompt = window.prompt;

        window.alert = function(msg) {{
            window.__xss_executed = true;
            window.__xss_message = String(msg);
            origAlert(msg);
        }};
        window.confirm = function(msg) {{
            window.__xss_executed = true;
            window.__xss_message = 'confirm:' + String(msg);
            return false;
        }};
        window.prompt = function(msg) {{
            window.__xss_executed = true;
            window.__xss_message = 'prompt:' + String(msg);
            return null;
        }};

        // ── Override dangerous sinks ──
        const origEval = window.eval;
        window.eval = function(code) {{
            window.__xss_executed = true;
            window.__xss_message = 'eval:' + String(code).substring(0, 100);
            return origEval(code);
        }};

        // ── Track DOM mutations ──
        window.__mutation_count = 0;
        const observer = new MutationObserver((mutations) => {{
            for (const m of mutations) {{
                if (m.type === 'childList') {{
                    for (const node of m.addedNodes) {{
                        if (node.nodeType === 1) {{
                            window.__mutation_count++;
                            if (node.tagName === 'SCRIPT' && !node.dataset.wshawk) {{
                                window.__xss_executed = true;
                                window.__xss_message = 'script_injection';
                            }}
                        }}
                    }}
                }}
            }}
        }});
        observer.observe(document.getElementById('ws-response'), {{
            childList: true,
            subtree: true,
            attributes: true,
        }});
    }})();
    </script>
</body>
</html>"""


# ── Auth Flow Recorder ───────────────────────────────────────────

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
                    except Exception:
                        pass

                # Capture Authorization headers from requests
                req_headers = response.request.headers
                if "authorization" in req_headers:
                    captured_headers["Authorization"] = req_headers["authorization"]

            except Exception:
                pass

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
                except Exception:
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
                except Exception:
                    pass

            flow.extracted_tokens = captured_tokens
            flow.ws_headers = captured_headers

        except Exception as e:
            logger.error(f"Auth recording error: {e}")
        finally:
            try:
                await browser.close()
            except Exception:
                pass
            try:
                await pw.stop()
            except Exception:
                pass

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
                except Exception as e:
                    logger.warning(f"Auth replay step failed: {step.action} - {e}")

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
            except Exception:
                pass

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

        except Exception as e:
            logger.error(f"Auth replay error: {e}")
        finally:
            await self._pool.release_context(ctx)

        logger.info(f"Auth replay: valid={tokens.valid}, headers={list(tokens.headers.keys())}")
        return tokens


# ── DOMInvader: Orchestrator ─────────────────────────────────────

class DOMInvader:
    """
    Single entry point for all headless DOM operations.
    gui_bridge.py interacts only with this class.
    """

    def __init__(self):
        self.pool = BrowserPool()
        self.verifier = XSSVerifier(self.pool)
        self.auth = AuthFlowRecorder(self.pool)
        self._saved_flow: Optional[AuthFlow] = None

    @property
    def is_available(self) -> bool:
        return HAS_PLAYWRIGHT

    async def start(self) -> None:
        """Pre-warm the browser pool."""
        if not self.is_available:
            raise ImportError(
                "Playwright not installed. Run: "
                "pip install playwright && playwright install chromium"
            )
        await self.pool.start(headless=True, max_contexts=4)

    async def shutdown(self) -> None:
        """Clean shutdown of all browser resources."""
        await self.pool.shutdown()

    async def verify_response(
        self, payload: str, response: str, timeout_ms: int = 3000
    ) -> VerifyResult:
        """Verify a single Blaster result for XSS execution."""
        return await self.verifier.verify(response, payload, timeout_ms)

    async def batch_verify_responses(
        self, results: List[Dict], timeout_ms: int = 3000
    ) -> List[Dict]:
        """Verify multiple Blaster results concurrently."""
        return await self.verifier.batch_verify(results, timeout_ms)

    async def record_auth_flow(
        self, login_url: str, target_ws_url: str = "", timeout_s: int = 120
    ) -> Dict:
        """Record an auth flow and save it for later replay."""
        flow = await self.auth.record(login_url, target_ws_url, timeout_s)
        self._saved_flow = flow
        return flow.to_dict()

    async def replay_auth_flow(self, flow_data: Optional[Dict] = None) -> AuthTokens:
        """Replay the saved (or provided) auth flow."""
        if flow_data:
            flow = AuthFlow(
                name=flow_data.get("name", ""),
                login_url=flow_data.get("login_url", ""),
                target_ws_url=flow_data.get("target_ws_url", ""),
                cookies=flow_data.get("cookies", []),
                local_storage=flow_data.get("local_storage", {}),
                extracted_tokens=flow_data.get("extracted_tokens", {}),
                ws_headers=flow_data.get("ws_headers", {}),
                steps=[
                    AuthStep(**s) for s in flow_data.get("steps", [])
                ],
            )
        elif self._saved_flow:
            flow = self._saved_flow
        else:
            return AuthTokens()

        return await self.auth.replay(flow)

    def get_saved_flow(self) -> Optional[Dict]:
        """Return the currently saved auth flow."""
        if self._saved_flow:
            return self._saved_flow.to_dict()
        return None

    def status(self) -> Dict:
        """Return current DOM Invader status."""
        return {
            "playwright_installed": HAS_PLAYWRIGHT,
            "browser_running": self.pool.is_started,
            "contexts_available": len(self.pool._available),
            "contexts_in_use": len(self.pool._in_use),
            "auth_flow_saved": self._saved_flow is not None,
        }
