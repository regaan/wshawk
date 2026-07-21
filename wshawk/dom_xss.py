"""Browser-backed XSS execution verification."""

from __future__ import annotations

import asyncio
import json
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from .dom_browser import BrowserPool
from .dom_models import VerifyResult, XSSTechnique
from .dom_runtime import DOM_PROTOCOL_ERRORS, BrowserContext, Page, PlaywrightError, logger


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

        except DOM_PROTOCOL_ERRORS as e:
            result.evidence = f"Verification error: {str(e)}"
            logger.warning("XSS verification browser/protocol failure: %s", e)
        finally:
            if page:
                try:
                    await page.close()
                except PlaywrightError as exc:
                    logger.debug("Verification page close failed: %s", exc)
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



__all__ = ["XSSVerifier"]
