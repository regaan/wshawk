"""Public DOM-invader facade composed from focused browser components."""

from __future__ import annotations

from typing import Dict, List, Optional

from .dom_auth import AuthFlowRecorder
from .dom_browser import BrowserPool
from .dom_models import AuthFlow, AuthStep, AuthTokens, VerifyResult, XSSTechnique
from .dom_runtime import HAS_PLAYWRIGHT, async_playwright
from .dom_xss import XSSVerifier


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


__all__ = [
    "HAS_PLAYWRIGHT",
    "async_playwright",
    "XSSTechnique",
    "VerifyResult",
    "AuthStep",
    "AuthFlow",
    "AuthTokens",
    "BrowserPool",
    "XSSVerifier",
    "AuthFlowRecorder",
    "DOMInvader",
]
