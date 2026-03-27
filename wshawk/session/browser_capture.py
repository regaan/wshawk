from typing import Any, Dict, Optional

from wshawk.dom_invader import DOMInvader


class BrowserCaptureService:
    """Browser-backed capture facade for authentication and DOM workflows."""

    def __init__(self, engine: Optional[DOMInvader] = None):
        self.engine = engine or DOMInvader()

    @property
    def is_available(self) -> bool:
        return self.engine.is_available

    async def ensure_started(self):
        if not self.engine.pool.is_started:
            await self.engine.start()

    async def status(self) -> Dict[str, Any]:
        return {
            "playwright_installed": self.engine.is_available,
            "browser_pool_started": self.engine.pool.is_started,
            "saved_flow": self.engine.get_saved_flow(),
        }

    async def verify_response(self, payload: str, response: str, timeout_ms: int = 3000):
        await self.ensure_started()
        return await self.engine.verify_response(payload=payload, response=response, timeout_ms=timeout_ms)

    async def batch_verify_responses(self, results, timeout_ms: int = 3000):
        await self.ensure_started()
        return await self.engine.batch_verify_responses(results, timeout_ms)

    async def record_auth_flow(self, login_url: str, target_ws_url: str = "", timeout_s: int = 120) -> Dict[str, Any]:
        return await self.engine.record_auth_flow(login_url=login_url, target_ws_url=target_ws_url, timeout_s=timeout_s)
