from typing import Any, Dict, Optional

from wshawk.dom_invader import DOMInvader


class BrowserReplayService:
    """Replay facade for browser-authenticated session recovery."""

    def __init__(self, engine: Optional[DOMInvader] = None):
        self.engine = engine or DOMInvader()

    @property
    def is_available(self) -> bool:
        return self.engine.is_available

    async def ensure_started(self):
        if not self.engine.pool.is_started:
            await self.engine.start()

    async def replay_auth_flow(self, flow_data: Optional[Dict[str, Any]] = None):
        await self.ensure_started()
        return await self.engine.replay_auth_flow(flow_data)
