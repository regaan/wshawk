from typing import Any, Dict, List, Optional

from wshawk.scanner_v2 import WSHawkV2


class GlobalState:
    """Mutable runtime state for the desktop sidecar."""

    scanner: Optional[WSHawkV2] = None
    active_scans: Dict[str, Any] = {}
    history: List[Dict] = []
    interception_enabled: bool = False
    interception_queue: dict = {}
    scan_context: Dict[str, Any] = {}
