from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from wshawk.scanner_v2 import WSHawkV2


@dataclass
class GlobalState:
    """Mutable runtime state for the desktop sidecar."""

    scanner: Optional[WSHawkV2] = None
    active_scans: Dict[str, Any] = field(default_factory=dict)
    history: List[Dict] = field(default_factory=list)
    interception_enabled: bool = False
    interception_queue: Dict[str, Any] = field(default_factory=dict)
    scan_context: Dict[str, Any] = field(default_factory=dict)

    def task_running(self, slot: str) -> bool:
        task = self.active_scans.get(slot)
        return bool(task is not None and not task.done())

    def register_task(self, slot: str, task: Any) -> None:
        if self.task_running(slot):
            raise RuntimeError(f"Task slot '{slot}' is already active")
        self.active_scans[slot] = task

    def release_task(self, slot: str, task: Any = None) -> None:
        current = self.active_scans.get(slot)
        if task is None or current is task:
            self.active_scans.pop(slot, None)
