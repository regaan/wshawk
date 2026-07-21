"""Data contracts for DOM XSS verification and authentication replay."""

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Dict, List


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



__all__ = [
    "XSSTechnique",
    "VerifyResult",
    "AuthStep",
    "AuthFlow",
    "AuthTokens",
]

