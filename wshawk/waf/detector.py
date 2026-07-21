"""Compatibility API for passive WAF response detection."""

from dataclasses import dataclass
from typing import Dict, Optional

from .signatures import WAF_METADATA, match_waf_signatures


@dataclass
class WAFInfo:
    """WAF detection information."""

    name: str
    confidence: float
    recommended_strategy: str


class WAFDetector:
    """Detect a WAF in an already captured HTTP response."""

    def __init__(self):
        self.detected_waf: Optional[str] = None
        self.confidence: float = 0.0

    def detect(self, headers: Dict[str, str], body: str) -> Optional[WAFInfo]:
        hits = match_waf_signatures({"headers": headers, "body": body, "cookies": ""})
        if not hits:
            self.detected_waf = None
            self.confidence = 0.0
            return None

        canonical_name = next(iter(hits))
        metadata = WAF_METADATA.get(canonical_name, {})
        self.detected_waf = canonical_name
        self.confidence = float(metadata.get("confidence", 0.75))
        return WAFInfo(
            name=str(metadata.get("display_name", canonical_name)),
            confidence=self.confidence,
            recommended_strategy=str(metadata.get("strategy", "encoding")),
        )


__all__ = ["WAFDetector", "WAFInfo"]
