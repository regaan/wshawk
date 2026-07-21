"""Row conversion and legacy PoC helpers for the database facade."""

import json
import shlex
import sqlite3
from typing import Any, Dict


class DatabaseRowMixin:
    # Row conversion helpers

    def _row_to_scan(self, row: sqlite3.Row) -> Dict[str, Any]:
        data = dict(row)
        data["findings"] = self._loads(data.pop("findings_json", "[]"), [])
        data["options"] = self._loads(data.get("options", "{}"), {})
        return data

    def _row_to_project(self, row: sqlite3.Row) -> Dict[str, Any]:
        data = dict(row)
        data["metadata"] = self._load_sensitive_json(data.pop("metadata_json", "{}"), {})
        return data

    def _row_to_identity(self, row: sqlite3.Row) -> Dict[str, Any]:
        data = dict(row)
        data["cookies"] = self._load_sensitive_json(data.pop("cookies_json", "[]"), [])
        data["headers"] = self._load_sensitive_json(data.pop("headers_json", "{}"), {})
        data["tokens"] = self._load_sensitive_json(data.pop("tokens_json", "{}"), {})
        data["storage"] = self._load_sensitive_json(data.pop("storage_json", "{}"), {})
        data["notes"] = self._decrypt_text(data.get("notes", ""))
        return data

    def _row_to_event(self, row: sqlite3.Row) -> Dict[str, Any]:
        data = dict(row)
        data["payload"] = self._load_sensitive_json(data.pop("payload_json", "{}"), {})
        return data

    def _row_to_evidence(self, row: sqlite3.Row) -> Dict[str, Any]:
        data = dict(row)
        data["payload"] = self._load_sensitive_json(data.pop("payload_json", "{}"), {})
        return data

    @staticmethod
    def _loads(raw: str, default: Any) -> Any:
        try:
            return json.loads(raw) if raw else default
        except (TypeError, json.JSONDecodeError):
            return default

    def _generate_poc(self, finding: Dict, target: str) -> str:
        """Generate a quick curl or HTML snippet for a legacy PoC."""
        finding_type = finding.get("type", "")
        value = finding.get("value", "")
        url = finding.get("url", target) or target

        safe_url = shlex.quote(url)

        if finding_type == "csrf":
            return (
                f'<html><body><form action="{url}" method="POST">'
                '<input type="submit" value="Exploit CSRF"></form>'
                "<script>document.forms[0].submit();</script></body></html>"
            )
        if any(keyword in finding_type.lower() for keyword in ("sql", "xss", "cmd", "lfi", "fuzz")):
            safe_value = shlex.quote(value)
            return f"curl -X POST {safe_url} -d {safe_value}"
        return f"curl -I {safe_url}"



__all__ = ["DatabaseRowMixin"]
