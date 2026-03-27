import json
import re
from collections import Counter
from typing import Any, Dict, List


class ProtocolTemplateService:
    """Build reusable, editable message templates from observed traffic."""

    ACTION_KEYS = ("action", "type", "event", "op", "command", "target")

    @staticmethod
    def _normalize_messages(messages: List[Any]) -> List[Dict[str, Any]]:
        normalized = []
        for message in messages:
            if message is None:
                continue
            if isinstance(message, dict) and ("payload_text" in message or "payload" in message or "metadata" in message):
                payload_text = str(message.get("payload_text") or message.get("payload") or "")
                direction = str(message.get("direction") or "")
                metadata = dict(message.get("metadata") or {})
            else:
                payload_text = message if isinstance(message, str) else json.dumps(message)
                direction = ""
                metadata = {}
            normalized.append({"payload_text": payload_text, "direction": direction, "metadata": metadata})
        return normalized

    @classmethod
    def _family_name(cls, parsed: Dict[str, Any], fallback: str = "json_message") -> str:
        for candidate in cls.ACTION_KEYS:
            if parsed.get(candidate):
                return str(parsed[candidate])
        return fallback

    @staticmethod
    def _collect_paths(value: Any, prefix: str = "") -> List[Dict[str, Any]]:
        paths: List[Dict[str, Any]] = []
        if isinstance(value, dict):
            for key, item in value.items():
                path = f"{prefix}.{key}" if prefix else key
                paths.append({"path": path, "type": type(item).__name__, "sample": item})
                paths.extend(ProtocolTemplateService._collect_paths(item, path))
        elif isinstance(value, list):
            path = f"{prefix}[]" if prefix else "[]"
            if value:
                paths.append({"path": path, "type": type(value[0]).__name__, "sample": value[0]})
                paths.extend(ProtocolTemplateService._collect_paths(value[0], path))
        return paths

    @staticmethod
    def _variable_name(path: str) -> str:
        return re.sub(r"[^a-zA-Z0-9_]+", "_", path).strip("_") or "value"

    def build_templates(self, messages: List[Any]) -> List[Dict[str, Any]]:
        templates: Dict[str, Dict[str, Any]] = {}

        for record in self._normalize_messages(messages):
            raw = record["payload_text"]
            metadata = record["metadata"] or {}
            try:
                parsed = raw if isinstance(raw, dict) else json.loads(raw)
            except Exception:
                parsed = None

            if isinstance(parsed, dict):
                key = self._family_name(parsed)
                editable_fields = []
                field_counter = Counter(parsed.keys())
                for field in self._collect_paths(parsed):
                    path = field["path"]
                    lowered = path.lower()
                    if lowered.endswith("id") or "tenant" in lowered or "channel" in lowered or "token" in lowered or "auth" in lowered:
                        editable_fields.append(
                            {
                                "path": path,
                                "current_value": field["sample"],
                                "suggested_variable": self._variable_name(path),
                            }
                        )

                entry = templates.setdefault(
                    key,
                    {
                        "name": key,
                        "count": 0,
                        "sample": parsed,
                        "fields": sorted(parsed.keys()),
                        "editable_fields": editable_fields,
                        "directions": Counter(),
                        "metadata_hints": Counter(),
                        "replay_template": {
                            "payload": parsed,
                            "headers": {},
                        },
                    },
                )
                entry["count"] += 1
                entry["directions"].update([record["direction"] or "unknown"])
                entry["fields"] = sorted(set(entry["fields"]).union(parsed.keys()))
                if metadata.get("family"):
                    entry["metadata_hints"].update([str(metadata["family"])])
                if metadata.get("channel"):
                    entry["metadata_hints"].update([f"channel:{metadata['channel']}"])
                existing_paths = {item["path"] for item in entry["editable_fields"]}
                for item in editable_fields:
                    if item["path"] not in existing_paths:
                        entry["editable_fields"].append(item)
                        existing_paths.add(item["path"])
            else:
                key = "text"
                entry = templates.setdefault(
                    key,
                    {
                        "name": "text",
                        "count": 0,
                        "sample": str(raw),
                        "fields": [],
                        "editable_fields": [],
                        "directions": Counter(),
                        "metadata_hints": Counter(),
                        "replay_template": {"payload": str(raw), "headers": {}},
                    },
                )
                entry["count"] += 1
                entry["directions"].update([record["direction"] or "unknown"])
                if metadata.get("binary_analysis", {}).get("format"):
                    entry["metadata_hints"].update([f"binary:{metadata['binary_analysis']['format']}"])

        rendered_templates = []
        for item in sorted(templates.values(), key=lambda template: (-template["count"], template["name"])):
            rendered_templates.append(
                {
                    "name": item["name"],
                    "count": item["count"],
                    "sample": item["sample"],
                    "fields": item["fields"],
                    "editable_fields": item["editable_fields"][:24],
                    "directions": dict(item["directions"]),
                    "metadata_hints": [hint for hint, _ in item["metadata_hints"].most_common(10)],
                    "replay_template": item["replay_template"],
                }
            )
        return rendered_templates
