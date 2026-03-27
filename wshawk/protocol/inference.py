import json
from collections import Counter, defaultdict
from typing import Any, Dict, Iterable, List, Tuple

from wshawk.message_intelligence import MessageAnalyzer


class ProtocolInferenceService:
    """Protocol-learning facade that derives field, family, and binary hints from captured traffic."""

    ACTION_KEYS = ("action", "type", "event", "op", "command", "target")

    def __init__(self):
        self.analyzer = MessageAnalyzer()

    @staticmethod
    def _normalize_message_records(messages: List[Any]) -> Tuple[List[str], List[Dict[str, Any]]]:
        normalized_text: List[str] = []
        records: List[Dict[str, Any]] = []
        for message in messages:
            if message is None:
                continue

            if isinstance(message, dict) and ("payload_text" in message or "payload" in message or "metadata" in message):
                payload_text = str(message.get("payload_text") or message.get("payload") or "")
                metadata = dict(message.get("metadata") or {})
                direction = str(message.get("direction") or metadata.get("direction") or "")
            else:
                payload_text = message if isinstance(message, str) else json.dumps(message)
                metadata = {}
                direction = ""

            if not payload_text:
                continue
            normalized_text.append(payload_text)
            records.append({"payload_text": payload_text, "metadata": metadata, "direction": direction})
        return normalized_text, records

    @staticmethod
    def _detect_field_type(value: Any) -> str:
        if value is None:
            return "null"
        if isinstance(value, bool):
            return "boolean"
        if isinstance(value, int) and not isinstance(value, bool):
            return "integer"
        if isinstance(value, float):
            return "number"
        if isinstance(value, dict):
            return "object"
        if isinstance(value, list):
            return "array"
        return "string"

    def _walk_fields(
        self,
        value: Any,
        path: str,
        stats: Dict[str, Dict[str, Any]],
    ) -> None:
        field_stat = stats.setdefault(
            path or "$",
            {"count": 0, "types": Counter(), "samples": [], "keys": Counter()},
        )
        field_stat["count"] += 1
        field_type = self._detect_field_type(value)
        field_stat["types"].update([field_type])
        if field_type == "object":
            field_stat["keys"].update(value.keys())
            for key, item in value.items():
                next_path = f"{path}.{key}" if path else key
                self._walk_fields(item, next_path, stats)
        elif field_type == "array":
            sample_values = value[:3]
            for index, item in enumerate(sample_values):
                next_path = f"{path}[]" if path else "[]"
                self._walk_fields(item, next_path, stats)
                if index == 0 and isinstance(item, dict):
                    for key in item.keys():
                        field_stat["keys"].update([key])
        else:
            sample = str(value)
            if sample and sample not in field_stat["samples"]:
                field_stat["samples"].append(sample[:120])
                field_stat["samples"] = field_stat["samples"][:5]

    def learn(self, messages: List[Any]) -> Dict[str, Any]:
        normalized, records = self._normalize_message_records(messages)
        self.analyzer.learn_from_messages(normalized)

        action_counter = Counter()
        auth_fields = set()
        recurring_fields = Counter()
        identifier_fields = Counter()
        subscription_fields = Counter()
        server_issued_fields = Counter()
        binary_formats = Counter()
        field_stats: Dict[str, Dict[str, Any]] = {}
        family_to_fields: Dict[str, Counter] = defaultdict(Counter)

        for record in records:
            raw = record["payload_text"]
            metadata = record["metadata"] or {}
            direction = record["direction"]
            binary_analysis = metadata.get("binary_analysis") or {}
            if binary_analysis.get("format"):
                binary_formats.update([str(binary_analysis["format"])])

            try:
                parsed = json.loads(raw)
            except Exception:
                continue

            if not isinstance(parsed, dict):
                continue

            action_name = None
            for action_key in self.ACTION_KEYS:
                if parsed.get(action_key):
                    action_name = str(parsed[action_key])
                    action_counter.update([action_name])
                    break

            self._walk_fields(parsed, "", field_stats)
            for field in parsed.keys():
                recurring_fields.update([field])
                if "auth" in field.lower() or "token" in field.lower() or field.lower() == "authorization":
                    auth_fields.add(field)
                if field.lower().endswith("id") or "tenant" in field.lower() or "user" in field.lower() or "channel" in field.lower():
                    identifier_fields.update([field])
                if field.lower() in {"channel", "topic", "room", "stream"} or "subscribe" in str(parsed.get(field, "")).lower():
                    subscription_fields.update([field])
                if direction == "in" and (
                    field.lower().endswith("id")
                    or field.lower() in {"session", "session_id", "token", "access_token", "subscription_id", "join_ref", "ref"}
                ):
                    server_issued_fields.update([field])

            family_name = action_name or "json_message"
            family_to_fields[family_name].update(parsed.keys())

        format_info = self.analyzer.get_format_info()
        format_info["message_families"] = action_counter.most_common(25)
        format_info["auth_fields"] = sorted(auth_fields)
        format_info["recurring_fields"] = [field for field, _ in recurring_fields.most_common(50)]
        format_info["identifier_fields"] = [field for field, _ in identifier_fields.most_common(25)]
        format_info["subscription_fields"] = [field for field, _ in subscription_fields.most_common(25)]
        format_info["server_issued_fields"] = [field for field, _ in server_issued_fields.most_common(25)]
        format_info["binary_formats"] = binary_formats.most_common(10)
        format_info["field_profiles"] = [
            {
                "path": path,
                "count": stat["count"],
                "types": dict(stat["types"]),
                "samples": stat["samples"],
                "keys": [key for key, _ in stat["keys"].most_common(12)],
            }
            for path, stat in sorted(field_stats.items(), key=lambda item: (-item[1]["count"], item[0]))
        ][:80]
        format_info["family_field_map"] = {
            family: [field for field, _ in counter.most_common(30)]
            for family, counter in family_to_fields.items()
        }
        return format_info
