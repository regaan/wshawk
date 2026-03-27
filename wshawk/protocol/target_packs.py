import json
import re
from abc import ABC, abstractmethod
from collections import Counter
from typing import Any, Dict, Iterable, List, Optional, Tuple


class BaseTargetPackAdapter(ABC):
    pack_id = "base"
    title = "Base Target Pack"
    notes = ""

    @staticmethod
    def _payload_text(frame: Dict[str, Any]) -> str:
        return str(frame.get("payload_text") or "")

    @staticmethod
    def _json_loads(payload_text: str) -> Optional[Any]:
        if not payload_text:
            return None
        try:
            return json.loads(payload_text)
        except Exception:
            return None

    @staticmethod
    def _dedupe(values: Iterable[Any], limit: int = 8) -> List[Any]:
        seen = set()
        deduped: List[Any] = []
        for value in values:
            marker = json.dumps(value, sort_keys=True) if isinstance(value, (dict, list)) else str(value)
            if marker in seen:
                continue
            seen.add(marker)
            deduped.append(value)
            if len(deduped) >= limit:
                break
        return deduped

    def _result(
        self,
        *,
        confidence: str,
        signals: List[str],
        operations: Optional[List[Dict[str, Any]]] = None,
        channels: Optional[List[str]] = None,
        identifiers: Optional[List[str]] = None,
        namespaces: Optional[List[str]] = None,
        normalized_messages: Optional[List[Dict[str, Any]]] = None,
        attack_templates: Optional[List[Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        if not signals:
            return None
        return {
            "id": self.pack_id,
            "title": self.title,
            "confidence": confidence,
            "signals": signals,
            "notes": self.notes,
            "operations": self._dedupe(operations or [], limit=8),
            "channels": self._dedupe([value for value in (channels or []) if value], limit=8),
            "identifiers": self._dedupe([value for value in (identifiers or []) if value], limit=12),
            "namespaces": self._dedupe([value for value in (namespaces or []) if value], limit=6),
            "normalized_messages": self._dedupe(normalized_messages or [], limit=6),
            "attack_templates": self._dedupe(attack_templates or [], limit=6),
            "metadata": metadata or {},
        }

    @abstractmethod
    def detect(self, connections: List[Dict[str, Any]], frames: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        raise NotImplementedError


class GraphQLTargetPackAdapter(BaseTargetPackAdapter):
    pack_id = "graphql_ws"
    title = "GraphQL Subscriptions"
    notes = (
        "Parses subscribe / next / complete flows, operation names, and variables so operators can "
        "swap operation IDs, variables, and subscription filters instead of mutating raw JSON blindly."
    )

    _OPERATION_RE = re.compile(r"\b(subscription|query|mutation)\s*([A-Za-z_][A-Za-z0-9_]*)?", re.IGNORECASE)
    _ROOT_FIELD_RE = re.compile(r"{\s*([A-Za-z_][A-Za-z0-9_]*)")

    def detect(self, connections: List[Dict[str, Any]], frames: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        subprotocols = [str(connection.get("subprotocol", "")).lower() for connection in connections]
        urls = [str(connection.get("url", "")).lower() for connection in connections]
        graphql_frames: List[Dict[str, Any]] = []
        signals: List[str] = []

        if any("graphql-transport-ws" in proto or "graphql-ws" in proto for proto in subprotocols):
            signals.append("graphql-subprotocol")
        if any("/graphql" in url for url in urls):
            signals.append("graphql-url")

        operations: List[Dict[str, Any]] = []
        channels: List[str] = []
        identifiers: List[str] = []
        normalized_messages: List[Dict[str, Any]] = []
        attack_templates: List[Dict[str, Any]] = []

        for frame in frames:
            parsed = self._json_loads(self._payload_text(frame))
            if not isinstance(parsed, dict):
                continue
            message_type = str(parsed.get("type", "")).lower()
            if message_type in {"connection_init", "subscribe", "next", "complete", "ping", "pong"}:
                graphql_frames.append(parsed)
            else:
                continue

            normalized = {
                "message_type": message_type or "unknown",
                "message_id": parsed.get("id"),
            }
            payload = parsed.get("payload")
            if isinstance(payload, dict):
                query = str(payload.get("query", "") or "")
                variables = sorted(payload.get("variables", {}).keys()) if isinstance(payload.get("variables"), dict) else []
                operation_name = payload.get("operationName")
                operation_type = None
                root_field = None
                if query:
                    match = self._OPERATION_RE.search(query)
                    if match:
                        operation_type = match.group(1).lower()
                        if match.group(2) and not operation_name:
                            operation_name = match.group(2)
                    root_match = self._ROOT_FIELD_RE.search(query)
                    if root_match:
                        root_field = root_match.group(1)
                normalized.update(
                    {
                        "operation_type": operation_type,
                        "operation_name": operation_name,
                        "variables": variables,
                        "root_field": root_field,
                    }
                )
                if operation_type or operation_name or root_field:
                    operations.append(
                        {
                            "operation_type": operation_type or "unknown",
                            "operation_name": operation_name or root_field or "anonymous",
                            "root_field": root_field or operation_name or "unknown",
                            "variables": variables,
                            "message_id": parsed.get("id"),
                        }
                    )
                    channels.append(root_field or operation_name or "")
                identifiers.extend(variables)
                if parsed.get("id"):
                    identifiers.append(str(parsed["id"]))
            normalized_messages.append(normalized)

        if graphql_frames:
            signals.append("graphql-message-types")
            attack_templates.extend(
                [
                    {
                        "id": "graphql-variable-swap",
                        "title": "Swap GraphQL variables across roles",
                        "fields": ["payload.variables", "payload.operationName"],
                    },
                    {
                        "id": "graphql-subscription-id-reuse",
                        "title": "Reuse or collide subscription IDs",
                        "fields": ["id"],
                    },
                ]
            )

        confidence = "high" if len(signals) >= 2 else "medium"
        return self._result(
            confidence=confidence,
            signals=signals,
            operations=operations,
            channels=channels,
            identifiers=identifiers,
            normalized_messages=normalized_messages,
            attack_templates=attack_templates,
            metadata={"observed_graphql_frames": len(graphql_frames)},
        )


class PhoenixTargetPackAdapter(BaseTargetPackAdapter):
    pack_id = "phoenix_channels"
    title = "Phoenix Channels"
    notes = (
        "Parses topic/event/payload/join_ref frames so operators can tamper with topic names, join "
        "references, and payload-scoped tenant or object identifiers."
    )

    def detect(self, connections: List[Dict[str, Any]], frames: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        signals: List[str] = []
        operations: List[Dict[str, Any]] = []
        channels: List[str] = []
        identifiers: List[str] = []
        normalized_messages: List[Dict[str, Any]] = []

        for frame in frames:
            parsed = self._json_loads(self._payload_text(frame))
            if not isinstance(parsed, dict) or not {"topic", "event", "payload"}.issubset(parsed.keys()):
                continue

            topic = str(parsed.get("topic") or "")
            event = str(parsed.get("event") or "")
            payload = parsed.get("payload") if isinstance(parsed.get("payload"), dict) else {}
            if topic:
                channels.append(topic)
            if parsed.get("join_ref") is not None:
                signals.append("join-ref")
                identifiers.append(str(parsed.get("join_ref")))
            signals.append("topic-event-payload")
            identifiers.extend(
                key
                for key in payload.keys()
                if key.lower().endswith("id") or "tenant" in key.lower() or "channel" in key.lower()
            )
            operations.append(
                {
                    "event": event or "unknown",
                    "topic": topic,
                    "payload_fields": sorted(payload.keys()),
                    "ref": parsed.get("ref"),
                    "join_ref": parsed.get("join_ref"),
                }
            )
            normalized_messages.append(
                {
                    "topic": topic,
                    "event": event,
                    "payload_fields": sorted(payload.keys()),
                    "join_ref": parsed.get("join_ref"),
                }
            )

        attack_templates = []
        if operations:
            attack_templates.extend(
                [
                    {
                        "id": "phoenix-topic-join-abuse",
                        "title": "Join alternate topics with captured payload",
                        "fields": ["topic", "payload"],
                    },
                    {
                        "id": "phoenix-tenant-pivot",
                        "title": "Swap tenant/object identifiers inside payload",
                        "fields": ["payload.*id", "payload.*tenant*"],
                    },
                ]
            )

        confidence = "high" if len(signals) >= 2 else "medium"
        return self._result(
            confidence=confidence,
            signals=signals,
            operations=operations,
            channels=channels,
            identifiers=identifiers,
            normalized_messages=normalized_messages,
            attack_templates=attack_templates,
            metadata={"observed_phoenix_frames": len(operations)},
        )


class ActionCableTargetPackAdapter(BaseTargetPackAdapter):
    pack_id = "actioncable"
    title = "ActionCable"
    notes = (
        "Parses command/identifier frames and decodes embedded identifier JSON so operators can replay "
        "subscriptions against alternate channels or stream identifiers."
    )

    @staticmethod
    def _parse_identifier(raw_identifier: Any) -> Dict[str, Any]:
        if isinstance(raw_identifier, dict):
            return raw_identifier
        if not raw_identifier:
            return {}
        try:
            parsed = json.loads(str(raw_identifier))
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}

    def detect(self, connections: List[Dict[str, Any]], frames: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        signals: List[str] = []
        operations: List[Dict[str, Any]] = []
        channels: List[str] = []
        identifiers: List[str] = []
        normalized_messages: List[Dict[str, Any]] = []

        for frame in frames:
            parsed = self._json_loads(self._payload_text(frame))
            if not isinstance(parsed, dict) or not {"command", "identifier"}.issubset(parsed.keys()):
                continue

            command = str(parsed.get("command") or "")
            identifier = self._parse_identifier(parsed.get("identifier"))
            message_payload = self._parse_identifier(parsed.get("data"))
            signals.append("command-identifier")
            if command.lower() in {"subscribe", "message"}:
                signals.append("subscribe-message")

            channel_name = str(identifier.get("channel") or identifier.get("stream") or "")
            if channel_name:
                channels.append(channel_name)
            identifiers.extend(str(value) for value in identifier.values() if value is not None)
            identifiers.extend(
                key
                for key in identifier.keys()
                if key.lower().endswith("id") or "tenant" in key.lower()
            )
            operations.append(
                {
                    "command": command or "unknown",
                    "channel": channel_name,
                    "identifier": identifier,
                    "message_fields": sorted(message_payload.keys()) if isinstance(message_payload, dict) else [],
                }
            )
            normalized_messages.append(
                {
                    "command": command,
                    "channel": channel_name,
                    "identifier_fields": sorted(identifier.keys()),
                }
            )

        attack_templates = []
        if operations:
            attack_templates.extend(
                [
                    {
                        "id": "actioncable-identifier-swap",
                        "title": "Swap ActionCable identifier JSON",
                        "fields": ["identifier.channel", "identifier.*id"],
                    },
                    {
                        "id": "actioncable-message-replay",
                        "title": "Replay message command across captured identifiers",
                        "fields": ["command", "data"],
                    },
                ]
            )

        confidence = "high" if len(signals) >= 2 else "medium"
        return self._result(
            confidence=confidence,
            signals=signals,
            operations=operations,
            channels=channels,
            identifiers=identifiers,
            normalized_messages=normalized_messages,
            attack_templates=attack_templates,
            metadata={"observed_actioncable_frames": len(operations)},
        )


class SignalRTargetPackAdapter(BaseTargetPackAdapter):
    pack_id = "signalr"
    title = "SignalR"
    notes = (
        "Splits SignalR record-separated messages and extracts invocation targets, invocation IDs, and "
        "argument counts so operators can replay or race hub methods with stale tokens."
    )

    _RECORD_SEPARATOR = "\x1e"

    @classmethod
    def _parse_records(cls, payload_text: str) -> List[Dict[str, Any]]:
        records: List[Dict[str, Any]] = []
        chunks = [chunk for chunk in payload_text.split(cls._RECORD_SEPARATOR) if chunk]
        for chunk in chunks:
            parsed = cls._json_loads(chunk)
            if isinstance(parsed, dict):
                records.append(parsed)
        return records

    def detect(self, connections: List[Dict[str, Any]], frames: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        urls = [str(connection.get("url", "")).lower() for connection in connections]
        signals: List[str] = []
        if any("signalr" in url for url in urls):
            signals.append("signalr-url")

        operations: List[Dict[str, Any]] = []
        identifiers: List[str] = []
        normalized_messages: List[Dict[str, Any]] = []

        for frame in frames:
            records = self._parse_records(self._payload_text(frame))
            for parsed in records:
                if not {"type", "target"}.issubset(parsed.keys()):
                    continue
                signals.append("type-target")
                if parsed.get("invocationId"):
                    signals.append("invocation-id")
                    identifiers.append(str(parsed.get("invocationId")))
                args = parsed.get("arguments") if isinstance(parsed.get("arguments"), list) else []
                operations.append(
                    {
                        "message_type": parsed.get("type"),
                        "target": parsed.get("target"),
                        "argument_count": len(args),
                        "invocation_id": parsed.get("invocationId"),
                    }
                )
                normalized_messages.append(
                    {
                        "message_type": parsed.get("type"),
                        "target": parsed.get("target"),
                        "invocation_id": parsed.get("invocationId"),
                    }
                )

        attack_templates = []
        if operations:
            attack_templates.extend(
                [
                    {
                        "id": "signalr-invocation-replay",
                        "title": "Replay invocation IDs across roles",
                        "fields": ["invocationId", "target", "arguments"],
                    },
                    {
                        "id": "signalr-race-window",
                        "title": "Race hub invocations in parallel",
                        "fields": ["target", "arguments"],
                    },
                ]
            )

        confidence = "high" if len(signals) >= 2 else "medium"
        return self._result(
            confidence=confidence,
            signals=signals,
            operations=operations,
            identifiers=identifiers,
            normalized_messages=normalized_messages,
            attack_templates=attack_templates,
            metadata={"observed_signalr_messages": len(operations)},
        )


class SocketIOTargetPackAdapter(BaseTargetPackAdapter):
    pack_id = "socket_io"
    title = "Socket.IO / Engine.IO"
    notes = (
        "Decodes Engine.IO numeric prefixes, namespaces, and event arrays so operators can replay event "
        "frames against alternate namespaces, room identifiers, or wildcard channels."
    )

    _SOCKET_IO_PREFIX = re.compile(r"^[0-6][0-9]?\[")
    _EVENT_RE = re.compile(r"^(?P<prefix>\d{2})(?P<namespace>/[^,]+,)?(?P<body>.*)$")

    def detect(self, connections: List[Dict[str, Any]], frames: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        urls = [str(connection.get("url", "")).lower() for connection in connections]
        signals: List[str] = []
        operations: List[Dict[str, Any]] = []
        channels: List[str] = []
        identifiers: List[str] = []
        namespaces: List[str] = []
        normalized_messages: List[Dict[str, Any]] = []

        if any("transport=polling" in url or "transport=websocket" in url for url in urls):
            signals.append("engineio-transport")
        if any("/socket.io/" in url for url in urls):
            signals.append("socketio-url")

        for frame in frames:
            payload_text = self._payload_text(frame)
            if not payload_text:
                continue
            if self._SOCKET_IO_PREFIX.match(payload_text):
                signals.append("engineio-prefix")
            match = self._EVENT_RE.match(payload_text)
            if not match:
                continue

            namespace = (match.group("namespace") or "").rstrip(",")
            if namespace:
                namespaces.append(namespace)
            body = match.group("body")
            parsed = self._json_loads(body)
            if not isinstance(parsed, list) or not parsed:
                continue
            event_name = str(parsed[0])
            payload = parsed[1] if len(parsed) > 1 and isinstance(parsed[1], dict) else {}
            channels.extend(
                str(value)
                for key, value in payload.items()
                if isinstance(value, str) and key.lower() in {"channel", "room", "namespace", "tenant"}
            )
            identifiers.extend(
                key
                for key in payload.keys()
                if key.lower().endswith("id") or key.lower() in {"channel", "room", "tenant"}
            )
            operations.append(
                {
                    "event": event_name,
                    "namespace": namespace or "/",
                    "payload_fields": sorted(payload.keys()),
                }
            )
            normalized_messages.append(
                {
                    "event": event_name,
                    "namespace": namespace or "/",
                    "payload_fields": sorted(payload.keys()),
                }
            )

        attack_templates = []
        if operations:
            attack_templates.extend(
                [
                    {
                        "id": "socketio-namespace-pivot",
                        "title": "Replay events into alternate namespaces",
                        "fields": ["namespace", "event"],
                    },
                    {
                        "id": "socketio-room-swap",
                        "title": "Swap room/channel identifiers in event payloads",
                        "fields": ["payload.channel", "payload.room", "payload.*id"],
                    },
                ]
            )

        confidence = "high" if len(signals) >= 2 else "medium"
        return self._result(
            confidence=confidence,
            signals=signals,
            operations=operations,
            channels=channels,
            identifiers=identifiers,
            namespaces=namespaces,
            normalized_messages=normalized_messages,
            attack_templates=attack_templates,
            metadata={"observed_socketio_events": len(operations)},
        )


class GenericStructuredTargetPackAdapter(BaseTargetPackAdapter):
    pack_id = "generic_realtime"
    title = "Generic Structured Realtime Protocol"
    notes = (
        "Provides a fallback adapter for structured JSON protocols by extracting action/type keys, likely "
        "channels, and identifier fields even when the framework is custom."
    )

    ACTION_KEYS = ("action", "type", "event", "op", "command", "target")

    def detect(self, connections: List[Dict[str, Any]], frames: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        family_counter = Counter()
        operations: List[Dict[str, Any]] = []
        channels: List[str] = []
        identifiers: List[str] = []
        normalized_messages: List[Dict[str, Any]] = []

        for frame in frames:
            parsed = self._json_loads(self._payload_text(frame))
            if not isinstance(parsed, dict):
                continue
            family_counter.update(parsed.keys())
            action_name = next((str(parsed[key]) for key in self.ACTION_KEYS if parsed.get(key)), "structured_frame")
            payload_fields = sorted(parsed.keys())
            channel_values = [
                str(parsed[key])
                for key in parsed.keys()
                if isinstance(parsed.get(key), str) and key.lower() in {"channel", "topic", "room", "stream"}
            ]
            channels.extend(channel_values)
            identifiers.extend(
                key
                for key in parsed.keys()
                if key.lower().endswith("id") or "tenant" in key.lower() or "user" in key.lower()
            )
            operations.append({"action": action_name, "payload_fields": payload_fields})
            normalized_messages.append({"action": action_name, "payload_fields": payload_fields})

        if not operations:
            return None

        signals = [f"fields:{', '.join(sorted(family_counter.keys())[:8])}"]
        attack_templates = [
            {
                "id": "generic-identifier-tamper",
                "title": "Swap identifier, tenant, or user fields",
                "fields": sorted(set(identifiers))[:8],
            }
        ]
        return self._result(
            confidence="low",
            signals=signals,
            operations=operations,
            channels=channels,
            identifiers=identifiers,
            normalized_messages=normalized_messages,
            attack_templates=attack_templates,
            metadata={"observed_structured_messages": len(operations)},
        )


class BinaryRealtimeTargetPackAdapter(BaseTargetPackAdapter):
    pack_id = "binary_realtime"
    title = "Binary / Encoded Realtime Protocol"
    notes = (
        "Uses binary analysis metadata captured by the WS proxy to surface protobuf/msgpack/CBOR/compressed "
        "traffic, injectable fields, and replay pivots without forcing the operator to decode frames manually."
    )

    def detect(self, connections: List[Dict[str, Any]], frames: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        signals: List[str] = []
        operations: List[Dict[str, Any]] = []
        identifiers: List[str] = []
        normalized_messages: List[Dict[str, Any]] = []
        attack_templates: List[Dict[str, Any]] = []
        formats = Counter()

        for frame in frames:
            metadata = frame.get("metadata") or {}
            analysis = metadata.get("binary_analysis") or {}
            if not analysis:
                continue
            fmt = str(analysis.get("format") or "raw")
            formats.update([fmt])
            signals.append(f"binary:{fmt}")
            injectable_fields = analysis.get("injectable_fields") or []
            identifiers.extend(injectable_fields)
            operations.append(
                {
                    "format": fmt,
                    "size_bytes": analysis.get("size_bytes", frame.get("payload_size", 0)),
                    "injectable_fields": injectable_fields,
                    "entropy": analysis.get("entropy"),
                }
            )
            normalized_messages.append(
                {
                    "format": fmt,
                    "fields": analysis.get("fields", {}),
                    "injectable_fields": injectable_fields,
                }
            )

        if not operations:
            return None

        top_formats = [fmt for fmt, _ in formats.most_common(4)]
        attack_templates.append(
            {
                "id": "binary-field-replay",
                "title": "Replay binary frames with injectable fields swapped",
                "fields": identifiers[:12],
            }
        )
        if any(fmt in {"compressed", "protobuf", "msgpack", "cbor"} for fmt in top_formats):
            attack_templates.append(
                {
                    "id": "binary-format-pivot",
                    "title": "Pivot on captured encoded/compressed frames",
                    "fields": top_formats,
                }
            )

        return self._result(
            confidence="medium" if len(top_formats) == 1 else "high",
            signals=sorted(set(signals))[:8],
            operations=operations,
            identifiers=identifiers,
            normalized_messages=normalized_messages,
            attack_templates=attack_templates,
            metadata={"formats": top_formats, "observed_binary_messages": len(operations)},
        )


class ProtocolTargetPackRegistry:
    """Detect and adapt common real-time framework patterns from captured WS traffic."""

    def __init__(self):
        self.adapters = [
            GraphQLTargetPackAdapter(),
            PhoenixTargetPackAdapter(),
            ActionCableTargetPackAdapter(),
            SignalRTargetPackAdapter(),
            SocketIOTargetPackAdapter(),
            BinaryRealtimeTargetPackAdapter(),
            GenericStructuredTargetPackAdapter(),
        ]

    def detect(self, connections: List[Dict[str, Any]], frames: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        packs: List[Dict[str, Any]] = []
        for adapter in self.adapters:
            result = adapter.detect(connections, frames)
            if result:
                packs.append(result)
        return packs
