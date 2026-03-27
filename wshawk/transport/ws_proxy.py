import asyncio
import json
from typing import Any, Dict, Optional

import websockets
from fastapi import WebSocket

from wshawk.binary_handler import BinaryMessageHandler
from wshawk.store import ProjectStore


class WSHawkWebSocketProxy:
    """Operator-grade WebSocket proxy with project-backed journaling."""

    def __init__(self, store: Optional[ProjectStore] = None):
        self.store = store
        self.binary_handler = BinaryMessageHandler()

    @staticmethod
    def _sanitize_headers(headers: Dict[str, Any]) -> Dict[str, str]:
        sanitized = {}
        for key, value in headers.items():
            if key.lower() == "x-wshawk-token":
                continue
            sanitized[str(key)] = str(value)
        return sanitized

    @staticmethod
    def _normalize_extensions(header_value: str) -> list:
        return [part.strip() for part in (header_value or "").split(",") if part.strip()]

    def _frame_metadata(self, payload: Any, is_binary: bool) -> Dict[str, Any]:
        metadata: Dict[str, Any] = {}
        if is_binary:
            if isinstance(payload, bytes):
                payload_bytes = payload
            elif isinstance(payload, str):
                payload_bytes = payload.encode("utf-8", errors="replace")
            else:
                payload_bytes = bytes(payload)
            analysis = self.binary_handler.analyze_message(payload_bytes)
            metadata["binary_analysis"] = analysis
            metadata["family"] = f"binary:{analysis.get('format', 'raw')}"
            metadata["identifier_fields"] = analysis.get("injectable_fields", [])
        else:
            metadata.update(self._structured_payload_metadata(payload))
        return metadata

    @staticmethod
    def _structured_payload_metadata(payload: Any) -> Dict[str, Any]:
        payload_text = payload if isinstance(payload, str) else str(payload or "")
        if not payload_text:
            return {}

        try:
            parsed = json.loads(payload_text)
        except Exception:
            return {"family": "text_message", "preview": payload_text[:120]}

        if not isinstance(parsed, dict):
            return {"family": "json_message", "preview": payload_text[:120]}

        family = next(
            (str(parsed[key]) for key in ("action", "type", "event", "op", "command", "target") if parsed.get(key)),
            "json_message",
        )
        channels = [
            str(parsed[key])
            for key in parsed.keys()
            if isinstance(parsed.get(key), str) and key.lower() in {"channel", "topic", "room", "stream", "namespace"}
        ]
        identifier_fields = [
            key
            for key in parsed.keys()
            if key.lower().endswith("id") or "tenant" in key.lower() or "user" in key.lower() or key.lower() in {"channel", "room"}
        ]
        return {
            "family": family,
            "channel": channels[0] if channels else "",
            "channels": channels[:6],
            "identifier_fields": identifier_fields[:12],
            "fields": sorted(parsed.keys())[:20],
            "preview": payload_text[:160],
        }

    @staticmethod
    def _build_upstream_connect_kwargs(handshake_headers: Dict[str, Any], requested_protocols: list, requested_extensions: list) -> Dict[str, Any]:
        blocked_headers = {
            "connection",
            "upgrade",
            "host",
            "content-length",
            "sec-websocket-key",
            "sec-websocket-version",
            "sec-websocket-extensions",
            "sec-websocket-protocol",
            "x-wshawk-token",
        }
        additional_headers = []
        origin = None
        user_agent = None

        for key, value in (handshake_headers or {}).items():
            lowered = str(key).lower()
            if lowered in blocked_headers:
                continue
            if lowered == "origin":
                origin = str(value)
                continue
            if lowered == "user-agent":
                user_agent = str(value)
                continue
            additional_headers.append((str(key), str(value)))

        return {
            "ping_interval": None,
            "subprotocols": requested_protocols or None,
            "additional_headers": additional_headers or None,
            "origin": origin,
            "user_agent_header": user_agent,
            "compression": "deflate" if requested_extensions else None,
        }

    async def proxy(
        self,
        websocket: WebSocket,
        *,
        url: str,
        sio,
        state,
        project_id: Optional[str] = None,
        correlation_id: str = "",
        shadow_url: str = "",
        delay_ms: int = 0,
    ) -> Dict[str, Any]:
        await websocket.accept()

        requested_protocols = self._normalize_extensions(
            websocket.headers.get("sec-websocket-protocol", "")
        )
        requested_extensions = self._normalize_extensions(
            websocket.headers.get("sec-websocket-extensions", "")
        )
        handshake_headers = self._sanitize_headers(dict(websocket.headers))

        connection = None
        shadow_ws = None
        if project_id and self.store:
            connection = self.store.open_ws_connection(
                project_id=project_id,
                url=url,
                handshake_headers=handshake_headers,
                correlation_id=correlation_id,
                subprotocol=", ".join(requested_protocols),
                extensions=requested_extensions,
                metadata={"mode": "proxy", "shadow_url": shadow_url or ""},
            )

        try:
            connect_kwargs = self._build_upstream_connect_kwargs(handshake_headers, requested_protocols, requested_extensions)
            async with websockets.connect(url, **connect_kwargs) as target_ws:
                response_headers = dict(getattr(target_ws, "response_headers", {}) or {})
                accepted_extensions = self._normalize_extensions(
                    response_headers.get("Sec-WebSocket-Extensions", "") or response_headers.get("sec-websocket-extensions", "")
                )
                accepted_subprotocol = getattr(target_ws, "subprotocol", "") or ", ".join(requested_protocols)
                if shadow_url:
                    shadow_ws = await websockets.connect(shadow_url, **connect_kwargs)

                if project_id and self.store and connection:
                    self.store.close_ws_connection(
                        connection["id"],
                        state="open",
                        subprotocol=accepted_subprotocol or connection.get("subprotocol", ""),
                        extensions=accepted_extensions or requested_extensions,
                        metadata={
                            "connected": True,
                            "requested_subprotocols": requested_protocols,
                            "requested_extensions": requested_extensions,
                            "accepted_extensions": accepted_extensions,
                            "compression_enabled": bool(accepted_extensions),
                            "response_header_count": len(response_headers),
                        },
                    )

                async def client_to_target():
                    while True:
                        message = await websocket.receive()
                        if message.get("type") == "websocket.disconnect":
                            break

                        payload = message.get("text")
                        is_binary = False
                        opcode = "text"
                        if payload is None:
                            payload = message.get("bytes")
                            is_binary = True
                            opcode = "binary"

                        if payload is None:
                            continue

                        if project_id and self.store:
                            self.store.add_ws_frame(
                                project_id=project_id,
                                connection_id=connection["id"] if connection else None,
                                direction="out",
                                payload=payload,
                                opcode=opcode,
                                is_binary=is_binary,
                                metadata=self._frame_metadata(payload, is_binary),
                            )

                        frame_for_ui = payload if not is_binary else self.binary_handler.parse(payload)
                        if state.interception_enabled:
                            intercept_id = json.dumps({"id": id(payload)})
                            fut = asyncio.Future()
                            state.interception_queue[intercept_id] = fut
                            await sio.emit(
                                "intercepted_frame",
                                {
                                    "id": intercept_id,
                                    "direction": "OUT",
                                    "payload": frame_for_ui if not is_binary else json.dumps(frame_for_ui),
                                    "url": url,
                                    "is_binary": is_binary,
                                },
                            )
                            result = await fut
                            if result.get("action") != "forward":
                                continue
                            payload = result.get("payload", payload)

                        if delay_ms > 0:
                            await asyncio.sleep(delay_ms / 1000.0)

                        if is_binary:
                            outbound_bytes = payload if isinstance(payload, bytes) else (
                                payload.encode("utf-8", errors="replace") if isinstance(payload, str) else bytes(payload)
                            )
                            await target_ws.send(outbound_bytes)
                            if shadow_ws:
                                await shadow_ws.send(outbound_bytes)
                        else:
                            await target_ws.send(payload)
                            if shadow_ws:
                                await shadow_ws.send(payload)

                        await sio.emit("message_sent", {"msg": payload if not is_binary else f"<binary:{len(payload)}>", "url": url})

                async def target_to_client():
                    while True:
                        payload = await target_ws.recv()
                        is_binary = isinstance(payload, bytes)
                        opcode = "binary" if is_binary else "text"

                        if project_id and self.store:
                            self.store.add_ws_frame(
                                project_id=project_id,
                                connection_id=connection["id"] if connection else None,
                                direction="in",
                                payload=payload,
                                opcode=opcode,
                                is_binary=is_binary,
                                metadata=self._frame_metadata(payload, is_binary),
                            )

                        frame_for_ui = payload if not is_binary else self.binary_handler.parse(payload)
                        if state.interception_enabled:
                            intercept_id = json.dumps({"id": id(payload)})
                            fut = asyncio.Future()
                            state.interception_queue[intercept_id] = fut
                            await sio.emit(
                                "intercepted_frame",
                                {
                                    "id": intercept_id,
                                    "direction": "IN",
                                    "payload": frame_for_ui if not is_binary else json.dumps(frame_for_ui),
                                    "url": url,
                                    "is_binary": is_binary,
                                },
                            )
                            result = await fut
                            if result.get("action") != "forward":
                                continue
                            payload = result.get("payload", payload)

                        if delay_ms > 0:
                            await asyncio.sleep(delay_ms / 1000.0)

                        if is_binary:
                            inbound_bytes = payload if isinstance(payload, bytes) else (
                                payload.encode("utf-8", errors="replace") if isinstance(payload, str) else bytes(payload)
                            )
                            await websocket.send_bytes(inbound_bytes)
                            await sio.emit("message_sent", {"response": f"<binary:{len(inbound_bytes)}>", "url": url})
                        else:
                            await websocket.send_text(payload)
                            await sio.emit("message_sent", {"response": payload, "url": url})

                await asyncio.gather(client_to_target(), target_to_client())
        finally:
            if shadow_ws:
                try:
                    await shadow_ws.close()
                except Exception:
                    pass
            if project_id and self.store and connection:
                self.store.close_ws_connection(connection["id"], state="closed", metadata={"connected": False})
