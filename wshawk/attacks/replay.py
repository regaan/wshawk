import asyncio
from time import perf_counter
from typing import Any, Dict, Optional

import websockets

from .common import (
    WS_HEADER_ARG,
    build_ws_headers,
    drain_ws_prelude_frames,
    recv_meaningful_ws_message,
    serialize_ws_payload,
)
from wshawk.store import ProjectStore


async def replay_websocket_message(
    url: str,
    payload: Any,
    identity: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, Any]] = None,
    timeout: float = 8.0,
    receive_response: bool = True,
) -> Dict[str, Any]:
    """Replay a single WS frame with optional identity-backed headers."""
    outbound_payload = serialize_ws_payload(payload)
    effective_headers = build_ws_headers(identity=identity, override_headers=headers)
    connect_kwargs: Dict[str, Any] = {"ping_interval": None}
    if effective_headers:
        connect_kwargs[WS_HEADER_ARG] = effective_headers

    started = perf_counter()
    result: Dict[str, Any] = {
        "url": url,
        "status": "pending",
        "payload": outbound_payload,
        "payload_length": len(outbound_payload),
        "identity_id": identity.get("id") if identity else None,
        "identity_alias": identity.get("alias") if identity else None,
        "header_keys": sorted(effective_headers.keys()),
    }

    try:
        async with websockets.connect(url, **connect_kwargs) as ws:
            prelude_frames = await drain_ws_prelude_frames(ws)
            if prelude_frames:
                result["prelude_frames"] = prelude_frames
                result["prelude_frame_count"] = len(prelude_frames)
            await ws.send(outbound_payload)

            if receive_response:
                response, skipped_frames = await recv_meaningful_ws_message(ws, timeout=timeout)
                result.update(
                    {
                        "status": "received",
                        "response": response,
                        "response_length": len(response),
                        "response_preview": response[:240],
                    }
                )
                if skipped_frames:
                    result["skipped_frames"] = skipped_frames
                    result["skipped_frame_count"] = len(skipped_frames)
            else:
                result.update(
                    {
                        "status": "sent",
                        "response": "",
                        "response_length": 0,
                        "response_preview": "",
                    }
                )
    except asyncio.TimeoutError:
        result.update(
            {
                "status": "timeout",
                "response": "",
                "response_length": 0,
                "response_preview": "",
                "error": f"No response received within {timeout:.2f}s",
            }
        )
    except Exception as exc:
        result.update(
            {
                "status": "error",
                "response": "",
                "response_length": 0,
                "response_preview": "",
                "error": str(exc),
            }
        )

    result["timing_ms"] = round((perf_counter() - started) * 1000, 2)
    return result


class WebSocketReplayService:
    """Project-aware single-message replay orchestration."""

    def __init__(self, store: Optional[ProjectStore] = None):
        self.store = store

    async def replay(
        self,
        *,
        project_id: str,
        url: str,
        payload: Any,
        identity: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, Any]] = None,
        timeout: float = 8.0,
    ) -> Dict[str, Any]:
        target = self.store.ensure_target(project_id, url, kind="websocket") if self.store else None
        run = self.store.start_attack_run(
            project_id=project_id,
            attack_type="ws_replay",
            target_id=target["id"] if target else None,
            identity_id=identity.get("id") if identity else None,
            parameters={"url": url, "headers": headers or {}},
        ) if self.store else None
        connection = self.store.open_ws_connection(
            project_id=project_id,
            url=url,
            attack_run_id=run["id"] if run else None,
            handshake_headers=build_ws_headers(identity=identity, override_headers=headers or {}),
            metadata={"source": "ws_replay", "identity_alias": identity.get("alias") if identity else ""},
        ) if self.store else None
        outbound_payload = serialize_ws_payload(payload)

        result = await replay_websocket_message(
            url=url,
            payload=payload,
            identity=identity,
            headers=headers or {},
            timeout=timeout,
        )

        if self.store and run:
            self.store.add_ws_frame(
                project_id=project_id,
                connection_id=connection["id"] if connection else None,
                direction="out",
                payload=outbound_payload,
                metadata={"attack_run_id": run["id"], "identity_alias": identity.get("alias") if identity else ""},
            )
            if result.get("response"):
                self.store.add_ws_frame(
                    project_id=project_id,
                    connection_id=connection["id"] if connection else None,
                    direction="in",
                    payload=result["response"],
                    metadata={"attack_run_id": run["id"], "identity_alias": identity.get("alias") if identity else ""},
                )
            self.store.update_attack_run(
                run["id"],
                status=result["status"],
                summary={"response_preview": result.get("response_preview", ""), "timing_ms": result.get("timing_ms")},
                completed=True,
            )
            if connection:
                self.store.close_ws_connection(
                    connection["id"],
                    state=result["status"],
                    metadata={"timing_ms": result.get("timing_ms"), "error": result.get("error", "")},
                )
        result["attack_run_id"] = run.get("id") if run else None
        result["connection_id"] = connection.get("id") if connection else None
        return result
