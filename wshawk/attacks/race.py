import asyncio
from time import perf_counter
from typing import Any, Dict, List, Optional

import websockets

from .common import (
    WS_HEADER_ARG,
    build_ws_headers,
    drain_ws_activity_frames,
    drain_ws_prelude_frames,
    recv_meaningful_ws_message,
    serialize_ws_payload,
    ws_result_effective_success,
)
from wshawk.store import ProjectStore


async def _race_attempt(
    *,
    url: str,
    payload: Any,
    identity: Optional[Dict[str, Any]],
    headers: Optional[Dict[str, Any]],
    timeout: float,
    receive_response: bool,
    wave: int,
    attempt: int,
    start_event: asyncio.Event,
    stagger_ms: int,
    pre_payloads: Optional[List[Any]] = None,
) -> Dict[str, Any]:
    await start_event.wait()
    if stagger_ms > 0:
        await asyncio.sleep((stagger_ms * attempt) / 1000.0)

    outbound_payload = serialize_ws_payload(payload)
    effective_headers = build_ws_headers(identity=identity, override_headers=headers or {})
    connect_kwargs: Dict[str, Any] = {"ping_interval": None}
    if effective_headers:
        connect_kwargs[WS_HEADER_ARG] = effective_headers

    started = perf_counter()
    result: Dict[str, Any] = {
        "wave": wave,
        "attempt": attempt,
        "status": "pending",
        "payload": outbound_payload,
        "identity_id": identity.get("id") if identity else None,
        "identity_alias": identity.get("alias") if identity else None,
    }

    try:
        async with websockets.connect(url, **connect_kwargs) as ws:
            prelude_frames = await drain_ws_prelude_frames(ws)
            if prelude_frames:
                result["prelude_frames"] = prelude_frames
                result["prelude_frame_count"] = len(prelude_frames)
            for pre_payload in pre_payloads or []:
                await ws.send(serialize_ws_payload(pre_payload))
                drained_frames = await drain_ws_activity_frames(ws)
                if drained_frames:
                    result.setdefault("setup_frames", []).extend(drained_frames)
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


class WebSocketRaceService:
    """Run concurrent duplicate/replay waves over multiple sockets."""

    def __init__(self, store: Optional[ProjectStore] = None):
        self.store = store

    async def run(
        self,
        *,
        project_id: str,
        url: str,
        payload: Any,
        identities: Optional[List[Optional[Dict[str, Any]]]] = None,
        headers: Optional[Dict[str, Any]] = None,
        timeout: float = 8.0,
        concurrency: int = 5,
        waves: int = 2,
        wave_delay_ms: int = 0,
        stagger_ms: int = 0,
        receive_response: bool = True,
        mode: str = "duplicate_action",
        pre_payloads: Optional[List[Any]] = None,
    ) -> Dict[str, Any]:
        identities = identities or [None]
        concurrency = max(1, int(concurrency))
        waves = max(1, int(waves))

        target = self.store.ensure_target(project_id, url, kind="websocket") if self.store else None
        run = self.store.start_attack_run(
            project_id=project_id,
            attack_type="ws_race",
            target_id=target["id"] if target else None,
            parameters={
                "url": url,
                "mode": mode,
                "concurrency": concurrency,
                "waves": waves,
                "wave_delay_ms": wave_delay_ms,
                "stagger_ms": stagger_ms,
                "headers": headers or {},
            },
        ) if self.store else None

        results: List[Dict[str, Any]] = []
        for wave in range(1, waves + 1):
            start_event = asyncio.Event()
            tasks = []
            for attempt in range(1, concurrency + 1):
                identity = identities[(wave + attempt - 2) % len(identities)]
                tasks.append(
                    asyncio.create_task(
                        _race_attempt(
                            url=url,
                            payload=payload,
                            identity=identity,
                            headers=headers,
                            timeout=timeout,
                            receive_response=receive_response,
                            wave=wave,
                            attempt=attempt,
                            start_event=start_event,
                            stagger_ms=stagger_ms,
                            pre_payloads=pre_payloads,
                        )
                    )
                )
            start_event.set()
            wave_results = await asyncio.gather(*tasks)
            results.extend(wave_results)
            if wave < waves and wave_delay_ms > 0:
                await asyncio.sleep(wave_delay_ms / 1000.0)

        behavior_keys = {
            (item.get("status"), item.get("response", ""), item.get("error", "")) for item in results
        }
        received_count = sum(1 for item in results if item.get("status") == "received")
        accepted_count = sum(1 for item in results if ws_result_effective_success(item))
        sent_count = sum(1 for item in results if item.get("status") == "sent")
        timeout_count = sum(1 for item in results if item.get("status") == "timeout")
        error_count = sum(1 for item in results if item.get("status") == "error")
        wave_success = {}
        for item in results:
            wave_key = f"wave_{item['wave']}"
            wave_success[wave_key] = wave_success.get(wave_key, 0) + (1 if ws_result_effective_success(item) else 0)

        multi_success = accepted_count > 1
        later_wave_success = any(count > 0 for key, count in wave_success.items() if key != "wave_1")
        suspicious = multi_success and (mode in {"duplicate_action", "replay_before_invalidation", "stale_token_window"} or len(behavior_keys) > 1)
        recommended_severity = "info"
        if suspicious and later_wave_success:
            recommended_severity = "high"
        elif suspicious:
            recommended_severity = "medium"

        summary = {
            "mode": mode,
            "wave_count": waves,
            "concurrency": concurrency,
            "attempt_count": len(results),
            "received_count": received_count,
            "accepted_count": accepted_count,
            "sent_count": sent_count,
            "timeout_count": timeout_count,
            "error_count": error_count,
            "behavior_group_count": len(behavior_keys),
            "wave_success": wave_success,
            "duplicate_success_observed": multi_success,
            "later_wave_success_observed": later_wave_success,
            "suspicious_race_window": suspicious,
            "recommended_severity": recommended_severity,
        }

        if self.store and run:
            outbound_payload = serialize_ws_payload(payload)
            for item in results:
                identity = next(
                    (
                        candidate
                        for candidate in identities
                        if candidate and candidate.get("id") == item.get("identity_id")
                    ),
                    None,
                )
                conn = self.store.open_ws_connection(
                    project_id=project_id,
                    url=url,
                    attack_run_id=run["id"],
                    handshake_headers=build_ws_headers(identity=identity, override_headers=headers or {}),
                    metadata={
                        "source": "ws_race",
                        "mode": mode,
                        "wave": item["wave"],
                        "attempt": item["attempt"],
                        "identity_alias": item.get("identity_alias", ""),
                    },
                )
                self.store.add_ws_frame(
                    project_id=project_id,
                    connection_id=conn["id"],
                    direction="out",
                    payload=outbound_payload,
                    metadata={"attack_run_id": run["id"], "mode": mode, "wave": item["wave"], "attempt": item["attempt"]},
                )
                if item.get("response"):
                    self.store.add_ws_frame(
                        project_id=project_id,
                        connection_id=conn["id"],
                        direction="in",
                        payload=item["response"],
                        metadata={"attack_run_id": run["id"], "mode": mode, "wave": item["wave"], "attempt": item["attempt"]},
                    )
                self.store.close_ws_connection(
                    conn["id"],
                    state=item.get("status", "unknown"),
                    metadata={
                        "timing_ms": item.get("timing_ms"),
                        "error": item.get("error", ""),
                        "mode": mode,
                        "wave": item["wave"],
                        "attempt": item["attempt"],
                    },
                )
            self.store.update_attack_run(run["id"], status="completed", summary=summary, completed=True)

        return {"attack_run_id": run["id"] if run else None, "results": results, "summary": summary}
