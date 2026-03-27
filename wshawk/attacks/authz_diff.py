from typing import Any, Dict, List, Optional

from .common import build_ws_headers, serialize_ws_payload, summarize_authz_diff
from .replay import replay_websocket_message
from wshawk.store import ProjectStore


async def authz_diff_websocket(
    url: str,
    payload: Any,
    identities: List[Dict[str, Any]],
    headers: Optional[Dict[str, Any]] = None,
    timeout: float = 8.0,
) -> Dict[str, Any]:
    """Replay the same WS frame across identities and summarize behavior drift."""
    results = []
    for identity in identities:
        result = await replay_websocket_message(
            url=url,
            payload=payload,
            identity=identity,
            headers=headers,
            timeout=timeout,
        )
        results.append(result)

    return {
        "url": url,
        "results": results,
        "summary": summarize_authz_diff(results),
    }


class WebSocketAuthzDiffService:
    """Project-aware multi-identity replay comparison."""

    def __init__(self, store: Optional[ProjectStore] = None):
        self.store = store

    async def compare(
        self,
        *,
        project_id: str,
        url: str,
        payload: Any,
        identities: List[Dict[str, Any]],
        headers: Optional[Dict[str, Any]] = None,
        timeout: float = 8.0,
    ) -> Dict[str, Any]:
        target = self.store.ensure_target(project_id, url, kind="websocket") if self.store else None
        run = self.store.start_attack_run(
            project_id=project_id,
            attack_type="ws_authz_diff",
            target_id=target["id"] if target else None,
            parameters={"url": url, "identity_count": len(identities), "headers": headers or {}},
        ) if self.store else None

        result = await authz_diff_websocket(
            url=url,
            payload=payload,
            identities=identities,
            headers=headers or {},
            timeout=timeout,
        )

        if self.store and run:
            outbound_payload = serialize_ws_payload(payload)
            for result_item, identity in zip(result.get("results", []), identities):
                connection = self.store.open_ws_connection(
                    project_id=project_id,
                    url=url,
                    attack_run_id=run["id"],
                    handshake_headers=build_ws_headers(identity=identity, override_headers=headers or {}),
                    metadata={"source": "ws_authz_diff", "identity_alias": identity.get("alias", "")},
                )
                self.store.add_ws_frame(
                    project_id=project_id,
                    connection_id=connection["id"] if connection else None,
                    direction="out",
                    payload=outbound_payload,
                    metadata={"attack_run_id": run["id"], "identity_alias": identity.get("alias", "")},
                )
                if result_item.get("response"):
                    self.store.add_ws_frame(
                        project_id=project_id,
                        connection_id=connection["id"] if connection else None,
                        direction="in",
                        payload=result_item["response"],
                        metadata={"attack_run_id": run["id"], "identity_alias": identity.get("alias", "")},
                    )
                if connection:
                    self.store.close_ws_connection(
                        connection["id"],
                        state=result_item.get("status", "completed"),
                        metadata={"timing_ms": result_item.get("timing_ms"), "error": result_item.get("error", "")},
                    )
            self.store.update_attack_run(
                run["id"],
                status="completed",
                summary=result.get("summary", {}),
                completed=True,
            )
        result["attack_run_id"] = run.get("id") if run else None
        return result
