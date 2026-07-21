"""Shared replay and classification helpers for platform route handlers."""

import json
import re
from typing import Any, Dict, Optional, Set

from fastapi import HTTPException

from wshawk.attacks import normalize_http_url

from .context import BridgeContext


def build_platform_route_helpers(ctx: BridgeContext):
    async def _emit_platform_refresh(project_id: str, evidence: Optional[Dict[str, Any]] = None) -> None:
        await ctx.sio.emit("platform_event", {"project_id": project_id})
        if evidence:
            await ctx.sio.emit("platform_evidence", {"project_id": project_id, "evidence": evidence})

    def _normalize_http_headers(raw: Any) -> Dict[str, str]:
        if isinstance(raw, dict):
            return {str(key): str(value) for key, value in raw.items() if value is not None}
        if isinstance(raw, str):
            return ctx.http_proxy_service.parse_headers(raw)
        return {}

    def _normalize_http_body(raw: Any) -> str:
        if raw is None:
            return ""
        if isinstance(raw, (dict, list)):
            try:
                import json

                return json.dumps(raw)
            except (TypeError, ValueError):
                return str(raw)
        return str(raw)

    def _build_http_template(project_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        if isinstance(data.get("template"), dict):
            template = dict(data["template"])
            template["url"] = normalize_http_url(template.get("url"))
            if not template.get("url"):
                raise HTTPException(status_code=400, detail="Template URL is required")
            return template

        flow_id = str(data.get("flow_id") or "").strip()
        if flow_id:
            return ctx.http_replay_service.build_template_from_flow(project_id=project_id, flow_id=flow_id)

        method = str(data.get("method") or "GET").strip().upper()
        url = normalize_http_url(data.get("url"))
        if not url:
            raise HTTPException(status_code=400, detail="Target URL is required")
        return ctx.http_replay_service.build_template(
            method=method,
            url=url,
            headers=_normalize_http_headers(data.get("headers")),
            body=_normalize_http_body(data.get("body", "")),
            correlation_id=str(data.get("correlation_id") or ""),
            name=str(data.get("name") or ""),
        )

    def _resolve_attack_identities(project_id: str, data: Dict[str, Any]):
        if data.get("identity_id") or data.get("identity_alias"):
            return [
                ctx.resolve_platform_identity(
                    project_id=project_id,
                    identity_id=data.get("identity_id"),
                    identity_alias=data.get("identity_alias"),
                )
            ]

        resolved = ctx.resolve_platform_identities(
            project_id=project_id,
            identity_ids=data.get("identity_ids") or [],
            identity_aliases=data.get("identity_aliases") or [],
        )
        return resolved or [None]

    def _parse_json_object(raw: Any) -> Dict[str, Any]:
        if isinstance(raw, dict):
            return raw
        if not isinstance(raw, str) or not raw.strip():
            return {}
        try:
            parsed = json.loads(raw)
        except (TypeError, ValueError, json.JSONDecodeError):
            return {}
        return parsed if isinstance(parsed, dict) else {}

    def _collect_identity_tenants(identity: Optional[Dict[str, Any]]) -> Set[str]:
        tenants: Set[str] = set()
        if not identity:
            return tenants

        alias = str(identity.get("alias") or "").lower()
        tenants.update(match.lower() for match in re.findall(r"tenant-[a-z0-9_-]+", alias))

        def absorb(value: Any) -> None:
            if isinstance(value, dict):
                for key, nested in value.items():
                    lowered = str(key).lower()
                    if lowered in {"tenant", "tenant_id", "tenantid"} and nested:
                        tenants.add(str(nested).lower())
                    else:
                        absorb(nested)
            elif isinstance(value, list):
                for nested in value:
                    absorb(nested)

        absorb(identity.get("tokens") or {})
        absorb(identity.get("storage") or {})
        return tenants

    def _is_cross_tenant(identity: Optional[Dict[str, Any]], tenant: str) -> bool:
        normalized_tenant = str(tenant or "").strip().lower()
        if not normalized_tenant:
            return False
        known_tenants = _collect_identity_tenants(identity)
        if not known_tenants:
            return False
        return normalized_tenant not in known_tenants

    def _record_replay_evidence(
        *,
        project_id: str,
        related_event_id: str,
        attack_run_id: Optional[str],
        related_connection_id: Optional[str],
        title: str,
        category: str,
        severity: str,
        description: str,
        payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        valid_connection_id = None
        if related_connection_id:
            known_connection_ids = {
                item.get("id")
                for item in ctx.platform_store.list_ws_connections(project_id, limit=1000)
            }
            if related_connection_id in known_connection_ids:
                valid_connection_id = related_connection_id

        evidence = ctx.db.add_evidence(
            project_id=project_id,
            title=title,
            category=category,
            severity=severity,
            related_event_id=related_event_id,
            payload=payload,
        )
        ctx.platform_store.add_finding(
            project_id=project_id,
            attack_run_id=attack_run_id,
            related_connection_id=valid_connection_id,
            title=title,
            category=category,
            severity=severity,
            description=description,
            payload=payload,
        )
        return evidence

    def _classify_ws_replay_result(
        *,
        project_id: str,
        target_url: str,
        payload: Any,
        identity: Optional[Dict[str, Any]],
        related_event_id: str,
        result: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        if result.get("status") != "received":
            return None

        response_obj = _parse_json_object(result.get("response"))
        if not response_obj:
            return None

        response_type = str(response_obj.get("type") or "").lower()
        identity_alias = identity.get("alias") if identity else None

        if response_type == "invoice_snapshot":
            invoice = response_obj.get("invoice") or {}
            response_tenant = str(invoice.get("tenant") or response_obj.get("tenant") or "").strip()
            leaked_token = str(invoice.get("approval_token") or response_obj.get("approval_token") or "").strip()
            cross_tenant = _is_cross_tenant(identity, response_tenant)
            if not (cross_tenant or leaked_token):
                return None
            title = (
                "WebSocket replay exposed cross-tenant invoice data"
                if cross_tenant
                else "WebSocket replay exposed invoice approval token"
            )
            description = (
                f"Identity {identity_alias or 'anonymous'} received invoice data for {response_tenant or 'an unexpected tenant'}."
            )
            return _record_replay_evidence(
                project_id=project_id,
                related_event_id=related_event_id,
                attack_run_id=result.get("attack_run_id"),
                related_connection_id=result.get("connection_id"),
                title=title,
                category="websocket_data_exposure",
                severity="high",
                description=description,
                payload={
                    "url": target_url,
                    "request_payload": payload,
                    "identity_alias": identity_alias,
                    "response_tenant": response_tenant,
                    "invoice_id": invoice.get("id"),
                    "approval_token_present": bool(leaked_token),
                    "response": response_obj,
                    "result": result,
                },
            )

        if response_type == "team_messages":
            response_tenant = str(response_obj.get("tenant") or "").strip()
            messages = response_obj.get("messages") or []
            if response_tenant and messages and _is_cross_tenant(identity, response_tenant):
                return _record_replay_evidence(
                    project_id=project_id,
                    related_event_id=related_event_id,
                    attack_run_id=result.get("attack_run_id"),
                    related_connection_id=result.get("connection_id"),
                    title="WebSocket replay exposed cross-tenant team messages",
                    category="websocket_data_exposure",
                    severity="high",
                    description=(
                        f"Identity {identity_alias or 'anonymous'} received {len(messages)} team message(s) "
                        f"for {response_tenant}."
                    ),
                    payload={
                        "url": target_url,
                        "request_payload": payload,
                        "identity_alias": identity_alias,
                        "response_tenant": response_tenant,
                        "message_count": len(messages),
                        "response": response_obj,
                        "result": result,
                    },
                )

        if response_type in {"refund_result", "refund_processed"} and response_obj.get("ok") and response_obj.get("approval_token_reused"):
            return _record_replay_evidence(
                project_id=project_id,
                related_event_id=related_event_id,
                attack_run_id=result.get("attack_run_id"),
                related_connection_id=result.get("connection_id"),
                title="WebSocket replay reused an approval token to authorize a refund",
                category="websocket_token_replay",
                severity="high",
                description=(
                    f"Identity {identity_alias or 'anonymous'} successfully replayed an approval token for "
                    f"{response_obj.get('invoice_id', 'an invoice')}."
                ),
                payload={
                    "url": target_url,
                    "request_payload": payload,
                    "identity_alias": identity_alias,
                    "response": response_obj,
                    "result": result,
                },
            )

        return None

    def _classify_http_replay_result(
        *,
        project_id: str,
        template: Dict[str, Any],
        identity: Optional[Dict[str, Any]],
        related_event_id: str,
        result: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        if result.get("status") != "received":
            return None

        response_obj = _parse_json_object(result.get("response") or result.get("body"))
        if not response_obj:
            return None

        identity_alias = identity.get("alias") if identity else None
        response_tenant = str(
            response_obj.get("tenant")
            or (response_obj.get("invoice") or {}).get("tenant")
            or ""
        ).strip()
        messages = response_obj.get("messages") or []
        invoice = response_obj.get("invoice") or {}
        leaked_token = str(invoice.get("approval_token") or response_obj.get("approval_token") or "").strip()

        if response_obj.get("type") == "team_messages" and response_tenant and messages and _is_cross_tenant(identity, response_tenant):
            return _record_replay_evidence(
                project_id=project_id,
                related_event_id=related_event_id,
                attack_run_id=result.get("attack_run_id"),
                related_connection_id=None,
                title="HTTP replay exposed cross-tenant team messages",
                category="http_data_exposure",
                severity="high",
                description=(
                    f"Identity {identity_alias or 'anonymous'} received {len(messages)} team message(s) "
                    f"for {response_tenant} over HTTP replay."
                ),
                payload={
                    "method": template.get("method"),
                    "url": template.get("url"),
                    "identity_alias": identity_alias,
                    "response_tenant": response_tenant,
                    "message_count": len(messages),
                    "response": response_obj,
                    "result": result,
                },
            )

        if invoice and (leaked_token or (response_tenant and _is_cross_tenant(identity, response_tenant))):
            return _record_replay_evidence(
                project_id=project_id,
                related_event_id=related_event_id,
                attack_run_id=result.get("attack_run_id"),
                related_connection_id=None,
                title="HTTP replay exposed invoice data or approval material",
                category="http_data_exposure",
                severity="high",
                description=(
                    f"Identity {identity_alias or 'anonymous'} received invoice data for "
                    f"{response_tenant or 'an unexpected tenant'} over HTTP replay."
                ),
                payload={
                    "method": template.get("method"),
                    "url": template.get("url"),
                    "identity_alias": identity_alias,
                    "response_tenant": response_tenant,
                    "invoice_id": invoice.get("id"),
                    "approval_token_present": bool(leaked_token),
                    "response": response_obj,
                    "result": result,
                },
            )

        if response_obj.get("ok") and response_obj.get("approval_token_reused"):
            return _record_replay_evidence(
                project_id=project_id,
                related_event_id=related_event_id,
                attack_run_id=result.get("attack_run_id"),
                related_connection_id=None,
                title="HTTP replay reused an approval token to authorize an action",
                category="http_token_replay",
                severity="high",
                description=(
                    f"Identity {identity_alias or 'anonymous'} successfully replayed an approval token "
                    f"over HTTP."
                ),
                payload={
                    "method": template.get("method"),
                    "url": template.get("url"),
                    "identity_alias": identity_alias,
                    "response": response_obj,
                    "result": result,
                },
            )

        return None

    return {
        "_emit_platform_refresh": _emit_platform_refresh,
        "_normalize_http_headers": _normalize_http_headers,
        "_normalize_http_body": _normalize_http_body,
        "_build_http_template": _build_http_template,
        "_resolve_attack_identities": _resolve_attack_identities,
        "_parse_json_object": _parse_json_object,
        "_collect_identity_tenants": _collect_identity_tenants,
        "_is_cross_tenant": _is_cross_tenant,
        "_record_replay_evidence": _record_replay_evidence,
        "_classify_ws_replay_result": _classify_ws_replay_result,
        "_classify_http_replay_result": _classify_http_replay_result,
    }


__all__ = ["build_platform_route_helpers"]
