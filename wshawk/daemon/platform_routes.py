import json
import re
import uuid
from datetime import datetime
from typing import Any, Dict, Optional, Set

from fastapi import HTTPException
from fastapi.responses import Response

from wshawk.attacks import normalize_http_url, serialize_ws_payload

from .context import BridgeContext


def register_platform_routes(ctx: BridgeContext) -> None:
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

    @ctx.app.get("/platform/projects")
    async def platform_list_projects():
        projects = ctx.db.list_projects()
        return {"status": "success", "projects": projects, "count": len(projects)}

    @ctx.app.post("/platform/projects")
    async def platform_save_project(data: Dict[str, Any]):
        try:
            target_url = data.get("target_url", "").strip()
            project = ctx.db.save_project(
                name=data.get("name", "").strip()
                or f"project_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                target_url=target_url,
                metadata=data.get("metadata") or {},
                project_id=data.get("project_id"),
            )
            if target_url:
                ctx.platform_store.ensure_target(
                    project["id"],
                    target_url,
                    kind="project_primary",
                    metadata={"source": "project_save"},
                )
            return {"status": "success", "project": project}
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @ctx.app.get("/platform/projects/{project_id}")
    async def platform_get_project(project_id: str):
        project = ctx.require_platform_project(project_id)
        return {
            "status": "success",
            "project": project,
            "identities": ctx.db.list_identities(project_id),
            "evidence": ctx.db.list_evidence(project_id, limit=20),
            "recent_events": ctx.db.list_events(project_id, limit=20),
            "timeline": ctx.timeline_service.build_project_summary(project_id, limit=50),
            "protocol_map_summary": ctx.protocol_graph.build_project_map(project_id, limit=200).get("summary", {}),
            "attack_runs": ctx.platform_store.list_attack_runs(project_id, limit=50),
            "findings": ctx.platform_store.list_findings(project_id, limit=50),
            "notes": ctx.platform_store.list_notes(project_id, limit=20),
        }

    @ctx.app.delete("/platform/projects/{project_id}")
    async def platform_delete_project(project_id: str):
        if not ctx.db.delete_project(project_id):
            raise HTTPException(status_code=404, detail="Project not found")
        return {"status": "success", "project_id": project_id}

    @ctx.app.get("/platform/projects/{project_id}/identities")
    async def platform_list_identities(project_id: str):
        ctx.require_platform_project(project_id)
        identities = ctx.db.list_identities(project_id)
        return {"status": "success", "identities": identities, "count": len(identities)}

    @ctx.app.post("/platform/projects/{project_id}/identities")
    async def platform_save_identity(project_id: str, data: Dict[str, Any]):
        ctx.require_platform_project(project_id)
        try:
            identity = ctx.identity_vault.save_identity(
                project_id=project_id,
                alias=data.get("alias", "").strip(),
                source=data.get("source", "manual"),
                cookies=data.get("cookies") or [],
                headers=data.get("headers") or {},
                tokens=data.get("tokens") or {},
                storage=data.get("storage") or {},
                notes=data.get("notes", ""),
                identity_id=data.get("identity_id"),
                last_validated_at=data.get("last_validated_at"),
            )
            return {"status": "success", "identity": identity}
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @ctx.app.get("/platform/projects/{project_id}/targets")
    async def platform_list_targets(project_id: str, limit: int = 200):
        ctx.require_platform_project(project_id)
        targets = ctx.platform_store.list_targets(project_id, limit=limit)
        return {"status": "success", "targets": targets, "count": len(targets)}

    @ctx.app.get("/platform/projects/{project_id}/findings")
    async def platform_list_findings(project_id: str, limit: int = 200):
        ctx.require_platform_project(project_id)
        findings = ctx.platform_store.list_findings(project_id, limit=limit)
        return {"status": "success", "findings": findings, "count": len(findings)}

    @ctx.app.get("/platform/projects/{project_id}/notes")
    async def platform_list_notes(project_id: str, limit: int = 100):
        ctx.require_platform_project(project_id)
        notes = ctx.platform_store.list_notes(project_id, limit=limit)
        return {"status": "success", "notes": notes, "count": len(notes)}

    @ctx.app.post("/platform/projects/{project_id}/notes")
    async def platform_save_note(project_id: str, data: Dict[str, Any]):
        ctx.require_platform_project(project_id)
        try:
            note = ctx.platform_store.save_note(
                project_id=project_id,
                title=data.get("title", ""),
                body=data.get("body", ""),
                note_id=data.get("note_id"),
            )
            return {"status": "success", "note": note}
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    @ctx.app.get("/platform/projects/{project_id}/timeline")
    async def platform_timeline(project_id: str, limit: int = 200):
        ctx.require_platform_project(project_id)
        return {
            "status": "success",
            "timeline": ctx.timeline_service.build_project_summary(project_id, limit=limit),
        }

    @ctx.app.get("/platform/projects/{project_id}/bundle")
    async def platform_bundle(project_id: str):
        ctx.require_platform_project(project_id)
        return {"status": "success", "bundle": ctx.evidence_bundle_builder.build(project_id)}

    @ctx.app.get("/platform/projects/{project_id}/protocol-map")
    async def platform_protocol_map(project_id: str, limit: int = 500):
        ctx.require_platform_project(project_id)
        return {
            "status": "success",
            "protocol_map": ctx.protocol_graph.build_project_map(project_id, limit=limit),
        }

    @ctx.app.get("/platform/projects/{project_id}/exports/{fmt}")
    async def platform_export_project(project_id: str, fmt: str):
        ctx.require_platform_project(project_id)
        try:
            export = ctx.evidence_exporter.export(project_id, fmt)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        return Response(
            content=export["content"],
            media_type=export["media_type"],
            headers={"Content-Disposition": f'attachment; filename="{export["filename"]}"'},
        )

    @ctx.app.get("/platform/projects/{project_id}/http-flows")
    async def platform_http_flows(project_id: str, limit: int = 200):
        ctx.require_platform_project(project_id)
        flows = ctx.platform_store.list_http_flows(project_id, limit=limit)
        return {"status": "success", "http_flows": flows, "count": len(flows)}

    @ctx.app.get("/platform/projects/{project_id}/ws-frames")
    async def platform_ws_frames(project_id: str, limit: int = 500, connection_id: Optional[str] = None):
        ctx.require_platform_project(project_id)
        frames = ctx.platform_store.list_ws_frames(project_id, connection_id=connection_id, limit=limit)
        protocol_summary = ctx.protocol_inference.learn(frames[:100]) if frames else {}
        templates = ctx.protocol_templates.build_templates(frames[:100]) if frames else []
        return {
            "status": "success",
            "ws_frames": frames,
            "count": len(frames),
            "protocol_summary": protocol_summary,
            "templates": templates,
        }

    @ctx.app.get("/platform/projects/{project_id}/ws-connections")
    async def platform_ws_connections(project_id: str, limit: int = 200):
        ctx.require_platform_project(project_id)
        connections = ctx.platform_store.list_ws_connections(project_id, limit=limit)
        return {"status": "success", "ws_connections": connections, "count": len(connections)}

    @ctx.app.get("/platform/projects/{project_id}/browser-artifacts")
    async def platform_browser_artifacts(project_id: str, limit: int = 100):
        ctx.require_platform_project(project_id)
        artifacts = ctx.platform_store.list_browser_artifacts(project_id, limit=limit)
        return {"status": "success", "browser_artifacts": artifacts, "count": len(artifacts)}

    @ctx.app.get("/platform/projects/{project_id}/attack-runs")
    async def platform_attack_runs(project_id: str, limit: int = 100):
        ctx.require_platform_project(project_id)
        runs = ctx.platform_store.list_attack_runs(project_id, limit=limit)
        return {"status": "success", "attack_runs": runs, "count": len(runs)}

    @ctx.app.get("/platform/workflow-playbooks")
    async def platform_workflow_playbooks():
        return {"status": "success", "playbooks": ctx.workflow_service.list_playbooks()}

    @ctx.app.post("/platform/exports/verify")
    async def platform_verify_export(data: Dict[str, Any]):
        bundle = data.get("bundle") if isinstance(data, dict) else {}
        verification = ctx.evidence_exporter.verify_bundle(bundle or {})
        return {"status": "success" if verification.get("ok") else "error", "verification": verification}

    @ctx.app.post("/platform/projects/{project_id}/http-templates")
    async def platform_http_template(project_id: str, data: Dict[str, Any]):
        ctx.require_platform_project(project_id)
        try:
            template = _build_http_template(project_id, data)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        return {"status": "success", "template": template}

    @ctx.app.post("/platform/projects/{project_id}/replay/http")
    async def platform_replay_http(project_id: str, data: Dict[str, Any]):
        ctx.require_platform_project(project_id)
        template = _build_http_template(project_id, data)
        identity = ctx.resolve_platform_identity(
            project_id=project_id,
            identity_id=data.get("identity_id"),
            identity_alias=data.get("identity_alias"),
        )

        attack_event = ctx.db.add_event(
            project_id=project_id,
            event_type="http_replay_started",
            payload={
                "method": template.get("method"),
                "url": template.get("url"),
                "identity_id": identity.get("id") if identity else None,
                "identity_alias": identity.get("alias") if identity else None,
                "source_flow_id": template.get("source_flow_id"),
            },
            target=template.get("url", ""),
        )

        result = await ctx.http_replay_service.replay(
            project_id=project_id,
            identity=identity,
            template=template,
            variables=data.get("variables") or {},
            cookies=data.get("cookies"),
            correlation_id=str(data.get("correlation_id") or template.get("correlation_id") or ""),
            allow_redirects=bool(data.get("allow_redirects", False)),
            timeout_s=int(data.get("timeout_s", 30) or 30),
            verify_ssl=bool(data.get("verify_ssl", True)),
        )

        evidence = _classify_http_replay_result(
            project_id=project_id,
            template=template,
            identity=identity,
            related_event_id=attack_event["id"],
            result=result,
        )

        completed_event = ctx.db.add_event(
            project_id=project_id,
            event_type="http_replay_completed" if result.get("status") != "error" else "http_replay_error",
            payload={
                "result": result,
                "attack_run_id": result.get("attack_run_id"),
                "related_event_id": attack_event["id"],
                "evidence_id": evidence.get("id") if evidence else None,
            },
            target=template.get("url", ""),
        )
        await _emit_platform_refresh(project_id, evidence=evidence)
        return {
            "status": "success",
            "project_id": project_id,
            "event_id": completed_event["id"],
            "replay": result,
            "evidence": evidence,
        }

    @ctx.app.post("/platform/projects/{project_id}/replay/ws")
    async def platform_replay_ws(project_id: str, data: Dict[str, Any]):
        project = ctx.require_platform_project(project_id)
        payload = data.get("payload")
        if payload is None:
            raise HTTPException(status_code=400, detail="Payload is required")

        target_url = (data.get("url") or project.get("target_url") or "").strip()
        if not target_url:
            raise HTTPException(status_code=400, detail="Target URL is required")

        identity = ctx.resolve_platform_identity(
            project_id=project_id,
            identity_id=data.get("identity_id"),
            identity_alias=data.get("identity_alias"),
        )
        connection_id = str(uuid.uuid4())
        payload_text = serialize_ws_payload(payload)

        sent_event = ctx.db.add_event(
            project_id=project_id,
            event_type="ws_platform_replay_sent",
            payload={
                "payload": payload_text,
                "identity_id": identity.get("id") if identity else None,
                "identity_alias": identity.get("alias") if identity else None,
            },
            direction="out",
            connection_id=connection_id,
            target=target_url,
        )

        result = await ctx.ws_replay_service.replay(
            project_id=project_id,
            url=target_url,
            payload=payload,
            identity=identity,
            headers=data.get("headers") or {},
            timeout=float(data.get("timeout", 8.0)),
        )

        event_type = {
            "received": "ws_platform_replay_response",
            "timeout": "ws_platform_replay_timeout",
            "error": "ws_platform_replay_error",
            "sent": "ws_platform_replay_complete",
        }.get(result["status"], "ws_platform_replay_complete")
        replay_event = ctx.db.add_event(
            project_id=project_id,
            event_type=event_type,
            payload={
                "result": result,
                "identity_id": identity.get("id") if identity else None,
                "identity_alias": identity.get("alias") if identity else None,
            },
            direction="in" if result["status"] == "received" else "",
            connection_id=connection_id,
            target=target_url,
        )

        evidence = _classify_ws_replay_result(
            project_id=project_id,
            target_url=target_url,
            payload=payload,
            identity=identity,
            related_event_id=replay_event["id"],
            result=result,
        )

        await ctx.sio.emit(
            "message_sent",
            {
                "msg": payload_text,
                "response": result.get("response") or result.get("error") or result.get("status"),
                "url": target_url,
                "project_id": project_id,
            },
        )
        await _emit_platform_refresh(project_id, evidence=evidence)

        return {
            "status": "success",
            "project_id": project_id,
            "sent_event_id": sent_event["id"],
            "event_id": replay_event["id"],
            "result": result,
            "evidence": evidence,
        }

    @ctx.app.post("/platform/projects/{project_id}/attacks/authz-diff")
    async def platform_authz_diff(project_id: str, data: Dict[str, Any]):
        project = ctx.require_platform_project(project_id)
        payload = data.get("payload")
        if payload is None:
            raise HTTPException(status_code=400, detail="Payload is required")

        target_url = (data.get("url") or project.get("target_url") or "").strip()
        if not target_url:
            raise HTTPException(status_code=400, detail="Target URL is required")

        identities = ctx.resolve_platform_identities(
            project_id=project_id,
            identity_ids=data.get("identity_ids") or [],
            identity_aliases=data.get("identity_aliases") or [],
        )
        if len(identities) < 2:
            raise HTTPException(
                status_code=400,
                detail="At least two identities are required for authorization diffing",
            )

        attack_event = ctx.db.add_event(
            project_id=project_id,
            event_type="ws_authz_diff_started",
            payload={
                "identity_count": len(identities),
                "identity_aliases": [identity.get("alias") for identity in identities],
                "payload": serialize_ws_payload(payload),
            },
            target=target_url,
        )

        diff_result = await ctx.ws_authz_diff_service.compare(
            project_id=project_id,
            url=target_url,
            payload=payload,
            identities=identities,
            headers=data.get("headers") or {},
            timeout=float(data.get("timeout", 8.0)),
        )

        for result in diff_result["results"]:
            ctx.db.add_event(
                project_id=project_id,
                event_type="ws_authz_diff_result",
                payload=result,
                direction="in" if result["status"] == "received" else "",
                target=target_url,
            )

        summary = diff_result["summary"]
        evidence = None
        if summary["behavior_changed"]:
            evidence = ctx.db.add_evidence(
                project_id=project_id,
                title="WebSocket authorization drift detected",
                category="websocket_authz_diff",
                severity=summary["recommended_severity"],
                related_event_id=attack_event["id"],
                payload={
                    "url": target_url,
                    "summary": summary,
                    "results": diff_result["results"],
                },
            )
            ctx.platform_store.add_finding(
                project_id=project_id,
                attack_run_id=diff_result.get("attack_run_id"),
                title="WebSocket authorization drift detected",
                category="websocket_authz_diff",
                severity=summary["recommended_severity"],
                description=f"Behavior changed across {summary['identity_count']} identities.",
                payload={"summary": summary, "results": diff_result["results"]},
            )

        completed_event = ctx.db.add_event(
            project_id=project_id,
            event_type="ws_authz_diff_completed",
            payload={
                "summary": summary,
                "evidence_id": evidence.get("id") if evidence else None,
            },
            target=target_url,
        )

        return {
            "status": "success",
            "project_id": project_id,
            "event_id": completed_event["id"],
            "evidence": evidence,
            "diff": diff_result,
        }

    @ctx.app.post("/platform/projects/{project_id}/attacks/http-authz-diff")
    async def platform_http_authz_diff(project_id: str, data: Dict[str, Any]):
        ctx.require_platform_project(project_id)
        template = _build_http_template(project_id, data)
        identities = ctx.resolve_platform_identities(
            project_id=project_id,
            identity_ids=data.get("identity_ids") or [],
            identity_aliases=data.get("identity_aliases") or [],
        )
        if len(identities) < 2:
            raise HTTPException(
                status_code=400,
                detail="At least two identities are required for HTTP authorization diffing",
            )

        attack_event = ctx.db.add_event(
            project_id=project_id,
            event_type="http_authz_diff_started",
            payload={
                "method": template.get("method"),
                "url": template.get("url"),
                "identity_count": len(identities),
                "identity_aliases": [identity.get("alias") for identity in identities],
                "source_flow_id": template.get("source_flow_id"),
            },
            target=template.get("url", ""),
        )

        diff_result = await ctx.http_authz_diff_service.compare(
            project_id=project_id,
            identities=identities,
            template=template,
            variables=data.get("variables") or {},
            cookies=data.get("cookies"),
            correlation_id=str(data.get("correlation_id") or template.get("correlation_id") or ""),
            allow_redirects=bool(data.get("allow_redirects", False)),
            timeout_s=int(data.get("timeout_s", 30) or 30),
            verify_ssl=bool(data.get("verify_ssl", True)),
        )

        for result in diff_result.get("results", []):
            ctx.db.add_event(
                project_id=project_id,
                event_type="http_authz_diff_result",
                payload=result,
                target=template.get("url", ""),
            )

        summary = diff_result["summary"]
        evidence = None
        if summary.get("behavior_changed"):
            evidence = ctx.db.add_evidence(
                project_id=project_id,
                title="HTTP authorization drift detected",
                category="http_authz_diff",
                severity=summary.get("recommended_severity", "medium"),
                related_event_id=attack_event["id"],
                payload={
                    "method": template.get("method"),
                    "url": template.get("url"),
                    "summary": summary,
                    "results": diff_result.get("results", []),
                    "template": diff_result.get("template", {}),
                },
            )
            ctx.platform_store.add_finding(
                project_id=project_id,
                attack_run_id=diff_result.get("attack_run_id"),
                title="HTTP authorization drift detected",
                category="http_authz_diff",
                severity=summary.get("recommended_severity", "medium"),
                description=f"Behavior changed across {summary.get('identity_count', 0)} identities for a replayed HTTP request.",
                payload={"summary": summary, "results": diff_result.get("results", [])},
            )

        completed_event = ctx.db.add_event(
            project_id=project_id,
            event_type="http_authz_diff_completed",
            payload={
                "summary": summary,
                "attack_run_id": diff_result.get("attack_run_id"),
                "evidence_id": evidence.get("id") if evidence else None,
            },
            target=template.get("url", ""),
        )
        await _emit_platform_refresh(project_id, evidence=evidence)
        return {
            "status": "success",
            "project_id": project_id,
            "event_id": completed_event["id"],
            "evidence": evidence,
            "diff": diff_result,
        }

    @ctx.app.post("/platform/projects/{project_id}/attacks/subscription-abuse")
    async def platform_subscription_abuse(project_id: str, data: Dict[str, Any]):
        project = ctx.require_platform_project(project_id)
        payload = data.get("payload")
        if payload is None:
            raise HTTPException(status_code=400, detail="Payload is required")

        target_url = (data.get("url") or project.get("target_url") or "").strip()
        if not target_url:
            raise HTTPException(status_code=400, detail="Target URL is required")

        identities = _resolve_attack_identities(project_id, data)
        attack_event = ctx.db.add_event(
            project_id=project_id,
            event_type="ws_subscription_abuse_started",
            payload={
                "identity_count": len(identities),
                "identity_aliases": [identity.get("alias") for identity in identities if identity],
                "payload": serialize_ws_payload(payload),
                "field_paths": data.get("field_paths") or [],
                "candidate_values": data.get("candidate_values") or [],
            },
            target=target_url,
        )

        probe_result = await ctx.ws_subscription_abuse_service.probe(
            project_id=project_id,
            url=target_url,
            payload=payload,
            identities=identities,
            headers=data.get("headers") or {},
            timeout=float(data.get("timeout", 8.0)),
            field_paths=data.get("field_paths") or [],
            candidate_values=data.get("candidate_values") or [],
            max_mutations=int(data.get("max_mutations", 24)),
        )

        summary = probe_result["summary"]
        suspicious_attempts = probe_result.get("suspicious_attempts") or []
        for attempt in suspicious_attempts[:25]:
            ctx.db.add_event(
                project_id=project_id,
                event_type="ws_subscription_abuse_match",
                payload=attempt,
                direction="in" if attempt.get("status") == "received" else "",
                target=target_url,
            )

        evidence = None
        if summary["suspicious_attempt_count"]:
            evidence = ctx.db.add_evidence(
                project_id=project_id,
                title="WebSocket subscription abuse accepted suspicious mutations",
                category="subscription_abuse",
                severity=summary["recommended_severity"],
                related_event_id=attack_event["id"],
                payload={
                    "url": target_url,
                    "summary": summary,
                    "suspicious_attempts": suspicious_attempts[:20],
                    "mutations": (probe_result.get("mutations") or [])[:20],
                },
            )
            ctx.platform_store.add_finding(
                project_id=project_id,
                attack_run_id=probe_result.get("attack_run_id"),
                title="WebSocket subscription abuse accepted suspicious mutations",
                category="subscription_abuse",
                severity=summary["recommended_severity"],
                description=(
                    f"{summary['suspicious_attempt_count']} suspicious subscription/channel/object mutation(s) "
                    f"were accepted by the target."
                ),
                payload={
                    "summary": summary,
                    "suspicious_attempts": suspicious_attempts[:20],
                },
            )

        completed_event = ctx.db.add_event(
            project_id=project_id,
            event_type="ws_subscription_abuse_completed",
            payload={
                "summary": summary,
                "attack_run_id": probe_result.get("attack_run_id"),
                "evidence_id": evidence.get("id") if evidence else None,
            },
            target=target_url,
        )
        await _emit_platform_refresh(project_id, evidence=evidence)
        return {
            "status": "success",
            "project_id": project_id,
            "event_id": completed_event["id"],
            "evidence": evidence,
            "attack": probe_result,
        }

    @ctx.app.post("/platform/projects/{project_id}/attacks/http-race")
    async def platform_http_race_attack(project_id: str, data: Dict[str, Any]):
        ctx.require_platform_project(project_id)
        template = _build_http_template(project_id, data)
        identities = _resolve_attack_identities(project_id, data)
        attack_event = ctx.db.add_event(
            project_id=project_id,
            event_type="http_race_started",
            payload={
                "method": template.get("method"),
                "url": template.get("url"),
                "mode": data.get("mode", "duplicate_action"),
                "concurrency": int(data.get("concurrency", 5)),
                "waves": int(data.get("waves", 2)),
                "source_flow_id": template.get("source_flow_id"),
                "identity_aliases": [identity.get("alias") for identity in identities if identity],
            },
            target=template.get("url", ""),
        )

        race_result = await ctx.http_race_service.run(
            project_id=project_id,
            identities=identities,
            template=template,
            variables=data.get("variables") or {},
            cookies=data.get("cookies"),
            correlation_id=str(data.get("correlation_id") or template.get("correlation_id") or ""),
            allow_redirects=bool(data.get("allow_redirects", False)),
            timeout_s=int(data.get("timeout_s", 30) or 30),
            verify_ssl=bool(data.get("verify_ssl", True)),
            concurrency=int(data.get("concurrency", 5) or 5),
            waves=int(data.get("waves", 2) or 2),
            wave_delay_ms=int(data.get("wave_delay_ms", 0) or 0),
            stagger_ms=int(data.get("stagger_ms", 0) or 0),
            mode=str(data.get("mode") or "duplicate_action"),
        )

        summary = race_result["summary"]
        for result in (race_result.get("results") or [])[:30]:
            ctx.db.add_event(
                project_id=project_id,
                event_type="http_race_result",
                payload=result,
                target=template.get("url", ""),
            )

        evidence = None
        if summary.get("suspicious_race_window"):
            evidence = ctx.db.add_evidence(
                project_id=project_id,
                title="HTTP race behavior indicates replay or duplicate-action acceptance",
                category="http_race",
                severity=summary.get("recommended_severity", "medium"),
                related_event_id=attack_event["id"],
                payload={
                    "method": template.get("method"),
                    "url": template.get("url"),
                    "summary": summary,
                    "results": (race_result.get("results") or [])[:20],
                    "template": race_result.get("template", {}),
                },
            )
            ctx.platform_store.add_finding(
                project_id=project_id,
                attack_run_id=race_result.get("attack_run_id"),
                title="HTTP race behavior indicates replay or duplicate-action acceptance",
                category="http_race",
                severity=summary.get("recommended_severity", "medium"),
                description=(
                    f"{summary.get('success_count', 0)} successful responses were observed across "
                    f"{summary.get('attempt_count', 0)} concurrent attempts."
                ),
                payload={"summary": summary, "results": (race_result.get("results") or [])[:20]},
            )

        completed_event = ctx.db.add_event(
            project_id=project_id,
            event_type="http_race_completed",
            payload={
                "summary": summary,
                "attack_run_id": race_result.get("attack_run_id"),
                "evidence_id": evidence.get("id") if evidence else None,
            },
            target=template.get("url", ""),
        )
        await _emit_platform_refresh(project_id, evidence=evidence)
        return {
            "status": "success",
            "project_id": project_id,
            "event_id": completed_event["id"],
            "evidence": evidence,
            "attack": race_result,
        }

    @ctx.app.post("/platform/projects/{project_id}/attacks/race")
    async def platform_race_attack(project_id: str, data: Dict[str, Any]):
        project = ctx.require_platform_project(project_id)
        payload = data.get("payload")
        if payload is None:
            raise HTTPException(status_code=400, detail="Payload is required")

        target_url = (data.get("url") or project.get("target_url") or "").strip()
        if not target_url:
            raise HTTPException(status_code=400, detail="Target URL is required")

        identities = _resolve_attack_identities(project_id, data)
        attack_event = ctx.db.add_event(
            project_id=project_id,
            event_type="ws_race_started",
            payload={
                "mode": data.get("mode", "duplicate_action"),
                "concurrency": int(data.get("concurrency", 5)),
                "waves": int(data.get("waves", 2)),
                "payload": serialize_ws_payload(payload),
                "identity_aliases": [identity.get("alias") for identity in identities if identity],
            },
            target=target_url,
        )

        race_result = await ctx.ws_race_service.run(
            project_id=project_id,
            url=target_url,
            payload=payload,
            identities=identities,
            headers=data.get("headers") or {},
            timeout=float(data.get("timeout", 8.0)),
            concurrency=int(data.get("concurrency", 5)),
            waves=int(data.get("waves", 2)),
            wave_delay_ms=int(data.get("wave_delay_ms", 0)),
            stagger_ms=int(data.get("stagger_ms", 0)),
            receive_response=bool(data.get("receive_response", True)),
            mode=str(data.get("mode", "duplicate_action")),
            pre_payloads=data.get("pre_payloads") or [],
        )

        summary = race_result["summary"]
        evidence = None
        if summary["suspicious_race_window"]:
            evidence = ctx.db.add_evidence(
                project_id=project_id,
                title="WebSocket race window produced duplicate or later-wave success",
                category="websocket_race",
                severity=summary["recommended_severity"],
                related_event_id=attack_event["id"],
                payload={
                    "url": target_url,
                    "summary": summary,
                    "results": race_result.get("results", [])[:30],
                },
            )
            ctx.platform_store.add_finding(
                project_id=project_id,
                attack_run_id=race_result.get("attack_run_id"),
                title="WebSocket race window produced duplicate or later-wave success",
                category="websocket_race",
                severity=summary["recommended_severity"],
                description=(
                    f"Race mode {summary['mode']} observed duplicate/later-wave success across "
                    f"{summary['attempt_count']} attempts."
                ),
                payload={
                    "summary": summary,
                    "results": race_result.get("results", [])[:30],
                },
            )

        completed_event = ctx.db.add_event(
            project_id=project_id,
            event_type="ws_race_completed",
            payload={
                "summary": summary,
                "attack_run_id": race_result.get("attack_run_id"),
                "evidence_id": evidence.get("id") if evidence else None,
            },
            target=target_url,
        )
        await _emit_platform_refresh(project_id, evidence=evidence)
        return {
            "status": "success",
            "project_id": project_id,
            "event_id": completed_event["id"],
            "evidence": evidence,
            "attack": race_result,
        }

    @ctx.app.post("/platform/projects/{project_id}/attacks/workflow")
    async def platform_workflow(project_id: str, data: Dict[str, Any]):
        project = ctx.require_platform_project(project_id)
        steps = data.get("steps") or []
        playbook = str(data.get("playbook") or "").strip()
        if not steps and not playbook:
            raise HTTPException(status_code=400, detail="At least one workflow step or playbook is required")

        default_identity = ctx.resolve_platform_identity(
            project_id=project_id,
            identity_id=data.get("identity_id"),
            identity_alias=data.get("identity_alias"),
        ) if data.get("identity_id") or data.get("identity_alias") else None
        default_url = (data.get("default_url") or project.get("target_url") or "").strip()
        default_ws_url = str(data.get("default_ws_url") or "").strip()

        attack_event = ctx.db.add_event(
            project_id=project_id,
            event_type="workflow_started",
            payload={
                "step_count": len(steps),
                "default_url": default_url,
                "default_ws_url": default_ws_url,
                "default_identity_alias": default_identity.get("alias") if default_identity else None,
                "playbook": playbook or None,
            },
            target=default_url,
        )

        workflow_result = await ctx.workflow_service.execute(
            project_id=project_id,
            steps=steps,
            playbook=playbook,
            initial_vars=data.get("variables") or {},
            default_url=default_url,
            default_ws_url=default_ws_url,
            default_identity=default_identity,
            timeout=float(data.get("timeout", 8.0)),
        )
        summary = workflow_result["summary"]
        evidence = ctx.db.add_evidence(
            project_id=project_id,
            title="Workflow execution recorded",
            category="workflow_execution",
            severity="medium" if summary.get("errors") else "info",
            related_event_id=attack_event["id"],
            payload={
                "default_url": default_url,
                "default_ws_url": default_ws_url,
                "summary": summary,
                "playbook": workflow_result.get("playbook"),
                "variables": workflow_result.get("variables", {}),
                "results": workflow_result.get("results", [])[:40],
            },
        )

        completed_event = ctx.db.add_event(
            project_id=project_id,
            event_type="workflow_completed",
            payload={
                "summary": summary,
                "attack_run_id": workflow_result.get("attack_run_id"),
                "evidence_id": evidence.get("id"),
            },
            target=default_url,
        )
        await _emit_platform_refresh(project_id, evidence=evidence)
        return {
            "status": "success",
            "project_id": project_id,
            "event_id": completed_event["id"],
            "evidence": evidence,
            "workflow": workflow_result,
        }

    @ctx.app.get("/platform/projects/{project_id}/events")
    async def platform_list_events(project_id: str, limit: int = 200, event_type: Optional[str] = None):
        ctx.require_platform_project(project_id)
        events = ctx.db.list_events(project_id=project_id, limit=limit, event_type=event_type)
        return {"status": "success", "events": events, "count": len(events)}

    @ctx.app.post("/platform/projects/{project_id}/events")
    async def platform_add_event(project_id: str, data: Dict[str, Any]):
        ctx.require_platform_project(project_id)
        event = ctx.db.add_event(
            project_id=project_id,
            event_type=data.get("event_type", "manual"),
            payload=data.get("payload") or {},
            direction=data.get("direction", ""),
            connection_id=data.get("connection_id", ""),
            target=data.get("target", ""),
        )
        return {"status": "success", "event": event}

    @ctx.app.get("/platform/projects/{project_id}/evidence")
    async def platform_list_evidence(project_id: str, limit: int = 100):
        ctx.require_platform_project(project_id)
        evidence = ctx.db.list_evidence(project_id=project_id, limit=limit)
        return {"status": "success", "evidence": evidence, "count": len(evidence)}

    @ctx.app.post("/platform/projects/{project_id}/evidence")
    async def platform_add_evidence(project_id: str, data: Dict[str, Any]):
        ctx.require_platform_project(project_id)
        try:
            evidence = ctx.db.add_evidence(
                project_id=project_id,
                title=data.get("title", "").strip(),
                category=data.get("category", "note"),
                payload=data.get("payload") or {},
                severity=data.get("severity", "info"),
                related_event_id=data.get("related_event_id"),
            )
            return {"status": "success", "evidence": evidence}
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
