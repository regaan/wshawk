import uuid
from datetime import datetime
from typing import Any, Dict, Optional

from fastapi import HTTPException
from fastapi.responses import Response

from wshawk.attacks import serialize_ws_payload

from .context import BridgeContext
from .platform_route_support import build_platform_route_helpers


def register_platform_routes(ctx: BridgeContext) -> None:
    helpers = build_platform_route_helpers(ctx)
    _emit_platform_refresh = helpers["_emit_platform_refresh"]
    _normalize_http_headers = helpers["_normalize_http_headers"]
    _normalize_http_body = helpers["_normalize_http_body"]
    _build_http_template = helpers["_build_http_template"]
    _resolve_attack_identities = helpers["_resolve_attack_identities"]
    _parse_json_object = helpers["_parse_json_object"]
    _collect_identity_tenants = helpers["_collect_identity_tenants"]
    _is_cross_tenant = helpers["_is_cross_tenant"]
    _record_replay_evidence = helpers["_record_replay_evidence"]
    _classify_ws_replay_result = helpers["_classify_ws_replay_result"]
    _classify_http_replay_result = helpers["_classify_http_replay_result"]
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
            ctx.logger.exception("Unexpected project persistence failure")
            raise HTTPException(status_code=500, detail="Project persistence failed") from e

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
            ctx.logger.exception("Unexpected identity persistence failure")
            raise HTTPException(status_code=500, detail="Identity persistence failed") from e

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
        if not verification.get("ok"):
            raise HTTPException(status_code=422, detail="Export integrity verification failed")
        return {"status": "success", "verification": verification}

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
            ctx.logger.exception("Unexpected evidence persistence failure")
            raise HTTPException(status_code=500, detail="Evidence persistence failed") from e
