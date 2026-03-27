from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import socketio
from fastapi import FastAPI, HTTPException

from wshawk.attacks import (
    HTTPAuthzDiffService,
    HTTPRaceService,
    HTTPReplayService,
    WebSocketAuthzDiffService,
    WebSocketRaceService,
    WebSocketReplayService,
    WebSocketSubscriptionAbuseService,
    WorkflowExecutionService,
)
from wshawk.db_manager import WSHawkDatabase
from wshawk.evidence import EvidenceBundleBuilder, EvidenceExportService, TimelineService
from wshawk.logger import get_logger
from wshawk.protocol import ProtocolGraphService, ProtocolInferenceService, ProtocolTemplateService
from wshawk.session import BrowserCaptureService, BrowserReplayService, IdentityVaultService
from wshawk.store import ProjectStore
from wshawk.transport import WSHawkHTTPProxy, WSHawkWebSocketProxy

from .state import GlobalState


@dataclass
class BridgeContext:
    app: FastAPI
    sio: socketio.AsyncServer
    db: WSHawkDatabase
    state: GlobalState
    platform_store: ProjectStore
    identity_vault: IdentityVaultService
    http_replay_service: HTTPReplayService
    http_authz_diff_service: HTTPAuthzDiffService
    http_race_service: HTTPRaceService
    ws_replay_service: WebSocketReplayService
    ws_authz_diff_service: WebSocketAuthzDiffService
    ws_subscription_abuse_service: WebSocketSubscriptionAbuseService
    ws_race_service: WebSocketRaceService
    workflow_service: WorkflowExecutionService
    ws_proxy_service: WSHawkWebSocketProxy
    http_proxy_service: WSHawkHTTPProxy
    protocol_inference: ProtocolInferenceService
    protocol_templates: ProtocolTemplateService
    protocol_graph: ProtocolGraphService
    timeline_service: TimelineService
    evidence_bundle_builder: EvidenceBundleBuilder
    evidence_exporter: EvidenceExportService
    logger: Any = field(default_factory=lambda: get_logger("gui_bridge"))
    bridge_version: str = "4.0.0"
    team: Any = None
    _browser_capture_service: Optional[BrowserCaptureService] = None
    _browser_replay_service: Optional[BrowserReplayService] = None
    _vuln_scanner: Optional[Any] = None

    def maybe_log_platform_event(
        self,
        project_id: Optional[str],
        event_type: str,
        payload: Optional[Dict[str, Any]] = None,
        direction: str = "",
        connection_id: str = "",
        target: str = "",
    ):
        """Best-effort timeline logging for project-backed workflows."""
        if not project_id:
            return None
        try:
            return self.db.add_event(
                project_id=project_id,
                event_type=event_type,
                payload=payload or {},
                direction=direction,
                connection_id=connection_id,
                target=target,
            )
        except Exception:
            return None

    def maybe_store_platform_evidence(
        self,
        project_id: Optional[str],
        title: str,
        category: str,
        payload: Optional[Dict[str, Any]] = None,
        severity: str = "info",
        related_event_id: Optional[str] = None,
    ):
        """Best-effort evidence persistence for project-backed offensive workflows."""
        if not project_id:
            return None

        try:
            return self.db.add_evidence(
                project_id=project_id,
                title=title,
                category=category,
                payload=payload or {},
                severity=severity,
                related_event_id=related_event_id,
            )
        except Exception:
            return None

    def store_identity_from_tokens(
        self,
        project_id: Optional[str],
        alias: Optional[str],
        source: str,
        cookies: Optional[List[Dict[str, Any]]] = None,
        headers: Optional[Dict[str, Any]] = None,
        session_token: Optional[str] = None,
        storage: Optional[Dict[str, Any]] = None,
    ):
        """Persist captured browser-backed auth material into the identity vault."""
        if not project_id or not alias:
            return None

        try:
            return self.identity_vault.save_auth_tokens(
                project_id=project_id,
                alias=alias,
                source=source,
                cookies=cookies or [],
                headers=headers or {},
                storage=storage or {},
                session_token=session_token,
            )
        except Exception:
            return None

    def require_platform_project(self, project_id: str) -> Dict[str, Any]:
        """Resolve a platform project or raise a clean HTTP 404."""
        project = self.db.get_project(project_id)
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        return project

    def resolve_platform_identity(
        self,
        project_id: str,
        identity_id: Optional[str] = None,
        identity_alias: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Resolve an identity by ID or alias within a project."""
        identity = None

        if identity_id:
            identity = self.db.get_identity(identity_id)
            if identity and identity.get("project_id") != project_id:
                identity = None
        elif identity_alias:
            identity = self.db.get_identity_by_alias(project_id, identity_alias)

        if (identity_id or identity_alias) and not identity:
            raise HTTPException(status_code=404, detail="Identity not found")

        return identity

    def resolve_platform_identities(
        self,
        project_id: str,
        identity_ids: Optional[List[str]] = None,
        identity_aliases: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """Resolve one or more project identities for comparison runs."""
        resolved: List[Dict[str, Any]] = []
        seen = set()

        for identity_id in identity_ids or []:
            identity = self.resolve_platform_identity(project_id, identity_id=identity_id)
            if identity and identity["id"] not in seen:
                resolved.append(identity)
                seen.add(identity["id"])

        for identity_alias in identity_aliases or []:
            identity = self.resolve_platform_identity(project_id, identity_alias=identity_alias)
            if identity and identity["id"] not in seen:
                resolved.append(identity)
                seen.add(identity["id"])

        if not resolved:
            resolved = self.db.list_identities(project_id)

        return resolved

    def get_browser_capture(self) -> BrowserCaptureService:
        if self._browser_capture_service is None:
            self._browser_capture_service = BrowserCaptureService()
            self._browser_replay_service = BrowserReplayService(self._browser_capture_service.engine)
        return self._browser_capture_service

    def get_browser_replay(self) -> BrowserReplayService:
        if self._browser_replay_service is None:
            self.get_browser_capture()
        return self._browser_replay_service
