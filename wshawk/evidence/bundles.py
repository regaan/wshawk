import json
import re
from typing import Any, Dict, List, Tuple
from datetime import datetime

from wshawk.db_manager import WSHawkDatabase
from wshawk.evidence.timeline import TimelineService
from wshawk.evidence.redaction import sanitize_jsonable
from wshawk.store import ProjectStore


class EvidenceBundleBuilder:
    """Build exportable evidence bundles from the structured project store."""

    def __init__(self, db: WSHawkDatabase, store: ProjectStore):
        self.db = db
        self.store = store
        self.timeline = TimelineService(store)

    @staticmethod
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

    @staticmethod
    def _alias_tenants(identity_alias: str) -> List[str]:
        return [item.lower() for item in re.findall(r"tenant-[a-z0-9_-]+", identity_alias or "", re.IGNORECASE)]

    @staticmethod
    def _is_cross_tenant(alias_tenants: List[str], response_tenant: str) -> bool:
        normalized_tenant = str(response_tenant or "").strip().lower()
        return bool(alias_tenants and normalized_tenant and normalized_tenant not in alias_tenants)

    def _derive_replay_evidence(
        self,
        *,
        project_id: str,
        events: List[Dict[str, Any]],
        ws_connection_ids: List[str],
        existing_evidence: List[Dict[str, Any]],
        existing_findings: List[Dict[str, Any]],
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        existing_evidence_keys = {
            (item.get("category"), item.get("related_event_id"))
            for item in existing_evidence
        }
        existing_finding_keys = {
            (item.get("category"), item.get("attack_run_id"), item.get("title"))
            for item in existing_findings
        }
        known_connection_ids = set(ws_connection_ids)
        derived_evidence: List[Dict[str, Any]] = []
        derived_findings: List[Dict[str, Any]] = []

        for event in events:
            event_type = event.get("event_type")
            if event_type not in {"ws_platform_replay_response", "http_replay_completed"}:
                continue

            event_payload = event.get("payload") or {}
            result = event_payload.get("result") or {}
            if result.get("status") != "received":
                continue

            response_obj = self._parse_json_object(result.get("response") or result.get("body"))
            if not response_obj:
                continue

            identity_alias = str(event_payload.get("identity_alias") or result.get("identity_alias") or "")
            alias_tenants = self._alias_tenants(identity_alias)
            response_type = str(response_obj.get("type") or "").lower()
            is_http = event_type == "http_replay_completed"
            related_event_id = event.get("id")
            attack_run_id = result.get("attack_run_id")
            related_connection_id = result.get("connection_id") if result.get("connection_id") in known_connection_ids else None

            def add(category: str, title: str, severity: str, description: str) -> None:
                evidence_key = (category, related_event_id)
                finding_key = (category, attack_run_id, title)
                if evidence_key not in existing_evidence_keys:
                    derived_evidence.append(
                        {
                            "id": f"derived-evidence-{related_event_id}-{category}",
                            "project_id": project_id,
                            "title": title,
                            "category": category,
                            "severity": severity,
                            "related_event_id": related_event_id,
                            "created_at": event.get("created_at"),
                            "payload": {
                                "derived": True,
                                "result": result,
                                "response": response_obj,
                                "identity_alias": identity_alias,
                            },
                        }
                    )
                    existing_evidence_keys.add(evidence_key)
                if finding_key not in existing_finding_keys:
                    derived_findings.append(
                        {
                            "id": f"derived-finding-{related_event_id}-{category}",
                            "project_id": project_id,
                            "attack_run_id": attack_run_id,
                            "title": title,
                            "category": category,
                            "severity": severity,
                            "description": description,
                            "payload": {
                                "derived": True,
                                "result": result,
                                "response": response_obj,
                                "identity_alias": identity_alias,
                            },
                            "related_target_id": None,
                            "related_connection_id": related_connection_id,
                            "created_at": event.get("created_at"),
                        }
                    )
                    existing_finding_keys.add(finding_key)

            invoice = response_obj.get("invoice") or {}
            if is_http and not invoice and response_obj.get("id") and response_obj.get("tenant"):
                invoice = response_obj
            response_tenant = str(invoice.get("tenant") or response_obj.get("tenant") or "").strip().lower()
            leaked_token = str(invoice.get("approval_token") or response_obj.get("approval_token") or "").strip()
            category_prefix = "HTTP" if is_http else "WebSocket"

            if response_type == "invoice_snapshot" or (is_http and invoice):
                response_tenant = str(invoice.get("tenant") or response_obj.get("tenant") or "").strip().lower()
                cross_tenant = self._is_cross_tenant(alias_tenants, response_tenant)
                if cross_tenant or leaked_token:
                    add(
                        "http_data_exposure" if is_http else "websocket_data_exposure",
                        f"{category_prefix} replay exposed invoice data or approval material",
                        "high",
                        f"Identity {identity_alias or 'anonymous'} received invoice data for {response_tenant or 'an unexpected tenant'}.",
                    )
                continue

            messages = response_obj.get("messages") or []
            if response_type == "team_messages" or (is_http and response_tenant and messages):
                response_tenant = str(response_obj.get("tenant") or "").strip().lower()
                cross_tenant = self._is_cross_tenant(alias_tenants, response_tenant)
                if cross_tenant and messages:
                    add(
                        "http_data_exposure" if is_http else "websocket_data_exposure",
                        f"{category_prefix} replay exposed cross-tenant team messages",
                        "high",
                        f"Identity {identity_alias or 'anonymous'} received {len(messages)} team message(s) for {response_tenant}.",
                    )
                continue

            if (is_http or response_type in {"refund_result", "refund_processed"}) and response_obj.get("ok") and response_obj.get("approval_token_reused"):
                add(
                    "http_token_replay" if is_http else "websocket_token_replay",
                    f"{category_prefix} replay reused an approval token to authorize a refund",
                    "high",
                    f"Identity {identity_alias or 'anonymous'} successfully replayed an approval token for {response_obj.get('invoice_id', 'an invoice')}.",
                )

        return derived_evidence, derived_findings

    def build(self, project_id: str) -> Dict:
        project = self.db.get_project(project_id)
        timeline = self.timeline.build_project_summary(project_id)
        evidence = self.db.list_evidence(project_id, limit=500)
        identities = self.db.list_identities(project_id)
        events = self.db.list_events(project_id, limit=500)
        derived_evidence, derived_findings = self._derive_replay_evidence(
            project_id=project_id,
            events=events,
            ws_connection_ids=[item.get("id") for item in timeline.get("ws_connections", [])],
            existing_evidence=evidence,
            existing_findings=timeline.get("findings", []),
        )
        evidence = evidence + derived_evidence
        timeline["findings"] = list(timeline.get("findings", [])) + derived_findings
        return {
            "generated_at": datetime.now().isoformat(),
            "project": project,
            "timeline": timeline,
            "identities": identities,
            "events": events,
            "evidence": evidence,
            "notes": self.store.list_notes(project_id, limit=200),
            "statistics": {
                "identity_count": len(identities),
                "evidence_count": len(evidence),
                "http_flow_count": len(timeline.get("http_flows", [])),
                "ws_connection_count": len(timeline.get("ws_connections", [])),
                "ws_frame_count": len(timeline.get("ws_frames", [])),
                "attack_run_count": len(timeline.get("attack_runs", [])),
                "finding_count": len(timeline.get("findings", [])),
                "correlation_chain_count": len(timeline.get("correlation_chains", [])),
            },
            "sanitized_preview": {
                "replay_recipes": sanitize_jsonable(timeline.get("replay_recipes", [])),
                "correlation_chains": sanitize_jsonable(timeline.get("correlation_chains", [])),
            },
        }
