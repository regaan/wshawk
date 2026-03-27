import json
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from wshawk.attacks.workflows import WorkflowExecutionService
from wshawk.store import ProjectStore

from .inference import ProtocolInferenceService
from .target_packs import ProtocolTargetPackRegistry
from .templates import ProtocolTemplateService


class ProtocolGraphService:
    """Build a project-backed protocol graph from normalized WS traffic."""

    ACTION_KEYS = ("action", "type", "event", "op")

    def __init__(
        self,
        store: ProjectStore,
        inference: Optional[ProtocolInferenceService] = None,
        templates: Optional[ProtocolTemplateService] = None,
        target_packs: Optional[ProtocolTargetPackRegistry] = None,
    ):
        self.store = store
        self.inference = inference or ProtocolInferenceService()
        self.templates = templates or ProtocolTemplateService()
        self.target_packs = target_packs or ProtocolTargetPackRegistry()

    @staticmethod
    def _safe_hostname(url: str) -> str:
        try:
            return urlparse(url).hostname or ""
        except Exception:
            return ""

    def _extract_family(self, payload_text: str, opcode: str) -> Dict[str, Any]:
        payload_text = payload_text or ""
        try:
            parsed = json.loads(payload_text)
        except Exception:
            parsed = None

        family = f"{opcode}_message"
        fields: List[str] = []
        auth_fields: List[str] = []
        identifiers: List[str] = []

        if isinstance(parsed, dict):
            for key in self.ACTION_KEYS:
                if parsed.get(key):
                    family = str(parsed[key])
                    break
            fields = sorted(parsed.keys())
            auth_fields = sorted(
                key for key in parsed.keys() if "auth" in key.lower() or "token" in key.lower()
            )
            identifiers = sorted(
                key
                for key in parsed.keys()
                if key.lower().endswith("id") or "tenant" in key.lower() or "channel" in key.lower()
            )

        return {
            "family": family,
            "fields": fields,
            "auth_fields": auth_fields,
            "identifier_fields": identifiers,
            "sample": parsed if isinstance(parsed, dict) else payload_text[:240],
        }

    @staticmethod
    def _build_recommendations(message_families: List[Dict[str, Any]], transitions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        recommendations: List[Dict[str, Any]] = []
        family_names = [str(item.get("name", "")).lower() for item in message_families]
        fields = {
            field.lower()
            for item in message_families
            for field in (item.get("fields") or [])
        }
        identifier_fields = {
            field.lower()
            for item in message_families
            for field in (item.get("identifier_fields") or [])
        }
        auth_fields = {
            field.lower()
            for item in message_families
            for field in (item.get("auth_fields") or [])
        }

        if any(token in name for name in family_names for token in ("subscribe", "channel", "topic", "join", "stream")):
            recommendations.append(
                {
                    "id": "subscription_abuse",
                    "title": "Subscription / channel abuse",
                    "reason": "Captured traffic includes subscription-like message families that are good candidates for channel, tenant, or object tampering.",
                }
            )

        if identifier_fields:
            recommendations.append(
                {
                    "id": "identifier_tamper",
                    "title": "Identifier / tenant tampering",
                    "reason": f"Observed identifier fields: {', '.join(sorted(identifier_fields)[:8])}. Replay these with alternate object, tenant, or user values.",
                }
            )

        if auth_fields or any(token in name for name in family_names for token in ("auth", "login", "token", "session")):
            recommendations.append(
                {
                    "id": "authz_diff",
                    "title": "Role diff and token replay",
                    "reason": "The protocol exposes auth-related fields or flows, making role-aware replay and authorization drift checks high value.",
                }
            )

        if transitions:
            recommendations.append(
                {
                    "id": "workflow_capture",
                    "title": "Workflow chaining",
                    "reason": "Observed message transitions can be replayed as chained workflows to preserve state and sequencing.",
                }
            )

        if len(message_families) >= 2:
            recommendations.append(
                {
                    "id": "race_attack",
                    "title": "Duplicate action / race window",
                    "reason": "Multiple live message families and transitions make the target a candidate for replay-before-invalidation and parallel socket abuse.",
                }
            )

        return recommendations[:6]

    @staticmethod
    def _build_playbook_candidates(
        recommended_attacks: List[Dict[str, Any]],
        target_packs: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        catalog = {item["id"]: item for item in WorkflowExecutionService.list_playbooks()}
        candidates: List[Dict[str, Any]] = []
        pack_ids = {pack.get("id") for pack in target_packs}
        recommended_ids = {item.get("id") for item in recommended_attacks}

        def add_candidate(playbook_id: str, reason: str):
            playbook = catalog.get(playbook_id)
            if not playbook or any(item["id"] == playbook_id for item in candidates):
                return
            candidates.append(
                {
                    "id": playbook_id,
                    "title": playbook.get("title", playbook_id),
                    "description": playbook.get("description", ""),
                    "reason": reason,
                }
            )

        if "authz_diff" in recommended_ids:
            add_candidate("tenant_hopping", "Role/tenant drift was recommended by the protocol graph.")
        if "workflow_capture" in recommended_ids:
            add_candidate("login_bootstrap", "Observed transitions look suitable for bootstrap-oriented replay workflows.")
        if "race_attack" in recommended_ids:
            add_candidate("stale_token_reuse", "Transitions and attack recommendations suggest replay-window or race-value checks.")
        if {"graphql_ws", "socket_io", "phoenix_channels", "actioncable", "signalr"} & pack_ids:
            add_candidate("ws_privilege_escalation", "Framework-specific realtime traffic was detected, making WS privilege replay valuable.")
        if "generic_realtime" in pack_ids:
            add_candidate("http_replay", "Structured HTTP/WS traffic was observed and can be replayed as a workflow.")

        return candidates[:6]

    def build_project_map(self, project_id: str, limit: int = 500) -> Dict[str, Any]:
        connections = self.store.list_ws_connections(project_id, limit=limit)
        frames = list(reversed(self.store.list_ws_frames(project_id, limit=limit)))
        correlation_groups = self.store.build_correlation_groups(project_id, limit=limit)
        findings = self.store.list_findings(project_id, limit=limit)
        protocol_summary = self.inference.learn(frames) if frames else {}
        templates = self.templates.build_templates(frames) if frames else []

        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, Any]] = []
        node_index: Dict[str, Dict[str, Any]] = {}
        edge_counts: Counter = Counter()
        transition_counts: Counter = Counter()
        family_counts: Counter = Counter()
        family_samples: Dict[str, Dict[str, Any]] = {}
        connection_frames: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

        def add_node(node_id: str, node_type: str, label: str, meta: Optional[Dict[str, Any]] = None):
            if node_id in node_index:
                existing = node_index[node_id]
                if meta:
                    existing.setdefault("meta", {}).update(meta)
                return
            node = {"id": node_id, "type": node_type, "label": label, "meta": meta or {}}
            node_index[node_id] = node
            nodes.append(node)

        for group in correlation_groups:
            node_id = f"corr:{group['correlation_id']}"
            add_node(
                node_id,
                "correlation",
                group["correlation_id"],
                {
                    "http_flow_count": len(group.get("http_flows", [])),
                    "ws_connection_count": len(group.get("ws_connections", [])),
                    "browser_artifact_count": len(group.get("browser_artifacts", [])),
                },
            )

        for connection in connections:
            host = self._safe_hostname(connection.get("url", ""))
            connection_label = connection.get("subprotocol") or host or connection.get("url", "")
            metadata = connection.get("metadata") or {}
            node_id = f"conn:{connection['id']}"
            add_node(
                node_id,
                "connection",
                connection_label,
                {
                    "url": connection.get("url", ""),
                    "state": connection.get("state", ""),
                    "subprotocol": connection.get("subprotocol", ""),
                    "correlation_id": connection.get("correlation_id", ""),
                    "accepted_subprotocol": metadata.get("accepted_subprotocol", ""),
                    "compression_enabled": bool(metadata.get("compression_enabled")),
                    "requested_extensions": metadata.get("requested_extensions", []),
                    "accepted_extensions": metadata.get("accepted_extensions", []),
                },
            )
            if connection.get("correlation_id"):
                edge_counts[(f"corr:{connection['correlation_id']}", node_id, "correlates")] += 1

        for frame in frames:
            info = self._extract_family(frame.get("payload_text", ""), frame.get("opcode", "text"))
            family = info["family"]
            family_counts[family] += 1
            family_samples.setdefault(family, info)
            connection_id = frame.get("connection_id") or "unbound"
            connection_frames[connection_id].append({"frame": frame, "family": family})

        for family, count in family_counts.items():
            info = family_samples.get(family, {})
            add_node(
                f"family:{family}",
                "message_family",
                family,
                {
                    "count": count,
                    "fields": info.get("fields", []),
                    "auth_fields": info.get("auth_fields", []),
                    "identifier_fields": info.get("identifier_fields", []),
                    "sample": info.get("sample"),
                },
            )

        for connection_id, items in connection_frames.items():
            previous_family = None
            connection_node_id = f"conn:{connection_id}" if connection_id != "unbound" else "conn:unbound"
            if connection_node_id == "conn:unbound":
                add_node(connection_node_id, "connection", "unbound", {"state": "unknown"})

            for item in items:
                family_node_id = f"family:{item['family']}"
                edge_counts[(connection_node_id, family_node_id, item["frame"].get("direction", "flow"))] += 1
                if previous_family:
                    transition_counts[(previous_family, item["family"])] += 1
                previous_family = item["family"]

        for (source, target, label), count in edge_counts.items():
            edges.append({"source": source, "target": target, "label": label, "count": count})

        transitions = []
        for (source_family, target_family), count in transition_counts.most_common(50):
            transitions.append(
                {
                    "source": source_family,
                    "target": target_family,
                    "count": count,
                }
            )
            edges.append(
                {
                    "source": f"family:{source_family}",
                    "target": f"family:{target_family}",
                    "label": "transition",
                    "count": count,
                }
            )

        message_families = [
            {
                "name": family,
                "count": count,
                "fields": family_samples.get(family, {}).get("fields", []),
                "auth_fields": family_samples.get(family, {}).get("auth_fields", []),
                "identifier_fields": family_samples.get(family, {}).get("identifier_fields", []),
                "sample": family_samples.get(family, {}).get("sample"),
            }
            for family, count in family_counts.most_common(50)
        ]
        recommended_attacks = self._build_recommendations(message_families, transitions)
        finding_categories = Counter(finding.get("category", "unknown") for finding in findings)
        target_packs = self.target_packs.detect(connections, frames)
        playbook_candidates = self._build_playbook_candidates(recommended_attacks, target_packs)

        return {
            "summary": {
                "connection_count": len(connections),
                "frame_count": len(frames),
                "family_count": len(message_families),
                "correlation_group_count": len(correlation_groups),
                "transition_count": len(transitions),
                "finding_count": len(findings),
            },
            "protocol_summary": protocol_summary,
            "templates": templates,
            "message_families": message_families,
            "transitions": transitions,
            "nodes": nodes,
            "edges": edges,
            "correlation_groups": correlation_groups,
            "recommended_attacks": recommended_attacks,
            "playbook_candidates": playbook_candidates,
            "finding_categories": dict(finding_categories),
            "target_packs": target_packs,
        }
