from typing import Dict, List

from wshawk.store import ProjectStore

from .redaction import sanitize_jsonable, sanitize_mapping, sanitize_text


class TimelineService:
    """Materialize transport/evidence data into a project-centric timeline."""

    def __init__(self, store: ProjectStore):
        self.store = store

    @staticmethod
    def _attack_run_correlation(run: Dict) -> str:
        summary = run.get("summary") or {}
        parameters = run.get("parameters") or {}
        return str(
            summary.get("correlation_id")
            or parameters.get("correlation_id")
            or ""
        )

    def _build_correlation_chains(
        self,
        *,
        correlation_groups: List[Dict],
        attack_runs: List[Dict],
        findings: List[Dict],
    ) -> List[Dict]:
        chains = []
        for group in correlation_groups:
            correlation_id = group.get("correlation_id", "")
            related_runs = [
                run for run in attack_runs
                if self._attack_run_correlation(run) == correlation_id
            ]
            related_finding_ids = {run.get("id") for run in related_runs}
            related_findings = [
                finding for finding in findings
                if finding.get("attack_run_id") in related_finding_ids
            ]
            chains.append(
                {
                    "correlation_id": correlation_id,
                    "summary": group.get("summary", {}),
                    "http_urls": [item.get("url", "") for item in group.get("http_flows", [])[:8]],
                    "ws_urls": [item.get("url", "") for item in group.get("ws_connections", [])[:8]],
                    "browser_sources": [item.get("artifact_type", "") for item in group.get("browser_artifacts", [])[:8]],
                    "attack_runs": [
                        {
                            "id": run.get("id"),
                            "attack_type": run.get("attack_type"),
                            "status": run.get("status"),
                            "summary": sanitize_jsonable(run.get("summary") or {}),
                        }
                        for run in related_runs[:12]
                    ],
                    "findings": [
                        {
                            "id": finding.get("id"),
                            "title": finding.get("title"),
                            "category": finding.get("category"),
                            "severity": finding.get("severity"),
                        }
                        for finding in related_findings[:12]
                    ],
                }
            )
        return chains

    def _build_http_replay_recipes(self, http_flows: List[Dict]) -> List[Dict]:
        recipes = []
        for flow in http_flows[:24]:
            headers = sanitize_mapping(flow.get("request_headers") or {})
            body = sanitize_text(flow.get("request_body", ""))
            header_args = " ".join(f"-H '{key}: {value}'" for key, value in headers.items())
            body_arg = f" --data '{body}'" if body and flow.get("method", "GET").upper() not in {"GET", "HEAD"} else ""
            curl_command = f"curl -X {flow.get('method', 'GET').upper()} {header_args}{body_arg} '{flow.get('url', '')}'".strip()
            recipes.append(
                {
                    "type": "http",
                    "flow_id": flow.get("id"),
                    "correlation_id": flow.get("correlation_id", ""),
                    "method": flow.get("method", "GET"),
                    "url": flow.get("url", ""),
                    "headers": headers,
                    "body": body,
                    "curl": curl_command,
                }
            )
        return recipes

    def _build_ws_replay_recipes(self, ws_connections: List[Dict], ws_frames: List[Dict]) -> List[Dict]:
        frames_by_connection = {}
        for frame in ws_frames:
            frames_by_connection.setdefault(frame.get("connection_id"), []).append(frame)

        recipes = []
        for connection in ws_connections[:20]:
            frames = frames_by_connection.get(connection.get("id"), [])
            outbound_frames = [frame for frame in frames if frame.get("direction") == "out"][:6]
            recipes.append(
                {
                    "type": "websocket",
                    "connection_id": connection.get("id"),
                    "correlation_id": connection.get("correlation_id", ""),
                    "url": connection.get("url", ""),
                    "subprotocol": connection.get("subprotocol", ""),
                    "handshake_headers": sanitize_mapping(connection.get("handshake_headers") or {}),
                    "payloads": [sanitize_text(frame.get("payload_text", "")) for frame in outbound_frames],
                    "frame_count": len(outbound_frames),
                }
            )
        return recipes

    def build_project_summary(self, project_id: str, limit: int = 200) -> Dict[str, List[Dict]]:
        targets = self.store.list_targets(project_id, limit=limit)
        http_flows = self.store.list_http_flows(project_id, limit=limit)
        ws_connections = self.store.list_ws_connections(project_id, limit=limit)
        ws_frames = self.store.list_ws_frames(project_id, limit=limit)
        browser_artifacts = self.store.list_browser_artifacts(project_id, limit=limit)
        attack_runs = self.store.list_attack_runs(project_id, limit=limit)
        findings = self.store.list_findings(project_id, limit=limit)
        correlation_groups = self.store.build_correlation_groups(project_id, limit=limit)
        correlation_chains = self._build_correlation_chains(
            correlation_groups=correlation_groups,
            attack_runs=attack_runs,
            findings=findings,
        )
        replay_recipes = self._build_http_replay_recipes(http_flows) + self._build_ws_replay_recipes(ws_connections, ws_frames)

        return {
            "targets": targets,
            "http_flows": http_flows,
            "ws_connections": ws_connections,
            "ws_frames": ws_frames,
            "browser_artifacts": browser_artifacts,
            "attack_runs": attack_runs,
            "findings": findings,
            "correlation_groups": correlation_groups,
            "correlation_chains": correlation_chains,
            "replay_recipes": replay_recipes,
        }
