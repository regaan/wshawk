"""HTTP/browser/WebSocket correlation behavior for :class:`ProjectStore`."""

import base64
import json
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse


class ProjectCorrelationMixin:
    @staticmethod
    def _extract_host(url: str) -> str:
        if not url:
            return ""
        try:
            return (urlparse(url).hostname or "").lower()
        except (TypeError, ValueError):
            return ""

    @staticmethod
    def _find_header(headers: Dict[str, Any], name: str) -> str:
        lowered = name.lower()
        for key, value in (headers or {}).items():
            if str(key).lower() == lowered:
                return str(value)
        return ""

    def _score_http_flow_match(
        self,
        flow: Dict[str, Any],
        candidate_urls: List[str],
        candidate_hosts: List[str],
    ) -> Dict[str, Any]:
        score = 0
        reasons: List[str] = []
        flow_url = flow.get("url", "")
        flow_host = self._extract_host(flow_url)
        request_headers = flow.get("request_headers") or {}
        request_origin = self._extract_host(self._find_header(request_headers, "origin"))
        request_referer = self._extract_host(self._find_header(request_headers, "referer"))

        if flow_host and flow_host in candidate_hosts:
            score += 6
            reasons.append(f"http-host:{flow_host}")

        if request_origin and request_origin in candidate_hosts:
            score += 4
            reasons.append(f"http-origin:{request_origin}")

        if request_referer and request_referer in candidate_hosts:
            score += 4
            reasons.append(f"http-referer:{request_referer}")

        if any(candidate and (flow_url.startswith(candidate) or candidate.startswith(flow_url)) for candidate in candidate_urls):
            score += 3
            reasons.append("http-url-prefix")

        if flow.get("correlation_id"):
            score += 2
            reasons.append("http-existing-correlation")

        try:
            created_at = datetime.fromisoformat(flow.get("created_at", ""))
            age_seconds = (datetime.now() - created_at).total_seconds()
            if age_seconds <= 120:
                score += 3
                reasons.append("http-recent")
            elif age_seconds <= 600:
                score += 1
                reasons.append("http-seen-this-session")
        except (TypeError, ValueError):
            # Missing or malformed timestamps simply do not receive a recency score.
            pass

        return {"score": score, "reasons": reasons}

    def _score_browser_artifact_match(
        self,
        artifact: Dict[str, Any],
        ws_url: str,
        candidate_urls: List[str],
        candidate_hosts: List[str],
    ) -> Dict[str, Any]:
        score = 0
        reasons: List[str] = []
        payload = artifact.get("payload") or {}
        artifact_urls = [
            artifact.get("url", ""),
            payload.get("target_ws_url", ""),
            payload.get("login_url", ""),
            payload.get("page_url", ""),
            payload.get("target_url", ""),
        ]

        if any(candidate and candidate == ws_url for candidate in artifact_urls):
            score += 8
            reasons.append("artifact-exact-ws-url")

        artifact_hosts = {self._extract_host(candidate) for candidate in artifact_urls if candidate}
        artifact_hosts.discard("")
        shared_hosts = sorted(artifact_hosts.intersection(candidate_hosts))
        if shared_hosts:
            score += 5
            reasons.append(f"artifact-host:{shared_hosts[0]}")

        if artifact.get("artifact_type") in {"auth_flow_recorded", "auth_flow_replayed", "ws_handshake"}:
            score += 2
            reasons.append(f"artifact-type:{artifact.get('artifact_type')}")

        if payload.get("correlation_id"):
            score += 2
            reasons.append("artifact-existing-correlation")

        try:
            created_at = datetime.fromisoformat(artifact.get("created_at", ""))
            age_seconds = (datetime.now() - created_at).total_seconds()
            if age_seconds <= 300:
                score += 2
                reasons.append("artifact-recent")
        except (TypeError, ValueError):
            # Missing or malformed timestamps simply do not receive a recency score.
            pass

        return {"score": score, "reasons": reasons}

    def update_http_flow_correlation(self, flow_id: str, correlation_id: str) -> Optional[Dict[str, Any]]:
        correlation_id = str(correlation_id or "").strip()
        if not correlation_id:
            return None

        conn = self._get_conn()
        try:
            row = conn.execute("SELECT * FROM http_flows WHERE id = ?", (flow_id,)).fetchone()
            if not row:
                return None
            conn.execute(
                "UPDATE http_flows SET correlation_id = ? WHERE id = ?",
                (correlation_id, flow_id),
            )
            conn.commit()
            row = conn.execute("SELECT * FROM http_flows WHERE id = ?", (flow_id,)).fetchone()
            return self._row_to_http_flow(row) if row else None
        finally:
            conn.close()

    def update_browser_artifact_payload(
        self,
        artifact_id: str,
        payload_updates: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        conn = self._get_conn()
        try:
            row = conn.execute("SELECT * FROM browser_artifacts WHERE id = ?", (artifact_id,)).fetchone()
            if not row:
                return None
            artifact = self._row_to_browser_artifact(row)
            payload = artifact.get("payload") or {}
            payload.update(payload_updates or {})
            conn.execute(
                "UPDATE browser_artifacts SET payload_json = ? WHERE id = ?",
                (self._dump_sensitive_json(payload), artifact_id),
            )
            conn.commit()
            row = conn.execute("SELECT * FROM browser_artifacts WHERE id = ?", (artifact_id,)).fetchone()
            return self._row_to_browser_artifact(row) if row else None
        finally:
            conn.close()

    def correlate_ws_handshake(
        self,
        project_id: str,
        ws_url: str,
        handshake_headers: Optional[Dict[str, Any]] = None,
        limit: int = 80,
    ) -> Dict[str, Any]:
        handshake_headers = handshake_headers or {}
        candidate_urls = [
            ws_url,
            self._find_header(handshake_headers, "origin"),
            self._find_header(handshake_headers, "referer"),
        ]
        candidate_urls = [candidate.strip() for candidate in candidate_urls if str(candidate).strip()]
        candidate_hosts = sorted({self._extract_host(candidate) for candidate in candidate_urls if self._extract_host(candidate)})

        if not candidate_hosts and not candidate_urls:
            return {
                "correlation_id": "",
                "http_flow_id": None,
                "browser_artifact_id": None,
                "reasons": [],
                "candidate_hosts": [],
            }

        conn = self._get_conn()
        try:
            http_rows = conn.execute(
                "SELECT * FROM http_flows WHERE project_id = ? ORDER BY created_at DESC LIMIT ?",
                (project_id, limit),
            ).fetchall()
            artifact_rows = conn.execute(
                "SELECT * FROM browser_artifacts WHERE project_id = ? ORDER BY created_at DESC LIMIT ?",
                (project_id, limit),
            ).fetchall()

            best_http: Optional[Dict[str, Any]] = None
            best_http_score = 0
            best_http_reasons: List[str] = []
            for row in http_rows:
                flow = self._row_to_http_flow(row)
                scored = self._score_http_flow_match(flow, candidate_urls, candidate_hosts)
                if scored["score"] > best_http_score:
                    best_http = flow
                    best_http_score = scored["score"]
                    best_http_reasons = scored["reasons"]

            best_artifact: Optional[Dict[str, Any]] = None
            best_artifact_score = 0
            best_artifact_reasons: List[str] = []
            for row in artifact_rows:
                artifact = self._row_to_browser_artifact(row)
                scored = self._score_browser_artifact_match(artifact, ws_url, candidate_urls, candidate_hosts)
                if scored["score"] > best_artifact_score:
                    best_artifact = artifact
                    best_artifact_score = scored["score"]
                    best_artifact_reasons = scored["reasons"]

            correlation_id = ""
            if best_http and best_http.get("correlation_id"):
                correlation_id = best_http["correlation_id"]
            elif best_artifact and (best_artifact.get("payload") or {}).get("correlation_id"):
                correlation_id = (best_artifact.get("payload") or {}).get("correlation_id", "")
            elif best_http_score >= 5 or best_artifact_score >= 5:
                correlation_id = f"corr-{uuid.uuid4().hex[:16]}"

            if correlation_id and best_http and not best_http.get("correlation_id"):
                conn.execute(
                    "UPDATE http_flows SET correlation_id = ? WHERE id = ?",
                    (correlation_id, best_http["id"]),
                )

            if correlation_id and best_artifact:
                payload = best_artifact.get("payload") or {}
                if payload.get("correlation_id") != correlation_id or payload.get("linked_ws_url") != ws_url:
                    payload["correlation_id"] = correlation_id
                    payload["linked_ws_url"] = ws_url
                    conn.execute(
                        "UPDATE browser_artifacts SET payload_json = ? WHERE id = ?",
                        (self._dump_sensitive_json(payload), best_artifact["id"]),
                    )

            if correlation_id:
                conn.commit()

            return {
                "correlation_id": correlation_id,
                "http_flow_id": best_http["id"] if best_http and best_http_score > 0 else None,
                "browser_artifact_id": best_artifact["id"] if best_artifact and best_artifact_score > 0 else None,
                "reasons": best_http_reasons + best_artifact_reasons,
                "candidate_hosts": candidate_hosts,
            }
        finally:
            conn.close()

    def build_correlation_groups(self, project_id: str, limit: int = 200) -> List[Dict[str, Any]]:
        groups: Dict[str, Dict[str, Any]] = {}

        for flow in self.list_http_flows(project_id, limit=limit):
            correlation_id = flow.get("correlation_id", "")
            if not correlation_id:
                continue
            group = groups.setdefault(
                correlation_id,
                {"correlation_id": correlation_id, "http_flows": [], "ws_connections": [], "browser_artifacts": []},
            )
            group["http_flows"].append(flow)

        for connection in self.list_ws_connections(project_id, limit=limit):
            correlation_id = connection.get("correlation_id", "")
            if not correlation_id:
                continue
            group = groups.setdefault(
                correlation_id,
                {"correlation_id": correlation_id, "http_flows": [], "ws_connections": [], "browser_artifacts": []},
            )
            group["ws_connections"].append(connection)

        for artifact in self.list_browser_artifacts(project_id, limit=limit):
            correlation_id = (artifact.get("payload") or {}).get("correlation_id", "")
            if not correlation_id:
                continue
            group = groups.setdefault(
                correlation_id,
                {"correlation_id": correlation_id, "http_flows": [], "ws_connections": [], "browser_artifacts": []},
            )
            group["browser_artifacts"].append(artifact)

        def latest_timestamp(group: Dict[str, Any]) -> str:
            candidates = []
            for key in ("http_flows", "ws_connections", "browser_artifacts"):
                for item in group.get(key, []):
                    candidates.append(
                        item.get("created_at")
                        or item.get("opened_at")
                        or item.get("updated_at")
                        or ""
                    )
            return max(candidates) if candidates else ""

        ordered = []
        for group in groups.values():
            group["summary"] = {
                "http_flow_count": len(group["http_flows"]),
                "ws_connection_count": len(group["ws_connections"]),
                "browser_artifact_count": len(group["browser_artifacts"]),
            }
            group["latest_at"] = latest_timestamp(group)
            ordered.append(group)

        return sorted(ordered, key=lambda item: item.get("latest_at", ""), reverse=True)



__all__ = ["ProjectCorrelationMixin"]
