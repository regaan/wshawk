import base64
import json
import sqlite3
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from wshawk.db_manager import WSHawkDatabase


class ProjectStore:
    """Structured project persistence for transport, sessions, and attack runs."""

    def __init__(self, db: Optional[WSHawkDatabase] = None):
        self.db = db or WSHawkDatabase()
        self._init_schema()

    def _get_conn(self) -> sqlite3.Connection:
        return self.db._get_conn()

    def _dump_sensitive_json(self, value: Any) -> str:
        return self.db.sensitive_cipher.dump_json(value)

    def _load_sensitive_json(self, raw: Any, default: Any) -> Any:
        return self.db.sensitive_cipher.load_json(raw, default)

    def _encrypt_text(self, value: Any) -> str:
        return self.db.sensitive_cipher.encrypt_text(value)

    def _decrypt_text(self, value: Any) -> str:
        return self.db.sensitive_cipher.decrypt_text(value)

    def _init_schema(self):
        conn = self._get_conn()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS targets (
                    id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    url TEXT NOT NULL,
                    host TEXT DEFAULT '',
                    scheme TEXT DEFAULT '',
                    kind TEXT DEFAULT 'generic',
                    metadata_json TEXT DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
                );

                CREATE UNIQUE INDEX IF NOT EXISTS idx_targets_project_url
                    ON targets(project_id, url);

                CREATE TABLE IF NOT EXISTS http_flows (
                    id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    target_id TEXT,
                    correlation_id TEXT DEFAULT '',
                    attack_run_id TEXT,
                    method TEXT NOT NULL,
                    url TEXT NOT NULL,
                    request_headers_json TEXT DEFAULT '{}',
                    request_body TEXT DEFAULT '',
                    response_status TEXT DEFAULT '',
                    response_headers_json TEXT DEFAULT '{}',
                    response_body TEXT DEFAULT '',
                    error TEXT DEFAULT '',
                    metadata_json TEXT DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE,
                    FOREIGN KEY(target_id) REFERENCES targets(id) ON DELETE SET NULL
                );

                CREATE INDEX IF NOT EXISTS idx_http_flows_project_created
                    ON http_flows(project_id, created_at DESC);

                CREATE TABLE IF NOT EXISTS ws_connections (
                    id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    target_id TEXT,
                    correlation_id TEXT DEFAULT '',
                    attack_run_id TEXT,
                    url TEXT NOT NULL,
                    handshake_headers_json TEXT DEFAULT '{}',
                    subprotocol TEXT DEFAULT '',
                    extensions_json TEXT DEFAULT '[]',
                    state TEXT DEFAULT 'open',
                    metadata_json TEXT DEFAULT '{}',
                    opened_at TEXT NOT NULL,
                    closed_at TEXT,
                    FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE,
                    FOREIGN KEY(target_id) REFERENCES targets(id) ON DELETE SET NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ws_connections_project_opened
                    ON ws_connections(project_id, opened_at DESC);

                CREATE TABLE IF NOT EXISTS ws_frames (
                    id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    connection_id TEXT,
                    direction TEXT DEFAULT '',
                    opcode TEXT DEFAULT 'text',
                    is_binary INTEGER DEFAULT 0,
                    payload_text TEXT DEFAULT '',
                    payload_base64 TEXT DEFAULT '',
                    payload_size INTEGER DEFAULT 0,
                    metadata_json TEXT DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE,
                    FOREIGN KEY(connection_id) REFERENCES ws_connections(id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_ws_frames_connection_created
                    ON ws_frames(connection_id, created_at DESC);

                CREATE TABLE IF NOT EXISTS browser_artifacts (
                    id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    identity_id TEXT,
                    artifact_type TEXT NOT NULL,
                    source TEXT DEFAULT '',
                    url TEXT DEFAULT '',
                    payload_json TEXT DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE,
                    FOREIGN KEY(identity_id) REFERENCES identities(id) ON DELETE SET NULL
                );

                CREATE INDEX IF NOT EXISTS idx_browser_artifacts_project_created
                    ON browser_artifacts(project_id, created_at DESC);

                CREATE TABLE IF NOT EXISTS attack_runs (
                    id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    attack_type TEXT NOT NULL,
                    target_id TEXT,
                    identity_id TEXT,
                    status TEXT DEFAULT 'running',
                    parameters_json TEXT DEFAULT '{}',
                    summary_json TEXT DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    completed_at TEXT,
                    FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE,
                    FOREIGN KEY(target_id) REFERENCES targets(id) ON DELETE SET NULL,
                    FOREIGN KEY(identity_id) REFERENCES identities(id) ON DELETE SET NULL
                );

                CREATE INDEX IF NOT EXISTS idx_attack_runs_project_created
                    ON attack_runs(project_id, created_at DESC);

                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    attack_run_id TEXT,
                    title TEXT NOT NULL,
                    category TEXT DEFAULT '',
                    severity TEXT DEFAULT 'info',
                    description TEXT DEFAULT '',
                    payload_json TEXT DEFAULT '{}',
                    related_target_id TEXT,
                    related_connection_id TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE,
                    FOREIGN KEY(attack_run_id) REFERENCES attack_runs(id) ON DELETE SET NULL,
                    FOREIGN KEY(related_target_id) REFERENCES targets(id) ON DELETE SET NULL,
                    FOREIGN KEY(related_connection_id) REFERENCES ws_connections(id) ON DELETE SET NULL
                );

                CREATE INDEX IF NOT EXISTS idx_findings_project_created
                    ON findings(project_id, created_at DESC);

                CREATE TABLE IF NOT EXISTS notes (
                    id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    body TEXT DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_notes_project_updated
                    ON notes(project_id, updated_at DESC);
                """
            )
            conn.commit()
        finally:
            conn.close()

    def _touch_project(self, conn: sqlite3.Connection, project_id: str, updated_at: Optional[str] = None):
        conn.execute(
            "UPDATE projects SET updated_at = ? WHERE id = ?",
            (updated_at or datetime.now().isoformat(), project_id),
        )

    def ensure_target(
        self,
        project_id: str,
        url: str,
        kind: str = "generic",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        if not url:
            return None

        now = datetime.now().isoformat()
        parsed = urlparse(url)
        host = parsed.netloc or parsed.path
        scheme = parsed.scheme
        metadata = metadata or {}

        conn = self._get_conn()
        try:
            existing = conn.execute(
                "SELECT id FROM targets WHERE project_id = ? AND url = ?",
                (project_id, url),
            ).fetchone()
            if existing:
                target_id = existing["id"]
                conn.execute(
                    """
                    UPDATE targets
                       SET host = ?, scheme = ?, kind = ?, metadata_json = ?, updated_at = ?
                     WHERE id = ?
                    """,
                    (host, scheme, kind, json.dumps(metadata), now, target_id),
                )
            else:
                target_id = str(uuid.uuid4())
                conn.execute(
                    """
                    INSERT INTO targets (id, project_id, url, host, scheme, kind, metadata_json, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (target_id, project_id, url, host, scheme, kind, json.dumps(metadata), now, now),
                )
            self._touch_project(conn, project_id, now)
            conn.commit()
            row = conn.execute("SELECT * FROM targets WHERE id = ?", (target_id,)).fetchone()
            return self._row_to_target(row) if row else None
        finally:
            conn.close()

    def get_target(self, target_id: str) -> Optional[Dict[str, Any]]:
        conn = self._get_conn()
        try:
            row = conn.execute("SELECT * FROM targets WHERE id = ?", (target_id,)).fetchone()
            return self._row_to_target(row) if row else None
        finally:
            conn.close()

    def list_targets(self, project_id: str, limit: int = 200) -> List[Dict[str, Any]]:
        conn = self._get_conn()
        try:
            rows = conn.execute(
                "SELECT * FROM targets WHERE project_id = ? ORDER BY updated_at DESC LIMIT ?",
                (project_id, limit),
            ).fetchall()
            return [self._row_to_target(row) for row in rows]
        finally:
            conn.close()

    def add_http_flow(
        self,
        project_id: str,
        method: str,
        url: str,
        request_headers: Optional[Dict[str, Any]] = None,
        request_body: str = "",
        response_status: str = "",
        response_headers: Optional[Dict[str, Any]] = None,
        response_body: str = "",
        error: str = "",
        correlation_id: str = "",
        attack_run_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        target = self.ensure_target(project_id, url, kind="http")
        flow_id = str(uuid.uuid4())
        created_at = datetime.now().isoformat()
        request_headers = request_headers or {}
        response_headers = response_headers or {}
        metadata = metadata or {}

        conn = self._get_conn()
        try:
            conn.execute(
                """
                INSERT INTO http_flows (
                    id, project_id, target_id, correlation_id, attack_run_id, method, url,
                    request_headers_json, request_body, response_status, response_headers_json,
                    response_body, error, metadata_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    flow_id,
                    project_id,
                    target["id"] if target else None,
                    correlation_id,
                    attack_run_id,
                    method,
                    url,
                    self._dump_sensitive_json(request_headers),
                    self._encrypt_text(request_body),
                    response_status,
                    self._dump_sensitive_json(response_headers),
                    self._encrypt_text(response_body),
                    self._encrypt_text(error),
                    self._dump_sensitive_json(metadata),
                    created_at,
                ),
            )
            self._touch_project(conn, project_id, created_at)
            conn.commit()
            row = conn.execute("SELECT * FROM http_flows WHERE id = ?", (flow_id,)).fetchone()
            return self._row_to_http_flow(row) if row else {}
        finally:
            conn.close()

    def list_http_flows(self, project_id: str, limit: int = 200) -> List[Dict[str, Any]]:
        conn = self._get_conn()
        try:
            rows = conn.execute(
                "SELECT * FROM http_flows WHERE project_id = ? ORDER BY created_at DESC LIMIT ?",
                (project_id, limit),
            ).fetchall()
            return [self._row_to_http_flow(row) for row in rows]
        finally:
            conn.close()

    def get_http_flow(self, flow_id: str) -> Optional[Dict[str, Any]]:
        conn = self._get_conn()
        try:
            row = conn.execute("SELECT * FROM http_flows WHERE id = ?", (flow_id,)).fetchone()
            return self._row_to_http_flow(row) if row else None
        finally:
            conn.close()

    @staticmethod
    def _extract_host(url: str) -> str:
        if not url:
            return ""
        try:
            return (urlparse(url).hostname or "").lower()
        except Exception:
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
        except Exception:
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
        except Exception:
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

    def open_ws_connection(
        self,
        project_id: str,
        url: str,
        handshake_headers: Optional[Dict[str, Any]] = None,
        correlation_id: str = "",
        attack_run_id: Optional[str] = None,
        subprotocol: str = "",
        extensions: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        target = self.ensure_target(project_id, url, kind="websocket")
        connection_id = str(uuid.uuid4())
        opened_at = datetime.now().isoformat()
        metadata = metadata or {}
        correlation_context = {}
        if not correlation_id:
            correlation_context = self.correlate_ws_handshake(
                project_id=project_id,
                ws_url=url,
                handshake_headers=handshake_headers,
            )
            correlation_id = correlation_context.get("correlation_id", "")
        if correlation_context:
            metadata = {**metadata, "correlation_context": correlation_context}
        conn = self._get_conn()
        try:
            conn.execute(
                """
                INSERT INTO ws_connections (
                    id, project_id, target_id, correlation_id, attack_run_id, url,
                    handshake_headers_json, subprotocol, extensions_json, state, metadata_json, opened_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?)
                """,
                (
                    connection_id,
                    project_id,
                    target["id"] if target else None,
                    correlation_id,
                    attack_run_id,
                    url,
                    self._dump_sensitive_json(handshake_headers or {}),
                    subprotocol,
                    json.dumps(extensions or []),
                    self._dump_sensitive_json(metadata),
                    opened_at,
                ),
            )
            self._touch_project(conn, project_id, opened_at)
            conn.commit()
            row = conn.execute("SELECT * FROM ws_connections WHERE id = ?", (connection_id,)).fetchone()
            return self._row_to_ws_connection(row) if row else {}
        finally:
            conn.close()

    def close_ws_connection(
        self,
        connection_id: str,
        state: str = "closed",
        subprotocol: Optional[str] = None,
        extensions: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        conn = self._get_conn()
        try:
            existing = conn.execute(
                "SELECT project_id, metadata_json FROM ws_connections WHERE id = ?",
                (connection_id,),
            ).fetchone()
            if not existing:
                return None

            merged_metadata = self._load_sensitive_json(existing["metadata_json"], {})
            if metadata:
                merged_metadata.update(metadata)

            now = datetime.now().isoformat()
            closed_at = now if state != "open" else None
            if subprotocol is None:
                row = conn.execute("SELECT subprotocol FROM ws_connections WHERE id = ?", (connection_id,)).fetchone()
                subprotocol = row["subprotocol"] if row else ""

            conn.execute(
                """
                UPDATE ws_connections
                   SET state = ?, subprotocol = ?, extensions_json = ?, metadata_json = ?, closed_at = ?
                 WHERE id = ?
                """,
                (state, subprotocol or "", json.dumps(extensions or []), self._dump_sensitive_json(merged_metadata), closed_at, connection_id),
            )
            self._touch_project(conn, existing["project_id"], now)
            conn.commit()
            row = conn.execute("SELECT * FROM ws_connections WHERE id = ?", (connection_id,)).fetchone()
            return self._row_to_ws_connection(row) if row else None
        finally:
            conn.close()

    def add_ws_frame(
        self,
        project_id: str,
        connection_id: Optional[str],
        direction: str,
        payload: Any,
        opcode: str = "text",
        is_binary: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        frame_id = str(uuid.uuid4())
        created_at = datetime.now().isoformat()
        payload_text = ""
        payload_base64 = ""
        payload_size = 0

        if is_binary:
            if isinstance(payload, bytes):
                payload_bytes = payload
            elif isinstance(payload, str):
                payload_bytes = payload.encode("utf-8", errors="replace")
            else:
                payload_bytes = bytes(payload)
            payload_text = payload_bytes.decode("utf-8", errors="replace")
            payload_base64 = base64.b64encode(payload_bytes).decode("ascii")
            payload_size = len(payload_bytes)
        else:
            payload_text = payload if isinstance(payload, str) else json.dumps(payload)
            payload_size = len(payload_text)

        conn = self._get_conn()
        try:
            conn.execute(
                """
                INSERT INTO ws_frames (
                    id, project_id, connection_id, direction, opcode, is_binary,
                    payload_text, payload_base64, payload_size, metadata_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    frame_id,
                    project_id,
                    connection_id,
                    direction,
                    opcode,
                    1 if is_binary else 0,
                    self._encrypt_text(payload_text),
                    self._encrypt_text(payload_base64),
                    payload_size,
                    self._dump_sensitive_json(metadata or {}),
                    created_at,
                ),
            )
            self._touch_project(conn, project_id, created_at)
            conn.commit()
            row = conn.execute("SELECT * FROM ws_frames WHERE id = ?", (frame_id,)).fetchone()
            return self._row_to_ws_frame(row) if row else {}
        finally:
            conn.close()

    def list_ws_frames(
        self,
        project_id: str,
        connection_id: Optional[str] = None,
        limit: int = 500,
    ) -> List[Dict[str, Any]]:
        conn = self._get_conn()
        try:
            if connection_id:
                rows = conn.execute(
                    """
                    SELECT * FROM ws_frames
                     WHERE project_id = ? AND connection_id = ?
                     ORDER BY created_at DESC
                     LIMIT ?
                    """,
                    (project_id, connection_id, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM ws_frames WHERE project_id = ? ORDER BY created_at DESC LIMIT ?",
                    (project_id, limit),
                ).fetchall()
            return [self._row_to_ws_frame(row) for row in rows]
        finally:
            conn.close()

    def list_ws_connections(self, project_id: str, limit: int = 200) -> List[Dict[str, Any]]:
        conn = self._get_conn()
        try:
            rows = conn.execute(
                """
                SELECT * FROM ws_connections
                 WHERE project_id = ?
                 ORDER BY opened_at DESC
                 LIMIT ?
                """,
                (project_id, limit),
            ).fetchall()
            return [self._row_to_ws_connection(row) for row in rows]
        finally:
            conn.close()

    def add_browser_artifact(
        self,
        project_id: str,
        artifact_type: str,
        source: str = "",
        url: str = "",
        payload: Optional[Dict[str, Any]] = None,
        identity_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        artifact_id = str(uuid.uuid4())
        created_at = datetime.now().isoformat()
        conn = self._get_conn()
        try:
            conn.execute(
                """
                INSERT INTO browser_artifacts (id, project_id, identity_id, artifact_type, source, url, payload_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    artifact_id,
                    project_id,
                    identity_id,
                    artifact_type,
                    source,
                    url,
                    self._dump_sensitive_json(payload or {}),
                    created_at,
                ),
            )
            self._touch_project(conn, project_id, created_at)
            conn.commit()
            row = conn.execute("SELECT * FROM browser_artifacts WHERE id = ?", (artifact_id,)).fetchone()
            return self._row_to_browser_artifact(row) if row else {}
        finally:
            conn.close()

    def list_browser_artifacts(self, project_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        conn = self._get_conn()
        try:
            rows = conn.execute(
                """
                SELECT * FROM browser_artifacts
                 WHERE project_id = ?
                 ORDER BY created_at DESC
                 LIMIT ?
                """,
                (project_id, limit),
            ).fetchall()
            return [self._row_to_browser_artifact(row) for row in rows]
        finally:
            conn.close()

    def start_attack_run(
        self,
        project_id: str,
        attack_type: str,
        target_id: Optional[str] = None,
        identity_id: Optional[str] = None,
        status: str = "running",
        parameters: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        run_id = str(uuid.uuid4())
        created_at = datetime.now().isoformat()
        conn = self._get_conn()
        try:
            conn.execute(
                """
                INSERT INTO attack_runs (
                    id, project_id, attack_type, target_id, identity_id, status,
                    parameters_json, summary_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, '{}', ?, ?)
                """,
                (
                    run_id,
                    project_id,
                    attack_type,
                    target_id,
                    identity_id,
                    status,
                    self._dump_sensitive_json(parameters or {}),
                    created_at,
                    created_at,
                ),
            )
            self._touch_project(conn, project_id, created_at)
            conn.commit()
            row = conn.execute("SELECT * FROM attack_runs WHERE id = ?", (run_id,)).fetchone()
            return self._row_to_attack_run(row) if row else {}
        finally:
            conn.close()

    def update_attack_run(
        self,
        run_id: str,
        status: Optional[str] = None,
        summary: Optional[Dict[str, Any]] = None,
        completed: bool = False,
    ) -> Optional[Dict[str, Any]]:
        conn = self._get_conn()
        try:
            existing = conn.execute(
                "SELECT project_id, summary_json FROM attack_runs WHERE id = ?",
                (run_id,),
            ).fetchone()
            if not existing:
                return None

            now = datetime.now().isoformat()
            merged_summary = self._load_sensitive_json(existing["summary_json"], {})
            if summary:
                merged_summary.update(summary)

            conn.execute(
                """
                UPDATE attack_runs
                   SET status = COALESCE(?, status),
                       summary_json = ?,
                       updated_at = ?,
                       completed_at = CASE WHEN ? THEN ? ELSE completed_at END
                 WHERE id = ?
                """,
                (
                    status,
                    self._dump_sensitive_json(merged_summary),
                    now,
                    1 if completed else 0,
                    now,
                    run_id,
                ),
            )
            self._touch_project(conn, existing["project_id"], now)
            conn.commit()
            row = conn.execute("SELECT * FROM attack_runs WHERE id = ?", (run_id,)).fetchone()
            return self._row_to_attack_run(row) if row else None
        finally:
            conn.close()

    def list_attack_runs(self, project_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        conn = self._get_conn()
        try:
            rows = conn.execute(
                """
                SELECT * FROM attack_runs
                 WHERE project_id = ?
                 ORDER BY created_at DESC
                 LIMIT ?
                """,
                (project_id, limit),
            ).fetchall()
            return [self._row_to_attack_run(row) for row in rows]
        finally:
            conn.close()

    def add_finding(
        self,
        project_id: str,
        title: str,
        category: str,
        severity: str = "info",
        description: str = "",
        payload: Optional[Dict[str, Any]] = None,
        attack_run_id: Optional[str] = None,
        related_target_id: Optional[str] = None,
        related_connection_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        finding_id = str(uuid.uuid4())
        created_at = datetime.now().isoformat()
        conn = self._get_conn()
        try:
            conn.execute(
                """
                INSERT INTO findings (
                    id, project_id, attack_run_id, title, category, severity, description,
                    payload_json, related_target_id, related_connection_id, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding_id,
                    project_id,
                    attack_run_id,
                    title,
                    category,
                    severity,
                    self._encrypt_text(description),
                    self._dump_sensitive_json(payload or {}),
                    related_target_id,
                    related_connection_id,
                    created_at,
                ),
            )
            self._touch_project(conn, project_id, created_at)
            conn.commit()
            row = conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
            return self._row_to_finding(row) if row else {}
        finally:
            conn.close()

    def list_findings(self, project_id: str, limit: int = 200) -> List[Dict[str, Any]]:
        conn = self._get_conn()
        try:
            rows = conn.execute(
                "SELECT * FROM findings WHERE project_id = ? ORDER BY created_at DESC LIMIT ?",
                (project_id, limit),
            ).fetchall()
            return [self._row_to_finding(row) for row in rows]
        finally:
            conn.close()

    def save_note(
        self,
        project_id: str,
        title: str,
        body: str,
        note_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        if not title or not title.strip():
            raise ValueError("Note title is required")

        now = datetime.now().isoformat()
        conn = self._get_conn()
        try:
            if note_id:
                conn.execute(
                    "UPDATE notes SET title = ?, body = ?, updated_at = ? WHERE id = ? AND project_id = ?",
                    (title.strip(), self._encrypt_text(body), now, note_id, project_id),
                )
            else:
                note_id = str(uuid.uuid4())
                conn.execute(
                    """
                    INSERT INTO notes (id, project_id, title, body, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (note_id, project_id, title.strip(), self._encrypt_text(body), now, now),
                )
            self._touch_project(conn, project_id, now)
            conn.commit()
            row = conn.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
            return self._row_to_note(row) if row else {}
        finally:
            conn.close()

    def list_notes(self, project_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        conn = self._get_conn()
        try:
            rows = conn.execute(
                "SELECT * FROM notes WHERE project_id = ? ORDER BY updated_at DESC LIMIT ?",
                (project_id, limit),
            ).fetchall()
            return [self._row_to_note(row) for row in rows]
        finally:
            conn.close()

    def _row_to_target(self, row: sqlite3.Row) -> Dict[str, Any]:
        data = dict(row)
        data["metadata"] = self._loads(data.pop("metadata_json", "{}"), {})
        return data

    def _row_to_http_flow(self, row: sqlite3.Row) -> Dict[str, Any]:
        data = dict(row)
        data["request_headers"] = self._load_sensitive_json(data.pop("request_headers_json", "{}"), {})
        data["request_body"] = self._decrypt_text(data.get("request_body", ""))
        data["response_headers"] = self._load_sensitive_json(data.pop("response_headers_json", "{}"), {})
        data["response_body"] = self._decrypt_text(data.get("response_body", ""))
        data["error"] = self._decrypt_text(data.get("error", ""))
        data["metadata"] = self._load_sensitive_json(data.pop("metadata_json", "{}"), {})
        return data

    def _row_to_ws_connection(self, row: sqlite3.Row) -> Dict[str, Any]:
        data = dict(row)
        data["handshake_headers"] = self._load_sensitive_json(data.pop("handshake_headers_json", "{}"), {})
        data["extensions"] = self._loads(data.pop("extensions_json", "[]"), [])
        data["metadata"] = self._load_sensitive_json(data.pop("metadata_json", "{}"), {})
        return data

    def _row_to_ws_frame(self, row: sqlite3.Row) -> Dict[str, Any]:
        data = dict(row)
        data["is_binary"] = bool(data.get("is_binary"))
        data["payload_text"] = self._decrypt_text(data.get("payload_text", ""))
        data["payload_base64"] = self._decrypt_text(data.get("payload_base64", ""))
        data["metadata"] = self._load_sensitive_json(data.pop("metadata_json", "{}"), {})
        return data

    def _row_to_browser_artifact(self, row: sqlite3.Row) -> Dict[str, Any]:
        data = dict(row)
        data["payload"] = self._load_sensitive_json(data.pop("payload_json", "{}"), {})
        return data

    def _row_to_attack_run(self, row: sqlite3.Row) -> Dict[str, Any]:
        data = dict(row)
        data["parameters"] = self._load_sensitive_json(data.pop("parameters_json", "{}"), {})
        data["summary"] = self._load_sensitive_json(data.pop("summary_json", "{}"), {})
        return data

    def _row_to_finding(self, row: sqlite3.Row) -> Dict[str, Any]:
        data = dict(row)
        data["description"] = self._decrypt_text(data.get("description", ""))
        data["payload"] = self._load_sensitive_json(data.pop("payload_json", "{}"), {})
        return data

    def _row_to_note(self, row: sqlite3.Row) -> Dict[str, Any]:
        data = dict(row)
        data["body"] = self._decrypt_text(data.get("body", ""))
        return data

    @staticmethod
    def _loads(raw: str, default: Any) -> Any:
        try:
            return json.loads(raw) if raw else default
        except (TypeError, json.JSONDecodeError):
            return default
