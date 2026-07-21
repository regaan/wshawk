import base64
import json
import sqlite3
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from wshawk.db_manager import WSHawkDatabase
from wshawk.store.project_correlation import ProjectCorrelationMixin


class ProjectStore(ProjectCorrelationMixin):
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
