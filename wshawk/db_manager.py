import json
import os
import shlex
import sqlite3
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from wshawk.secure_store import SensitiveDataCipher


class WSHawkDatabase:
    """
    Unified WSHawk SQLite database manager.

    The legacy scanner still uses the `scans` table, while the platform
    runtime stores operator projects, identities, traffic events, and
    evidence in the same database.
    """

    SCAN_COLUMNS = {
        "target",
        "options",
        "status",
        "progress",
        "findings_json",
        "high_count",
        "medium_count",
        "low_count",
        "info_count",
        "messages_sent",
        "messages_received",
        "created_at",
        "started_at",
        "completed_at",
        "duration",
        "error",
    }

    def __init__(self, db_path: Optional[str] = None):
        if db_path:
            self.db_path = Path(db_path)
        else:
            self.db_path = self._resolve_default_db_path()

        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.sensitive_cipher = SensitiveDataCipher(self.db_path.parent)
        self._init_schema()

    @staticmethod
    def _resolve_default_db_path() -> Path:
        """Pick a writable default data directory across dev, packaged, and sandboxed environments."""
        candidate_dirs = []

        env_dir = os.environ.get("WSHAWK_DATA_DIR")
        if env_dir:
            candidate_dirs.append(Path(env_dir))

        candidate_dirs.extend(
            [
                Path(os.path.expanduser("~")) / ".wshawk",
                Path.cwd() / ".wshawk",
                Path("/tmp") / "wshawk",
            ]
        )

        for base_dir in candidate_dirs:
            try:
                base_dir.mkdir(parents=True, exist_ok=True)
                probe = base_dir / ".write_probe"
                probe.write_text("ok", encoding="utf-8")
                probe.unlink(missing_ok=True)
                return base_dir / "wshawk_v3.db"
            except OSError:
                continue

        return Path("/tmp") / "wshawk_v3.db"

    def _get_conn(self) -> sqlite3.Connection:
        """Get a connection with modern SQLite defaults."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _dump_sensitive_json(self, value: Any) -> str:
        return self.sensitive_cipher.dump_json(value)

    def _load_sensitive_json(self, raw: Any, default: Any) -> Any:
        return self.sensitive_cipher.load_json(raw, default)

    def _encrypt_text(self, value: Any) -> str:
        return self.sensitive_cipher.encrypt_text(value)

    def _decrypt_text(self, value: Any) -> str:
        return self.sensitive_cipher.decrypt_text(value)

    def _init_schema(self):
        """Initialize the legacy scan schema plus platform tables."""
        conn = self._get_conn()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    options TEXT DEFAULT '{}',
                    status TEXT DEFAULT 'queued',
                    progress INTEGER DEFAULT 0,
                    findings_json TEXT DEFAULT '[]',
                    high_count INTEGER DEFAULT 0,
                    medium_count INTEGER DEFAULT 0,
                    low_count INTEGER DEFAULT 0,
                    info_count INTEGER DEFAULT 0,
                    messages_sent INTEGER DEFAULT 0,
                    messages_received INTEGER DEFAULT 0,
                    created_at TEXT NOT NULL,
                    started_at TEXT,
                    completed_at TEXT,
                    duration REAL DEFAULT 0,
                    error TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
                CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC);

                CREATE TABLE IF NOT EXISTS projects (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE,
                    target_url TEXT DEFAULT '',
                    metadata_json TEXT DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_projects_updated ON projects(updated_at DESC);

                CREATE TABLE IF NOT EXISTS identities (
                    id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    alias TEXT NOT NULL,
                    source TEXT DEFAULT 'manual',
                    cookies_json TEXT DEFAULT '[]',
                    headers_json TEXT DEFAULT '{}',
                    tokens_json TEXT DEFAULT '{}',
                    storage_json TEXT DEFAULT '{}',
                    notes TEXT DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_validated_at TEXT,
                    FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
                );

                CREATE UNIQUE INDEX IF NOT EXISTS idx_identity_alias
                    ON identities(project_id, alias);
                CREATE INDEX IF NOT EXISTS idx_identity_project
                    ON identities(project_id, updated_at DESC);

                CREATE TABLE IF NOT EXISTS traffic_events (
                    id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    direction TEXT DEFAULT '',
                    connection_id TEXT DEFAULT '',
                    target TEXT DEFAULT '',
                    payload_json TEXT DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_traffic_project_created
                    ON traffic_events(project_id, created_at DESC);

                CREATE TABLE IF NOT EXISTS evidence (
                    id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    category TEXT NOT NULL,
                    severity TEXT DEFAULT 'info',
                    payload_json TEXT DEFAULT '{}',
                    related_event_id TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_evidence_project_created
                    ON evidence(project_id, created_at DESC);
                """
            )
            conn.commit()
        finally:
            conn.close()

    # Legacy scan persistence

    def create(self, target: str, options: Optional[Dict] = None) -> str:
        """Create a new scan entry and return the scan ID."""
        scan_id = str(uuid.uuid4())
        conn = self._get_conn()
        try:
            conn.execute(
                """INSERT INTO scans (id, target, options, status, created_at)
                   VALUES (?, ?, ?, 'queued', ?)""",
                (scan_id, target, json.dumps(options or {}), datetime.now().isoformat()),
            )
            conn.commit()
        finally:
            conn.close()
        return scan_id

    def update(self, scan_id: str, **kwargs):
        """Update scan fields using a strict column allow-list."""
        if not kwargs:
            return

        invalid = [key for key in kwargs if key not in self.SCAN_COLUMNS]
        if invalid:
            raise ValueError(f"Invalid scan column(s): {', '.join(sorted(invalid))}")

        conn = self._get_conn()
        try:
            for key, value in kwargs.items():
                if key in ("findings_json", "options"):
                    value = json.dumps(value)
                conn.execute(
                    f"UPDATE scans SET {key} = ? WHERE id = ?",
                    (value, scan_id),
                )
            conn.commit()
        finally:
            conn.close()

    def save_scan(self, target: str, report: Dict) -> str:
        """Compatibility method for legacy toolchains."""
        scan_id = str(uuid.uuid4())
        timestamp = datetime.now().isoformat()
        elapsed = report.get("elapsed", 0.0)
        sev = report.get("severity_counts", {})
        findings = report.get("findings", [])

        for finding in findings:
            if "poc" not in finding:
                finding["poc"] = self._generate_poc(finding, target)

        conn = self._get_conn()
        try:
            conn.execute(
                """
                INSERT INTO scans (
                    id, target, created_at, started_at, completed_at,
                    duration, high_count, medium_count, low_count,
                    info_count, findings_json, status, progress
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'completed', 100)
                """,
                (
                    scan_id,
                    target,
                    timestamp,
                    timestamp,
                    timestamp,
                    elapsed,
                    sev.get("High", 0),
                    sev.get("Medium", 0),
                    sev.get("Low", 0),
                    sev.get("Info", 0),
                    json.dumps(findings),
                ),
            )
            conn.commit()
        finally:
            conn.close()
        return scan_id

    def get(self, scan_id: str) -> Optional[Dict]:
        """Get scan by ID."""
        conn = self._get_conn()
        try:
            row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
            return self._row_to_scan(row) if row else None
        finally:
            conn.close()

    def list_all(self, limit: int = 100) -> List[Dict]:
        """Get all scans, newest first."""
        conn = self._get_conn()
        try:
            rows = conn.execute(
                "SELECT * FROM scans ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [self._row_to_scan(row) for row in rows]
        finally:
            conn.close()

    def delete(self, scan_id: str) -> bool:
        """Delete a scan."""
        conn = self._get_conn()
        try:
            cursor = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            conn.commit()
            return cursor.rowcount > 0
        finally:
            conn.close()

    def get_stats(self) -> Dict:
        """Get aggregate scan statistics."""
        conn = self._get_conn()
        try:
            total = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            completed = conn.execute(
                "SELECT COUNT(*) FROM scans WHERE status = 'completed'"
            ).fetchone()[0]
            running = conn.execute(
                "SELECT COUNT(*) FROM scans WHERE status IN ('queued', 'running')"
            ).fetchone()[0]
            return {
                "total_scans": total,
                "completed": completed,
                "running": running,
            }
        finally:
            conn.close()

    def compare_scans(self, scan_a_id: str, scan_b_id: str) -> Dict:
        """Compute a diff between two historical scans."""
        scan_a = self.get(scan_a_id)
        scan_b = self.get(scan_b_id)

        if not scan_a or not scan_b:
            return {"error": "Scan not found"}

        findings_a = {
            (f.get("type", ""), f.get("value", ""), f.get("url", ""))
            for f in scan_a.get("findings", [])
        }
        findings_b = {
            (f.get("type", ""), f.get("value", ""), f.get("url", ""))
            for f in scan_b.get("findings", [])
        }

        fixed = findings_a - findings_b
        new_vulns = findings_b - findings_a

        return {
            "fixed_count": len(fixed),
            "new_count": len(new_vulns),
            "fixed": [{"type": t, "value": v, "url": u} for t, v, u in fixed],
            "new_vulns": [{"type": t, "value": v, "url": u} for t, v, u in new_vulns],
        }

    # Platform persistence

    def save_project(
        self,
        name: str,
        target_url: str = "",
        metadata: Optional[Dict[str, Any]] = None,
        project_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create or update an operator project."""
        if not name or not name.strip():
            raise ValueError("Project name is required")

        name = name.strip()
        metadata = metadata or {}
        now = datetime.now().isoformat()

        conn = self._get_conn()
        try:
            if project_id:
                current = conn.execute(
                    "SELECT id, name FROM projects WHERE id = ?",
                    (project_id,),
                ).fetchone()
                if not current:
                    raise ValueError("Project not found")

                conflicting = conn.execute(
                    "SELECT id FROM projects WHERE name = ?",
                    (name,),
                ).fetchone()
                if conflicting and conflicting["id"] != project_id:
                    name = current["name"]

                conn.execute(
                    """
                    UPDATE projects
                       SET name = ?, target_url = ?, metadata_json = ?, updated_at = ?
                     WHERE id = ?
                    """,
                    (name, target_url, self._dump_sensitive_json(metadata), now, project_id),
                )
            else:
                existing = conn.execute(
                    "SELECT id FROM projects WHERE name = ?",
                    (name,),
                ).fetchone()
                if existing:
                    project_id = existing["id"]
                    conn.execute(
                        """
                        UPDATE projects
                           SET target_url = ?, metadata_json = ?, updated_at = ?
                         WHERE id = ?
                        """,
                        (target_url, self._dump_sensitive_json(metadata), now, project_id),
                    )
                else:
                    project_id = str(uuid.uuid4())
                    conn.execute(
                        """
                        INSERT INTO projects (id, name, target_url, metadata_json, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (project_id, name, target_url, self._dump_sensitive_json(metadata), now, now),
                    )

            conn.commit()
            return self.get_project(project_id)
        finally:
            conn.close()

    def get_project(self, project_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a project by ID."""
        conn = self._get_conn()
        try:
            row = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
            return self._row_to_project(row) if row else None
        finally:
            conn.close()

    def get_project_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        """Fetch a project by name."""
        conn = self._get_conn()
        try:
            row = conn.execute("SELECT * FROM projects WHERE name = ?", (name,)).fetchone()
            return self._row_to_project(row) if row else None
        finally:
            conn.close()

    def list_projects(self, limit: int = 100) -> List[Dict[str, Any]]:
        """List operator projects, newest first."""
        conn = self._get_conn()
        try:
            rows = conn.execute(
                "SELECT * FROM projects ORDER BY updated_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [self._row_to_project(row) for row in rows]
        finally:
            conn.close()

    def delete_project(self, project_id: str) -> bool:
        """Delete a project by ID."""
        conn = self._get_conn()
        try:
            cursor = conn.execute("DELETE FROM projects WHERE id = ?", (project_id,))
            conn.commit()
            return cursor.rowcount > 0
        finally:
            conn.close()

    def delete_project_by_name(self, name: str) -> bool:
        """Delete a project by name."""
        conn = self._get_conn()
        try:
            cursor = conn.execute("DELETE FROM projects WHERE name = ?", (name,))
            conn.commit()
            return cursor.rowcount > 0
        finally:
            conn.close()

    def save_identity(
        self,
        project_id: str,
        alias: str,
        source: str = "manual",
        cookies: Optional[List[Dict[str, Any]]] = None,
        headers: Optional[Dict[str, Any]] = None,
        tokens: Optional[Dict[str, Any]] = None,
        storage: Optional[Dict[str, Any]] = None,
        notes: str = "",
        identity_id: Optional[str] = None,
        last_validated_at: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create or update an identity in the operator vault."""
        if not alias or not alias.strip():
            raise ValueError("Identity alias is required")

        alias = alias.strip()
        now = datetime.now().isoformat()
        cookies = cookies or []
        headers = headers or {}
        tokens = tokens or {}
        storage = storage or {}

        conn = self._get_conn()
        try:
            if identity_id:
                conn.execute(
                    """
                    UPDATE identities
                       SET alias = ?, source = ?, cookies_json = ?, headers_json = ?,
                           tokens_json = ?, storage_json = ?, notes = ?, updated_at = ?,
                           last_validated_at = ?
                     WHERE id = ? AND project_id = ?
                    """,
                    (
                        alias,
                        source,
                        self._dump_sensitive_json(cookies),
                        self._dump_sensitive_json(headers),
                        self._dump_sensitive_json(tokens),
                        self._dump_sensitive_json(storage),
                        self._encrypt_text(notes),
                        now,
                        last_validated_at,
                        identity_id,
                        project_id,
                    ),
                )
            else:
                existing = conn.execute(
                    "SELECT id FROM identities WHERE project_id = ? AND alias = ?",
                    (project_id, alias),
                ).fetchone()
                if existing:
                    identity_id = existing["id"]
                    conn.execute(
                        """
                        UPDATE identities
                           SET source = ?, cookies_json = ?, headers_json = ?,
                               tokens_json = ?, storage_json = ?, notes = ?,
                               updated_at = ?, last_validated_at = ?
                         WHERE id = ?
                        """,
                        (
                            source,
                            self._dump_sensitive_json(cookies),
                            self._dump_sensitive_json(headers),
                            self._dump_sensitive_json(tokens),
                            self._dump_sensitive_json(storage),
                            self._encrypt_text(notes),
                            now,
                            last_validated_at,
                            identity_id,
                        ),
                    )
                else:
                    identity_id = str(uuid.uuid4())
                    conn.execute(
                        """
                        INSERT INTO identities (
                            id, project_id, alias, source, cookies_json, headers_json,
                            tokens_json, storage_json, notes, created_at, updated_at, last_validated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            identity_id,
                            project_id,
                            alias,
                            source,
                            self._dump_sensitive_json(cookies),
                            self._dump_sensitive_json(headers),
                            self._dump_sensitive_json(tokens),
                            self._dump_sensitive_json(storage),
                            self._encrypt_text(notes),
                            now,
                            now,
                            last_validated_at,
                        ),
                    )

            conn.commit()
            return self.get_identity(identity_id)
        finally:
            conn.close()

    def get_identity(self, identity_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a vault identity by ID."""
        conn = self._get_conn()
        try:
            row = conn.execute("SELECT * FROM identities WHERE id = ?", (identity_id,)).fetchone()
            return self._row_to_identity(row) if row else None
        finally:
            conn.close()

    def get_identity_by_alias(self, project_id: str, alias: str) -> Optional[Dict[str, Any]]:
        """Fetch a vault identity by project-scoped alias."""
        conn = self._get_conn()
        try:
            row = conn.execute(
                "SELECT * FROM identities WHERE project_id = ? AND alias = ?",
                (project_id, alias),
            ).fetchone()
            return self._row_to_identity(row) if row else None
        finally:
            conn.close()

    def list_identities(self, project_id: str) -> List[Dict[str, Any]]:
        """List identities for a project."""
        conn = self._get_conn()
        try:
            rows = conn.execute(
                "SELECT * FROM identities WHERE project_id = ? ORDER BY updated_at DESC",
                (project_id,),
            ).fetchall()
            return [self._row_to_identity(row) for row in rows]
        finally:
            conn.close()

    def add_event(
        self,
        project_id: str,
        event_type: str,
        payload: Optional[Dict[str, Any]] = None,
        direction: str = "",
        connection_id: str = "",
        target: str = "",
    ) -> Dict[str, Any]:
        """Append a traffic or operator event to a project timeline."""
        event_id = str(uuid.uuid4())
        created_at = datetime.now().isoformat()
        conn = self._get_conn()
        try:
            conn.execute(
                """
                INSERT INTO traffic_events (
                    id, project_id, event_type, direction, connection_id, target, payload_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    project_id,
                    event_type,
                    direction,
                    connection_id,
                    target,
                    self._dump_sensitive_json(payload or {}),
                    created_at,
                ),
            )
            conn.execute(
                "UPDATE projects SET updated_at = ? WHERE id = ?",
                (created_at, project_id),
            )
            conn.commit()
            return self.get_event(event_id)
        finally:
            conn.close()

    def get_event(self, event_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a traffic event by ID."""
        conn = self._get_conn()
        try:
            row = conn.execute("SELECT * FROM traffic_events WHERE id = ?", (event_id,)).fetchone()
            return self._row_to_event(row) if row else None
        finally:
            conn.close()

    def list_events(
        self,
        project_id: str,
        limit: int = 200,
        event_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List traffic events for a project."""
        conn = self._get_conn()
        try:
            if event_type:
                rows = conn.execute(
                    """
                    SELECT * FROM traffic_events
                     WHERE project_id = ? AND event_type = ?
                     ORDER BY created_at DESC
                     LIMIT ?
                    """,
                    (project_id, event_type, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT * FROM traffic_events
                     WHERE project_id = ?
                     ORDER BY created_at DESC
                     LIMIT ?
                    """,
                    (project_id, limit),
                ).fetchall()
            return [self._row_to_event(row) for row in rows]
        finally:
            conn.close()

    def add_evidence(
        self,
        project_id: str,
        title: str,
        category: str,
        payload: Optional[Dict[str, Any]] = None,
        severity: str = "info",
        related_event_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Persist a piece of operator evidence."""
        if not title or not title.strip():
            raise ValueError("Evidence title is required")

        evidence_id = str(uuid.uuid4())
        created_at = datetime.now().isoformat()

        conn = self._get_conn()
        try:
            conn.execute(
                """
                INSERT INTO evidence (
                    id, project_id, title, category, severity, payload_json, related_event_id, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    evidence_id,
                    project_id,
                    title.strip(),
                    category,
                    severity,
                    self._dump_sensitive_json(payload or {}),
                    related_event_id,
                    created_at,
                ),
            )
            conn.execute(
                "UPDATE projects SET updated_at = ? WHERE id = ?",
                (created_at, project_id),
            )
            conn.commit()
            return self.get_evidence(evidence_id)
        finally:
            conn.close()

    def get_evidence(self, evidence_id: str) -> Optional[Dict[str, Any]]:
        """Fetch evidence by ID."""
        conn = self._get_conn()
        try:
            row = conn.execute("SELECT * FROM evidence WHERE id = ?", (evidence_id,)).fetchone()
            return self._row_to_evidence(row) if row else None
        finally:
            conn.close()

    def list_evidence(self, project_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        """List evidence items for a project."""
        conn = self._get_conn()
        try:
            rows = conn.execute(
                """
                SELECT * FROM evidence
                 WHERE project_id = ?
                 ORDER BY created_at DESC
                 LIMIT ?
                """,
                (project_id, limit),
            ).fetchall()
            return [self._row_to_evidence(row) for row in rows]
        finally:
            conn.close()

    # Row conversion helpers

    def _row_to_scan(self, row: sqlite3.Row) -> Dict[str, Any]:
        data = dict(row)
        data["findings"] = self._loads(data.pop("findings_json", "[]"), [])
        data["options"] = self._loads(data.get("options", "{}"), {})
        return data

    def _row_to_project(self, row: sqlite3.Row) -> Dict[str, Any]:
        data = dict(row)
        data["metadata"] = self._load_sensitive_json(data.pop("metadata_json", "{}"), {})
        return data

    def _row_to_identity(self, row: sqlite3.Row) -> Dict[str, Any]:
        data = dict(row)
        data["cookies"] = self._load_sensitive_json(data.pop("cookies_json", "[]"), [])
        data["headers"] = self._load_sensitive_json(data.pop("headers_json", "{}"), {})
        data["tokens"] = self._load_sensitive_json(data.pop("tokens_json", "{}"), {})
        data["storage"] = self._load_sensitive_json(data.pop("storage_json", "{}"), {})
        data["notes"] = self._decrypt_text(data.get("notes", ""))
        return data

    def _row_to_event(self, row: sqlite3.Row) -> Dict[str, Any]:
        data = dict(row)
        data["payload"] = self._load_sensitive_json(data.pop("payload_json", "{}"), {})
        return data

    def _row_to_evidence(self, row: sqlite3.Row) -> Dict[str, Any]:
        data = dict(row)
        data["payload"] = self._load_sensitive_json(data.pop("payload_json", "{}"), {})
        return data

    @staticmethod
    def _loads(raw: str, default: Any) -> Any:
        try:
            return json.loads(raw) if raw else default
        except (TypeError, json.JSONDecodeError):
            return default

    def _generate_poc(self, finding: Dict, target: str) -> str:
        """Generate a quick curl or HTML snippet for a legacy PoC."""
        finding_type = finding.get("type", "")
        value = finding.get("value", "")
        url = finding.get("url", target) or target

        safe_url = shlex.quote(url)

        if finding_type == "csrf":
            return (
                f'<html><body><form action="{url}" method="POST">'
                '<input type="submit" value="Exploit CSRF"></form>'
                "<script>document.forms[0].submit();</script></body></html>"
            )
        if any(keyword in finding_type.lower() for keyword in ("sql", "xss", "cmd", "lfi", "fuzz")):
            safe_value = shlex.quote(value)
            return f"curl -X POST {safe_url} -d {safe_value}"
        return f"curl -I {safe_url}"


# Integration functions for legacy functional usage
_db_instance = None


def _get_db() -> WSHawkDatabase:
    global _db_instance
    if _db_instance is None:
        _db_instance = WSHawkDatabase()
    return _db_instance


def init_db():
    _get_db()


def save_scan(target, report):
    return _get_db().save_scan(target, report)


def get_all_scans():
    return _get_db().list_all()


def get_scan(scan_id):
    return _get_db().get(scan_id)


def compare_scans(id1, id2):
    return _get_db().compare_scans(id1, id2)
