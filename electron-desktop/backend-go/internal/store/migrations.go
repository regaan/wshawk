package store

var migrations = []string{
	`CREATE TABLE IF NOT EXISTS schema_migrations (
		version INTEGER PRIMARY KEY,
		applied_at TEXT NOT NULL
	);
	CREATE TABLE IF NOT EXISTS projects (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		target_url TEXT NOT NULL DEFAULT '',
		metadata_json TEXT NOT NULL DEFAULT '{}',
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL
	);
	CREATE TABLE IF NOT EXISTS targets (
		id TEXT PRIMARY KEY,
		project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
		name TEXT NOT NULL DEFAULT '', value TEXT NOT NULL DEFAULT '',
		metadata_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL, updated_at TEXT NOT NULL
	);
	CREATE TABLE IF NOT EXISTS notes (
		id TEXT PRIMARY KEY,
		project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
		name TEXT NOT NULL DEFAULT '', value TEXT NOT NULL DEFAULT '',
		metadata_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL, updated_at TEXT NOT NULL
	);
	CREATE TABLE IF NOT EXISTS evidence (
		id TEXT PRIMARY KEY,
		project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
		name TEXT NOT NULL DEFAULT '', value TEXT NOT NULL DEFAULT '',
		metadata_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL, updated_at TEXT NOT NULL
	);
	CREATE TABLE IF NOT EXISTS identities (
		id TEXT PRIMARY KEY,
		project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
		name TEXT NOT NULL DEFAULT '', value TEXT NOT NULL DEFAULT '',
		metadata_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL, updated_at TEXT NOT NULL
	);
	CREATE TABLE IF NOT EXISTS sessions (
		id TEXT PRIMARY KEY,
		project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
		name TEXT NOT NULL DEFAULT '', value TEXT NOT NULL DEFAULT '',
		metadata_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL, updated_at TEXT NOT NULL
	);
	CREATE TABLE IF NOT EXISTS http_flows (
		id TEXT PRIMARY KEY,
		project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
		name TEXT NOT NULL DEFAULT '', value TEXT NOT NULL DEFAULT '',
		metadata_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL, updated_at TEXT NOT NULL
	);
	CREATE TABLE IF NOT EXISTS ws_connections (
		id TEXT PRIMARY KEY,
		project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
		name TEXT NOT NULL DEFAULT '', value TEXT NOT NULL DEFAULT '',
		metadata_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL, updated_at TEXT NOT NULL
	);
	CREATE TABLE IF NOT EXISTS ws_frames (
		id TEXT PRIMARY KEY,
		project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
		name TEXT NOT NULL DEFAULT '', value TEXT NOT NULL DEFAULT '',
		metadata_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL, updated_at TEXT NOT NULL
	);
	CREATE TABLE IF NOT EXISTS protocol_maps (
		id TEXT PRIMARY KEY,
		project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
		name TEXT NOT NULL DEFAULT '', value TEXT NOT NULL DEFAULT '',
		metadata_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL, updated_at TEXT NOT NULL
	);
	CREATE TABLE IF NOT EXISTS timeline (
		id TEXT PRIMARY KEY,
		project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
		name TEXT NOT NULL DEFAULT '', value TEXT NOT NULL DEFAULT '',
		metadata_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL, updated_at TEXT NOT NULL
	);
	CREATE TABLE IF NOT EXISTS attack_runs (
		id TEXT PRIMARY KEY,
		project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
		name TEXT NOT NULL DEFAULT '', value TEXT NOT NULL DEFAULT '',
		metadata_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL, updated_at TEXT NOT NULL
	);
	CREATE TABLE IF NOT EXISTS findings (
		id TEXT PRIMARY KEY,
		project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
		name TEXT NOT NULL DEFAULT '', value TEXT NOT NULL DEFAULT '',
		metadata_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL, updated_at TEXT NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_targets_project ON targets(project_id, created_at DESC);
	CREATE INDEX IF NOT EXISTS idx_notes_project ON notes(project_id, created_at DESC);
	CREATE INDEX IF NOT EXISTS idx_evidence_project ON evidence(project_id, created_at DESC);
	CREATE INDEX IF NOT EXISTS idx_identities_project ON identities(project_id, created_at DESC);
	CREATE INDEX IF NOT EXISTS idx_sessions_project ON sessions(project_id, created_at DESC);
	CREATE INDEX IF NOT EXISTS idx_http_flows_project ON http_flows(project_id, created_at DESC);
	CREATE INDEX IF NOT EXISTS idx_ws_connections_project ON ws_connections(project_id, created_at DESC);
	CREATE INDEX IF NOT EXISTS idx_ws_frames_project ON ws_frames(project_id, created_at DESC);
	CREATE INDEX IF NOT EXISTS idx_protocol_maps_project ON protocol_maps(project_id, created_at DESC);
	CREATE INDEX IF NOT EXISTS idx_timeline_project ON timeline(project_id, created_at DESC);
	CREATE INDEX IF NOT EXISTS idx_attack_runs_project ON attack_runs(project_id, created_at DESC);
	CREATE INDEX IF NOT EXISTS idx_findings_project ON findings(project_id, created_at DESC);`,
}
