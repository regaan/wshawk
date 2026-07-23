package store

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const SchemaVersion = 1

var entityTables = map[string]string{
	"targets": "targets", "notes": "notes", "evidence": "evidence",
	"identities": "identities", "sessions": "sessions", "http_flows": "http_flows",
	"ws_connections": "ws_connections", "ws_frames": "ws_frames",
	"protocol_maps": "protocol_maps", "timeline": "timeline",
	"attack_runs": "attack_runs", "findings": "findings",
}

type Store struct {
	db   *sql.DB
	path string
	aead cipher.AEAD
}

const encryptedPrefix = "wshawk.enc.v1:"

type Project struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	TargetURL string         `json:"target_url"`
	Metadata  map[string]any `json:"metadata"`
	CreatedAt string         `json:"created_at"`
	UpdatedAt string         `json:"updated_at"`
}

type Entity struct {
	ID        string         `json:"id"`
	ProjectID string         `json:"project_id"`
	Name      string         `json:"name"`
	Value     string         `json:"value"`
	Metadata  map[string]any `json:"metadata"`
	CreatedAt string         `json:"created_at"`
	UpdatedAt string         `json:"updated_at"`
}

func Open(dataDir string) (*Store, error) {
	if strings.TrimSpace(dataDir) == "" {
		return nil, errors.New("data directory is required")
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create data directory: %w", err)
	}
	path := filepath.Join(dataDir, "wshawk-go.db")
	existingDatabase := false
	if info, err := os.Stat(path); err == nil {
		existingDatabase = info.Size() > 0
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect database: %w", err)
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	db.SetMaxOpenConns(1)
	aead, err := storageCipher(dataDir)
	if err != nil {
		db.Close()
		return nil, err
	}
	store := &Store{db: db, path: path, aead: aead}
	if err := store.configureAndMigrate(context.Background(), existingDatabase); err != nil {
		db.Close()
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		db.Close()
		return nil, fmt.Errorf("restrict database permissions: %w", err)
	}
	if existingDatabase {
		needsEncryption, checkErr := store.needsEncryption(context.Background())
		if checkErr != nil {
			db.Close()
			return nil, checkErr
		}
		if needsEncryption {
			if _, checkErr = store.db.ExecContext(context.Background(), "PRAGMA wal_checkpoint(TRUNCATE)"); checkErr != nil {
				db.Close()
				return nil, checkErr
			}
			if _, checkErr = backupFile(path, filepath.Join(filepath.Dir(path), "backups"), "pre-encryption"); checkErr != nil {
				db.Close()
				return nil, checkErr
			}
		}
	}
	if err := store.encryptExisting(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

func OpenMemory() (*Store, error) {
	db, err := sql.Open("sqlite", "file:wshawk-memory?mode=memory&cache=shared")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		db.Close()
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		db.Close()
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		db.Close()
		return nil, err
	}
	store := &Store{db: db, path: ":memory:", aead: aead}
	if err := store.configureAndMigrate(context.Background(), false); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) Close() error { return s.db.Close() }

func storageCipher(dataDir string) (cipher.AEAD, error) {
	var key []byte
	configured := strings.TrimSpace(os.Getenv("WSHAWK_STORAGE_KEY"))
	if configured != "" {
		decoded, err := base64.StdEncoding.DecodeString(configured)
		if err != nil || len(decoded) != 32 {
			return nil, errors.New("WSHAWK_STORAGE_KEY must be a base64-encoded 32-byte key")
		}
		key = decoded
	} else {
		keyPath := filepath.Join(dataDir, ".wshawk-storage-key")
		encoded, err := os.ReadFile(keyPath)
		if err == nil {
			key, err = base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
			if err != nil || len(key) != 32 {
				return nil, errors.New("local WSHawk storage key is invalid")
			}
		} else if errors.Is(err, os.ErrNotExist) {
			key = make([]byte, 32)
			if _, err = rand.Read(key); err != nil {
				return nil, err
			}
			if err = os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(key)), 0o600); err != nil {
				return nil, fmt.Errorf("create local storage key: %w", err)
			}
		} else {
			return nil, fmt.Errorf("read local storage key: %w", err)
		}
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (s *Store) seal(value string) (string, error) {
	if strings.HasPrefix(value, encryptedPrefix) {
		if _, err := s.open(value); err != nil {
			return "", err
		}
		return value, nil
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := s.aead.Seal(nil, nonce, []byte(value), nil)
	return encryptedPrefix + base64.RawStdEncoding.EncodeToString(append(nonce, sealed...)), nil
}

func (s *Store) open(value string) (string, error) {
	if !strings.HasPrefix(value, encryptedPrefix) {
		return value, nil
	}
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(value, encryptedPrefix))
	if err != nil || len(raw) < s.aead.NonceSize() {
		return "", errors.New("encrypted project value is invalid")
	}
	plain, err := s.aead.Open(nil, raw[:s.aead.NonceSize()], raw[s.aead.NonceSize():], nil)
	if err != nil {
		return "", errors.New("encrypted project value could not be decrypted with the active storage key")
	}
	return string(plain), nil
}

func (s *Store) needsEncryption(ctx context.Context) (bool, error) {
	var count int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM projects WHERE name NOT LIKE ? OR target_url NOT LIKE ? OR metadata_json NOT LIKE ?", encryptedPrefix+"%", encryptedPrefix+"%", encryptedPrefix+"%").Scan(&count); err != nil {
		return false, err
	}
	if count > 0 {
		return true, nil
	}
	for _, table := range entityTables {
		query := fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE name NOT LIKE ? OR value NOT LIKE ? OR metadata_json NOT LIKE ?", table)
		if err := s.db.QueryRowContext(ctx, query, encryptedPrefix+"%", encryptedPrefix+"%", encryptedPrefix+"%").Scan(&count); err != nil {
			return false, err
		}
		if count > 0 {
			return true, nil
		}
	}
	return false, nil
}

func (s *Store) encryptExisting(ctx context.Context) error {
	needs, err := s.needsEncryption(ctx)
	if err != nil || !needs {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	type record struct{ id, name, value, metadata string }
	projects, err := tx.QueryContext(ctx, "SELECT id,name,target_url,metadata_json FROM projects")
	if err != nil {
		return err
	}
	projectRecords := []record{}
	for projects.Next() {
		var row record
		if err = projects.Scan(&row.id, &row.name, &row.value, &row.metadata); err != nil {
			projects.Close()
			return err
		}
		projectRecords = append(projectRecords, row)
	}
	projects.Close()
	for _, row := range projectRecords {
		name, sealErr := s.seal(row.name)
		if sealErr != nil {
			return sealErr
		}
		value, sealErr := s.seal(row.value)
		if sealErr != nil {
			return sealErr
		}
		metadata, sealErr := s.seal(row.metadata)
		if sealErr != nil {
			return sealErr
		}
		if _, err = tx.ExecContext(ctx, "UPDATE projects SET name=?,target_url=?,metadata_json=? WHERE id=?", name, value, metadata, row.id); err != nil {
			return err
		}
	}
	for _, table := range entityTables {
		rows, queryErr := tx.QueryContext(ctx, fmt.Sprintf("SELECT id,name,value,metadata_json FROM %s", table))
		if queryErr != nil {
			return queryErr
		}
		records := []record{}
		for rows.Next() {
			var row record
			if queryErr = rows.Scan(&row.id, &row.name, &row.value, &row.metadata); queryErr != nil {
				rows.Close()
				return queryErr
			}
			records = append(records, row)
		}
		rows.Close()
		for _, row := range records {
			name, sealErr := s.seal(row.name)
			if sealErr != nil {
				return sealErr
			}
			value, sealErr := s.seal(row.value)
			if sealErr != nil {
				return sealErr
			}
			metadata, sealErr := s.seal(row.metadata)
			if sealErr != nil {
				return sealErr
			}
			if _, err = tx.ExecContext(ctx, fmt.Sprintf("UPDATE %s SET name=?,value=?,metadata_json=? WHERE id=?", table), name, value, metadata, row.id); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

func (s *Store) configureAndMigrate(ctx context.Context, backupBeforeMigration bool) error {
	for _, pragma := range []string{
		"PRAGMA foreign_keys=ON", "PRAGMA journal_mode=WAL", "PRAGMA synchronous=FULL",
		"PRAGMA busy_timeout=5000", "PRAGMA secure_delete=ON",
	} {
		if _, err := s.db.ExecContext(ctx, pragma); err != nil {
			return fmt.Errorf("configure database: %w", err)
		}
	}
	pending, err := s.pendingMigrations(ctx)
	if err != nil {
		return err
	}
	if backupBeforeMigration && pending {
		if _, err := s.db.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
			return fmt.Errorf("checkpoint before migration: %w", err)
		}
		if _, err := backupFile(s.path, filepath.Join(filepath.Dir(s.path), "backups"), "pre-migration"); err != nil {
			return fmt.Errorf("pre-migration backup: %w", err)
		}
	}
	for index, migration := range migrations {
		version := index + 1
		var applied int
		err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='schema_migrations'").Scan(&applied)
		if err != nil {
			return fmt.Errorf("inspect schema: %w", err)
		}
		if applied > 0 {
			if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM schema_migrations WHERE version=?", version).Scan(&applied); err != nil {
				return fmt.Errorf("inspect migration: %w", err)
			}
			if applied > 0 {
				continue
			}
		}
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("start migration: %w", err)
		}
		if _, err = tx.ExecContext(ctx, migration); err == nil {
			_, err = tx.ExecContext(ctx, "INSERT INTO schema_migrations(version, applied_at) VALUES(?, ?)", version, now())
		}
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("apply migration %d: %w", version, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %d: %w", version, err)
		}
	}
	return nil
}

func (s *Store) pendingMigrations(ctx context.Context) (bool, error) {
	var tableCount int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='schema_migrations'").Scan(&tableCount); err != nil {
		return false, fmt.Errorf("inspect schema: %w", err)
	}
	if tableCount == 0 {
		return len(migrations) > 0, nil
	}
	for index := range migrations {
		var applied int
		if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM schema_migrations WHERE version=?", index+1).Scan(&applied); err != nil {
			return false, fmt.Errorf("inspect schema version: %w", err)
		}
		if applied == 0 {
			return true, nil
		}
	}
	return false, nil
}

func (s *Store) Health(ctx context.Context) map[string]any {
	result := map[string]any{"path": s.path, "schemaVersion": SchemaVersion, "ready": false, "encryption": "AES-256-GCM", "encryptedFields": []string{"project.name", "project.target_url", "project.metadata", "entity.name", "entity.value", "entity.metadata"}}
	if err := s.db.PingContext(ctx); err != nil {
		result["error"] = err.Error()
		return result
	}
	result["ready"] = true
	return result
}

func (s *Store) SaveProject(ctx context.Context, project Project) (Project, error) {
	return saveProject(ctx, s.db, s, project)
}

type databaseWriter interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func saveProject(ctx context.Context, database databaseWriter, protector *Store, project Project) (Project, error) {
	project.ID = cleanID(project.ID)
	if project.ID == "" {
		project.ID = newID("project")
	}
	project.Name = strings.TrimSpace(project.Name)
	if project.Name == "" {
		project.Name = "Untitled WSHawk Project"
	}
	if project.Metadata == nil {
		project.Metadata = map[string]any{}
	}
	stamp := now()
	metadata, err := json.Marshal(project.Metadata)
	if err != nil {
		return Project{}, fmt.Errorf("encode project metadata: %w", err)
	}
	name, err := protector.seal(project.Name)
	if err != nil {
		return Project{}, err
	}
	targetURL, err := protector.seal(strings.TrimSpace(project.TargetURL))
	if err != nil {
		return Project{}, err
	}
	metadataValue, err := protector.seal(string(metadata))
	if err != nil {
		return Project{}, err
	}
	_, err = database.ExecContext(ctx, `INSERT INTO projects(id,name,target_url,metadata_json,created_at,updated_at)
		VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,target_url=excluded.target_url,
		metadata_json=excluded.metadata_json,updated_at=excluded.updated_at`, project.ID, name,
		targetURL, metadataValue, stamp, stamp)
	if err != nil {
		return Project{}, fmt.Errorf("save project: %w", err)
	}
	return scanProject(protector, database.QueryRowContext(ctx, "SELECT id,name,target_url,metadata_json,created_at,updated_at FROM projects WHERE id=?", project.ID))
}

func (s *Store) GetProject(ctx context.Context, id string) (Project, error) {
	row := s.db.QueryRowContext(ctx, "SELECT id,name,target_url,metadata_json,created_at,updated_at FROM projects WHERE id=?", cleanID(id))
	return scanProject(s, row)
}

func (s *Store) ListProjects(ctx context.Context, limit int) ([]Project, error) {
	limit = boundedLimit(limit, 100, 1000)
	rows, err := s.db.QueryContext(ctx, "SELECT id,name,target_url,metadata_json,created_at,updated_at FROM projects ORDER BY updated_at DESC LIMIT ?", limit)
	if err != nil {
		return nil, fmt.Errorf("list projects: %w", err)
	}
	defer rows.Close()
	projects := make([]Project, 0)
	for rows.Next() {
		project, err := scanProject(s, rows)
		if err != nil {
			return nil, err
		}
		projects = append(projects, project)
	}
	return projects, rows.Err()
}

func (s *Store) DeleteProject(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, "DELETE FROM projects WHERE id=?", cleanID(id))
	if err != nil {
		return fmt.Errorf("delete project: %w", err)
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) SaveEntity(ctx context.Context, kind string, entity Entity) (Entity, error) {
	return saveEntity(ctx, s.db, s, kind, entity)
}

func saveEntity(ctx context.Context, database databaseWriter, protector *Store, kind string, entity Entity) (Entity, error) {
	table, ok := entityTables[kind]
	if !ok {
		return Entity{}, fmt.Errorf("unsupported entity kind %q", kind)
	}
	entity.ProjectID = cleanID(entity.ProjectID)
	if entity.ProjectID == "" {
		return Entity{}, errors.New("project_id is required")
	}
	entity.ID = cleanID(entity.ID)
	if entity.ID == "" {
		entity.ID = newID(strings.TrimSuffix(kind, "s"))
	}
	if entity.Metadata == nil {
		entity.Metadata = map[string]any{}
	}
	metadata, err := json.Marshal(entity.Metadata)
	if err != nil {
		return Entity{}, fmt.Errorf("encode entity metadata: %w", err)
	}
	stamp := now()
	name, err := protector.seal(strings.TrimSpace(entity.Name))
	if err != nil {
		return Entity{}, err
	}
	value, err := protector.seal(entity.Value)
	if err != nil {
		return Entity{}, err
	}
	metadataValue, err := protector.seal(string(metadata))
	if err != nil {
		return Entity{}, err
	}
	query := fmt.Sprintf(`INSERT INTO %s(id,project_id,name,value,metadata_json,created_at,updated_at)
		VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,value=excluded.value,
		metadata_json=excluded.metadata_json,updated_at=excluded.updated_at`, table)
	_, err = database.ExecContext(ctx, query, entity.ID, entity.ProjectID, name, value, metadataValue, stamp, stamp)
	if err != nil {
		return Entity{}, fmt.Errorf("save %s: %w", kind, err)
	}
	query = fmt.Sprintf("SELECT id,project_id,name,value,metadata_json,created_at,updated_at FROM %s WHERE id=?", table)
	return scanEntity(protector, database.QueryRowContext(ctx, query, entity.ID))
}

func (s *Store) GetEntity(ctx context.Context, kind, id string) (Entity, error) {
	table, ok := entityTables[kind]
	if !ok {
		return Entity{}, fmt.Errorf("unsupported entity kind %q", kind)
	}
	query := fmt.Sprintf("SELECT id,project_id,name,value,metadata_json,created_at,updated_at FROM %s WHERE id=?", table)
	return scanEntity(s, s.db.QueryRowContext(ctx, query, cleanID(id)))
}

func (s *Store) ListEntities(ctx context.Context, kind, projectID string, limit int) ([]Entity, error) {
	table, ok := entityTables[kind]
	if !ok {
		return nil, fmt.Errorf("unsupported entity kind %q", kind)
	}
	limit = boundedLimit(limit, 200, 5000)
	query := fmt.Sprintf("SELECT id,project_id,name,value,metadata_json,created_at,updated_at FROM %s WHERE project_id=? ORDER BY created_at DESC LIMIT ?", table)
	rows, err := s.db.QueryContext(ctx, query, cleanID(projectID), limit)
	if err != nil {
		return nil, fmt.Errorf("list %s: %w", kind, err)
	}
	defer rows.Close()
	entities := make([]Entity, 0)
	for rows.Next() {
		entity, err := scanEntity(s, rows)
		if err != nil {
			return nil, err
		}
		entities = append(entities, entity)
	}
	return entities, rows.Err()
}

func (s *Store) DeleteEntity(ctx context.Context, kind, id string) error {
	table, ok := entityTables[kind]
	if !ok {
		return fmt.Errorf("unsupported entity kind %q", kind)
	}
	result, err := s.db.ExecContext(ctx, fmt.Sprintf("DELETE FROM %s WHERE id=?", table), cleanID(id))
	if err != nil {
		return err
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) ProjectSnapshot(ctx context.Context, projectID string) (map[string]any, error) {
	project, err := s.GetProject(ctx, projectID)
	if err != nil {
		return nil, err
	}
	snapshot := map[string]any{"format": "wshawk-project", "version": 1, "project": project}
	for kind := range entityTables {
		items, err := s.ListEntities(ctx, kind, projectID, 5000)
		if err != nil {
			return nil, err
		}
		snapshot[kind] = items
	}
	return snapshot, nil
}

func (s *Store) ImportJSON(ctx context.Context, raw []byte) (Project, error) {
	if len(raw) == 0 || len(raw) > 64*1024*1024 {
		return Project{}, errors.New("import size is invalid")
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(raw, &document); err != nil {
		return Project{}, fmt.Errorf("parse project import: %w", err)
	}
	var project Project
	legacyImport := false
	var legacy struct {
		ProjectID   string           `json:"projectId"`
		ProjectName string           `json:"projectName"`
		URL         string           `json:"url"`
		Findings    []map[string]any `json:"findings"`
		Logs        []map[string]any `json:"logs"`
		History     []map[string]any `json:"history"`
		Notes       []map[string]any `json:"notes"`
	}
	if projectRaw := document["project"]; len(projectRaw) > 0 {
		if err := json.Unmarshal(projectRaw, &project); err != nil {
			return Project{}, fmt.Errorf("parse imported project: %w", err)
		}
	} else {
		legacyImport = true
		if err := json.Unmarshal(raw, &legacy); err != nil {
			return Project{}, err
		}
		project = Project{ID: legacy.ProjectID, Name: legacy.ProjectName, TargetURL: legacy.URL, Metadata: map[string]any{"imported_from": "legacy-desktop"}}
	}
	project.ID = newID("project")
	project.Metadata = mergeMetadata(project.Metadata, map[string]any{"imported_at": now(), "source_ids_preserved": false})
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Project{}, fmt.Errorf("start project import: %w", err)
	}
	defer tx.Rollback()
	created, err := saveProject(ctx, tx, s, project)
	if err != nil {
		return Project{}, err
	}
	for kind := range entityTables {
		var entities []Entity
		if data := document[kind]; len(data) > 0 {
			if err := json.Unmarshal(data, &entities); err != nil {
				return Project{}, fmt.Errorf("parse imported %s: %w", kind, err)
			}
		}
		for _, entity := range entities {
			if entity.ID == "" && entity.ProjectID == "" && entity.Name == "" && entity.Value == "" && len(entity.Metadata) == 0 {
				continue
			}
			entity.ID = ""
			entity.ProjectID = created.ID
			if _, err := saveEntity(ctx, tx, s, kind, entity); err != nil {
				return Project{}, fmt.Errorf("import %s: %w", kind, err)
			}
		}
	}
	if legacyImport {
		for _, finding := range legacy.Findings {
			name := fmt.Sprint(finding["type"])
			value := fmt.Sprint(finding["payload"])
			if _, err := saveEntity(ctx, tx, s, "findings", Entity{ProjectID: created.ID, Name: name, Value: value, Metadata: finding}); err != nil {
				return Project{}, fmt.Errorf("import legacy finding: %w", err)
			}
		}
		for _, entry := range legacy.Logs {
			if _, err := saveEntity(ctx, tx, s, "timeline", Entity{ProjectID: created.ID, Name: fmt.Sprint(entry["type"]), Value: fmt.Sprint(entry["text"]), Metadata: entry}); err != nil {
				return Project{}, fmt.Errorf("import legacy log: %w", err)
			}
		}
		for _, frame := range legacy.History {
			if _, err := saveEntity(ctx, tx, s, "ws_frames", Entity{ProjectID: created.ID, Name: fmt.Sprint(frame["dir"]), Value: fmt.Sprint(frame["payload"]), Metadata: frame}); err != nil {
				return Project{}, fmt.Errorf("import legacy frame: %w", err)
			}
		}
		for _, note := range legacy.Notes {
			if _, err := saveEntity(ctx, tx, s, "notes", Entity{ProjectID: created.ID, Name: fmt.Sprint(note["title"]), Value: fmt.Sprint(note["content"]), Metadata: note}); err != nil {
				return Project{}, fmt.Errorf("import legacy note: %w", err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return Project{}, fmt.Errorf("commit project import: %w", err)
	}
	return created, nil
}

func (s *Store) Backup(ctx context.Context) (string, error) {
	if s.path == ":memory:" {
		return "", errors.New("memory database cannot be backed up")
	}
	if _, err := s.db.ExecContext(ctx, "PRAGMA wal_checkpoint(FULL)"); err != nil {
		return "", fmt.Errorf("checkpoint database: %w", err)
	}
	return backupFile(s.path, filepath.Join(filepath.Dir(s.path), "backups"), "manual")
}

func backupFile(source, directory, label string) (string, error) {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", err
	}
	destination := filepath.Join(directory, fmt.Sprintf("wshawk-%s-%s.db", label, time.Now().UTC().Format("20060102T150405.000000000Z")))
	in, err := os.Open(source)
	if err != nil {
		return "", err
	}
	defer in.Close()
	out, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	ok := false
	defer func() {
		out.Close()
		if !ok {
			os.Remove(destination)
		}
	}()
	if _, err := io.Copy(out, in); err != nil {
		return "", err
	}
	if err := out.Sync(); err != nil {
		return "", err
	}
	ok = true
	return destination, nil
}

type scanner interface{ Scan(dest ...any) error }

func scanProject(protector *Store, row scanner) (Project, error) {
	var project Project
	var raw string
	err := row.Scan(&project.ID, &project.Name, &project.TargetURL, &raw, &project.CreatedAt, &project.UpdatedAt)
	if err != nil {
		return Project{}, err
	}
	project.Name, err = protector.open(project.Name)
	if err != nil {
		return Project{}, err
	}
	project.TargetURL, err = protector.open(project.TargetURL)
	if err != nil {
		return Project{}, err
	}
	raw, err = protector.open(raw)
	if err != nil {
		return Project{}, err
	}
	if err := json.Unmarshal([]byte(raw), &project.Metadata); err != nil {
		project.Metadata = map[string]any{}
	}
	return project, nil
}

func scanEntity(protector *Store, row scanner) (Entity, error) {
	var entity Entity
	var raw string
	err := row.Scan(&entity.ID, &entity.ProjectID, &entity.Name, &entity.Value, &raw, &entity.CreatedAt, &entity.UpdatedAt)
	if err != nil {
		return Entity{}, err
	}
	entity.Name, err = protector.open(entity.Name)
	if err != nil {
		return Entity{}, err
	}
	entity.Value, err = protector.open(entity.Value)
	if err != nil {
		return Entity{}, err
	}
	raw, err = protector.open(raw)
	if err != nil {
		return Entity{}, err
	}
	if err := json.Unmarshal([]byte(raw), &entity.Metadata); err != nil {
		entity.Metadata = map[string]any{}
	}
	return entity, nil
}

func newID(prefix string) string {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return prefix + "_" + hex.EncodeToString(buffer)
}

func cleanID(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 128 {
		return ""
	}
	for _, char := range value {
		if !(char == '_' || char == '-' || char == '.' || char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9') {
			return ""
		}
	}
	return value
}

func boundedLimit(value, fallback, maximum int) int {
	if value <= 0 {
		return fallback
	}
	if value > maximum {
		return maximum
	}
	return value
}

func now() string { return time.Now().UTC().Format(time.RFC3339Nano) }

func mergeMetadata(left, right map[string]any) map[string]any {
	result := map[string]any{}
	for key, value := range left {
		result[key] = value
	}
	for key, value := range right {
		result[key] = value
	}
	return result
}
