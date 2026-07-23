package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestProjectEntitiesSnapshotAndImport(t *testing.T) {
	ctx := context.Background()
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	project, err := store.SaveProject(ctx, Project{Name: "Lab", TargetURL: "wss://example.test/ws"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SaveEntity(ctx, "notes", Entity{ProjectID: project.ID, Name: "scope", Value: "owned lab"}); err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.ProjectSnapshot(ctx, project.ID)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(snapshot)
	imported, err := store.ImportJSON(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	if imported.ID == project.ID {
		t.Fatal("import must create an independent project")
	}
	notes, err := store.ListEntities(ctx, "notes", imported.ID, 10)
	if err != nil || len(notes) != 1 || notes[0].Value != "owned lab" {
		t.Fatalf("unexpected imported notes: %#v %v", notes, err)
	}
}

func TestProjectDatabaseEncryptsSensitiveFieldsAtRest(t *testing.T) {
	directory := t.TempDir()
	database, err := Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	project, err := database.SaveProject(context.Background(), Project{Name: "Secret project name", TargetURL: "https://private.example.test/account/123"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = database.SaveEntity(context.Background(), "identities", Entity{ProjectID: project.ID, Name: "admin identity", Value: "Bearer TOP-SECRET-TOKEN", Metadata: map[string]any{"cookie": "PRIVATE-COOKIE"}}); err != nil {
		t.Fatal(err)
	}
	if err = database.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(directory, "wshawk-go.db"))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range [][]byte{[]byte("Secret project name"), []byte("private.example.test"), []byte("TOP-SECRET-TOKEN"), []byte("PRIVATE-COOKIE")} {
		if bytes.Contains(raw, secret) {
			t.Fatalf("plaintext secret remained in encrypted database: %q", secret)
		}
	}
	database, err = Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	loaded, err := database.GetProject(context.Background(), project.ID)
	if err != nil || loaded.Name != "Secret project name" {
		t.Fatalf("encrypted project did not round-trip: %#v %v", loaded, err)
	}
	identities, err := database.ListEntities(context.Background(), "identities", project.ID, 10)
	if err != nil || len(identities) != 1 || !bytes.Contains([]byte(identities[0].Value), []byte("TOP-SECRET-TOKEN")) {
		t.Fatalf("encrypted entity did not round-trip: %#v %v", identities, err)
	}
}

func TestMigrationBackupAndManualBackup(t *testing.T) {
	directory := t.TempDir()
	store, err := Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	backup, err := store.Backup(context.Background())
	store.Close()
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(backup); err != nil || info.Size() == 0 {
		t.Fatalf("invalid backup %q: %v", backup, err)
	}
	store, err = Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	store.Close()
	entries, err := filepath.Glob(filepath.Join(directory, "backups", "wshawk-pre-migration-*.db"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("current schema must not create startup migration backups: %#v %v", entries, err)
	}
}

func TestPendingMigrationCreatesBackup(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "wshawk-go.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE legacy_marker(value TEXT); INSERT INTO legacy_marker(value) VALUES('preserve me')"); err != nil {
		db.Close()
		t.Fatal(err)
	}
	db.Close()

	store, err := Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	store.Close()
	entries, err := filepath.Glob(filepath.Join(directory, "backups", "wshawk-pre-migration-*.db"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("expected exactly one pre-migration backup: %#v %v", entries, err)
	}
}

func TestRejectsUnknownEntityKind(t *testing.T) {
	store, err := OpenMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.SaveEntity(context.Background(), "arbitrary_table", Entity{}); err == nil {
		t.Fatal("expected table allowlist error")
	}
}

func TestImportsLegacyDesktopState(t *testing.T) {
	store, err := OpenMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	raw := []byte(`{"projectId":"old-id","projectName":"Copied","url":"wss://lab.invalid/ws","findings":[{"type":"xss","severity":"HIGH","payload":"probe"}],"logs":[{"type":"info","text":"captured"}],"history":[{"dir":"IN","payload":"hello"}]}`)
	project, err := store.ImportJSON(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	findings, _ := store.ListEntities(context.Background(), "findings", project.ID, 10)
	frames, _ := store.ListEntities(context.Background(), "ws_frames", project.ID, 10)
	if len(findings) != 1 || len(frames) != 1 {
		t.Fatalf("legacy import lost state: findings=%#v frames=%#v", findings, frames)
	}
}

func TestImportRollsBackCompletelyOnEntityFailure(t *testing.T) {
	store, err := OpenMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.db.Exec(`CREATE TRIGGER reject_import_note BEFORE INSERT ON notes BEGIN SELECT RAISE(ABORT, 'forced import failure'); END`); err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"project":{"name":"must rollback"},"notes":[{"name":"failure","value":"trigger"}]}`)
	if _, err := store.ImportJSON(context.Background(), raw); err == nil {
		t.Fatal("expected forced import failure")
	}
	projects, err := store.ListProjects(context.Background(), 10)
	if err != nil || len(projects) != 0 {
		t.Fatalf("partial project survived failed import: %#v %v", projects, err)
	}
}
