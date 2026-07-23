package protocolmap

import (
	"context"
	"testing"

	"github.com/regaan/wshawk/electron-desktop/backend-go/internal/store"
)

func TestBuildsFamiliesTransitionsAndRecommendations(t *testing.T) {
	database, err := store.OpenMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	project, _ := database.SaveProject(context.Background(), store.Project{Name: "map lab"})
	connection, _ := database.SaveEntity(context.Background(), "ws_connections", store.Entity{ProjectID: project.ID, Name: "ws://lab/ws", Metadata: map[string]any{"url": "ws://lab/ws", "status": "closed"}})
	for _, payload := range []string{`{"type":"subscribe","tenant_id":"alpha"}`, `{"type":"message","tenant_id":"alpha","text":"hello"}`} {
		if _, err := database.SaveEntity(context.Background(), "ws_frames", store.Entity{ProjectID: project.ID, Name: "outbound", Value: payload, Metadata: map[string]any{"connection_id": connection.ID, "message_type": "text"}}); err != nil {
			t.Fatal(err)
		}
	}
	result, err := Build(context.Background(), database, project.ID)
	if err != nil {
		t.Fatal(err)
	}
	summary := result["summary"].(map[string]any)
	if summary["frame_count"] != 2 || summary["family_count"] != 2 {
		t.Fatalf("unexpected protocol summary: %#v", summary)
	}
	if len(result["transitions"].([]map[string]any)) != 1 {
		t.Fatalf("expected one state transition: %#v", result["transitions"])
	}
	if len(result["recommended_attacks"].([]map[string]any)) < 2 {
		t.Fatalf("expected field-driven recommendations: %#v", result["recommended_attacks"])
	}
}
