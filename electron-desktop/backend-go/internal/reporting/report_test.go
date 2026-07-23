package reporting

import (
	"context"
	"strings"
	"testing"

	"github.com/regaan/wshawk/electron-desktop/backend-go/internal/store"
)

func TestAllReportFormatsAndBundleIntegrity(t *testing.T) {
	database, err := store.OpenMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	project, _ := database.SaveProject(context.Background(), store.Project{Name: "report lab"})
	_, _ = database.SaveEntity(context.Background(), "findings", store.Entity{ProjectID: project.ID, Name: "xss", Value: "probe", Metadata: map[string]any{"severity": "high", "detail": "reflected marker", "url": "https://example.test"}})
	generator := New(database)
	for _, format := range []string{"json", "html", "csv", "sarif", "markdown"} {
		report, reportErr := generator.Generate(context.Background(), project.ID, format)
		if reportErr != nil {
			t.Fatal(reportErr)
		}
		if report["bytes"].(int) == 0 || report["sha256"] == "" {
			t.Fatalf("invalid %s report: %#v", format, report)
		}
	}
	bundle, err := generator.Bundle(context.Background(), project.ID)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyBundle(bundle["content_base64"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if verified["valid"] != true {
		t.Fatalf("bundle verification failed: %#v", verified)
	}
}

func TestJSONReportOmitsLargeRawFlowsAndIdentitySecrets(t *testing.T) {
	database, err := store.OpenMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	project, _ := database.SaveProject(context.Background(), store.Project{Name: "large report"})
	largeMarker := "RAW_HTTP_BODY_MUST_NOT_ENTER_REPORT"
	for index := 0; index < 18; index++ {
		_, _ = database.SaveEntity(context.Background(), "http_flows", store.Entity{ProjectID: project.ID, Name: "GET /large", Value: largeMarker + strings.Repeat("x", 1024*1024), Metadata: map[string]any{"status": 200, "url": "https://example.test"}})
	}
	_, _ = database.SaveEntity(context.Background(), "identities", store.Entity{ProjectID: project.ID, Name: "user", Value: "IDENTITY_SECRET", Metadata: map[string]any{"token": "IDENTITY_SECRET"}})
	report, err := New(database).Generate(context.Background(), project.ID, "json")
	if err != nil {
		t.Fatal(err)
	}
	content := report["content"].(string)
	if strings.Contains(content, largeMarker) || strings.Contains(content, "IDENTITY_SECRET") {
		t.Fatal("JSON report exposed a raw flow body or identity secret")
	}
	if report["bytes"].(int) >= 8*1024*1024 || !strings.Contains(content, "raw_value_omitted") {
		t.Fatalf("JSON report was not compacted safely: %d bytes", report["bytes"].(int))
	}
}
