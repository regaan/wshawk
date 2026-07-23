package workflow

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/regaan/wshawk/electron-desktop/backend-go/internal/store"
	"github.com/regaan/wshawk/electron-desktop/backend-go/internal/websec"
)

func TestWorkflowExtractsAndSubstitutesVariables(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/token" {
			response.Header().Set("Set-Cookie", "session=lab-session; HttpOnly")
			_, _ = response.Write([]byte(`{"csrf":"abc123"}`))
			return
		}
		if request.URL.Query().Get("csrf") != "abc123" || request.Header.Get("X-Session") != "lab-session" {
			t.Errorf("workflow variables were not substituted: url=%s session=%q", request.URL.String(), request.Header.Get("X-Session"))
			response.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer server.Close()
	database, _ := store.OpenMemory()
	defer database.Close()
	project, _ := database.SaveProject(context.Background(), store.Project{Name: "workflow lab"})
	runner := New(websec.New(database), database, func(string, any) {})
	result, err := runner.Run(context.Background(), Options{ProjectID: project.ID, AuthorizationConfirmed: true, Steps: []Step{
		{Name: "extract", Method: "GET", URL: server.URL + "/token", Extract: []ExtractRule{{Variable: "csrf", From: "body", Regex: `"csrf":"([^"]+)"`}, {Variable: "session", From: "cookies", Regex: `session=([^;]+)`}}},
		{Name: "reuse", Method: "GET", URL: server.URL + "/use?csrf={{csrf}}", Headers: map[string]string{"X-Session": "{{session}}"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	summary := result["workflow"].(map[string]any)["summary"].(map[string]any)
	if summary["completed"] != 2 || summary["errors"] != 0 {
		t.Fatalf("unexpected workflow summary: %#v", summary)
	}
}

func TestWorkflowRequiresAuthorization(t *testing.T) {
	database, _ := store.OpenMemory()
	defer database.Close()
	runner := New(websec.New(database), database, func(string, any) {})
	if _, err := runner.Run(context.Background(), Options{ProjectID: "project", Steps: []Step{{URL: "https://example.invalid"}}}); err == nil {
		t.Fatal("expected authorization error")
	}
}
