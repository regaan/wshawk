package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSendRequiresConfirmation(t *testing.T) {
	if _, err := Send(context.Background(), Request{Kind: "webhook", URL: "https://example.invalid"}); err == nil {
		t.Fatal("expected explicit confirmation error")
	}
}

func TestDefectDojoRequestUsesExpectedEndpointAndToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/v2/import-scan/" {
			t.Errorf("unexpected endpoint %q", request.URL.Path)
		}
		if request.Header.Get("Authorization") != "Token lab-token" {
			t.Errorf("unexpected authorization header %q", request.Header.Get("Authorization"))
		}
		response.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	result, err := Send(context.Background(), Request{
		Kind: "DefectDojo", URL: server.URL, Token: "lab-token",
		Payload: map[string]any{"scan_type": "SARIF"}, AuthorizationConfirmed: true,
	})
	if err != nil || result["ok"] != true {
		t.Fatalf("unexpected integration result: %#v %v", result, err)
	}
}
