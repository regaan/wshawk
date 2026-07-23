package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/regaan/wshawk/electron-desktop/backend-go/internal/protocol"
)

func TestServerHealthAndGracefulShutdown(t *testing.T) {
	input := strings.NewReader(
		`{"version":"1","id":"health","method":"system.health","params":{}}` + "\n" +
			`{"version":"1","id":"shutdown","method":"system.shutdown","params":{}}` + "\n",
	)
	var output bytes.Buffer
	var diagnostics bytes.Buffer
	server := NewServer(input, &output, &diagnostics)

	if code := server.Run(); code != 0 {
		t.Fatalf("server returned %d: %s", code, diagnostics.String())
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected two responses, got %d: %s", len(lines), output.String())
	}

	var health protocol.Response
	if err := json.Unmarshal([]byte(lines[0]), &health); err != nil {
		t.Fatal(err)
	}
	result, ok := health.Result.(map[string]any)
	if !ok || result["noNetworkBridge"] != true || result["transport"] != "stdio-json-rpc" {
		t.Fatalf("unexpected health result: %#v", health.Result)
	}

	var shutdown protocol.Response
	if err := json.Unmarshal([]byte(lines[1]), &shutdown); err != nil {
		t.Fatal(err)
	}
	if shutdown.Error != nil {
		t.Fatalf("shutdown failed: %#v", shutdown.Error)
	}
}

func TestTrackedOperationCanBeCancelled(t *testing.T) {
	server := NewServer(strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	defer server.Close()
	ctx, finish, err := server.beginOperation("crawl-test", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer finish()
	if !server.cancelOperation("crawl-test") {
		t.Fatal("operation cancellation was not accepted")
	}
	select {
	case <-ctx.Done():
		if ctx.Err() != context.Canceled {
			t.Fatalf("unexpected context result: %v", ctx.Err())
		}
	case <-time.After(time.Second):
		t.Fatal("operation context was not cancelled")
	}
}

func TestServerRejectsUnknownMethod(t *testing.T) {
	input := strings.NewReader(`{"version":"1","id":"unknown","method":"network.listen","params":{}}` + "\n")
	var output bytes.Buffer
	server := NewServer(input, &output, &bytes.Buffer{})
	if code := server.Run(); code != 0 {
		t.Fatalf("server returned %d", code)
	}

	var response protocol.Response
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &response); err != nil {
		t.Fatal(err)
	}
	if response.Error == nil || response.Error.Code != "method_not_found" {
		t.Fatalf("unexpected response: %#v", response)
	}
}

func TestAuthorizationDifferenceRequiresExplicitConfirmation(t *testing.T) {
	input := strings.NewReader(`{"version":"1","id":"authz","method":"scanner.authz_diff","params":{"left":{"url":"https://example.invalid/"},"right":{"url":"https://example.invalid/"}}}` + "\n")
	var output bytes.Buffer
	server := NewServer(input, &output, &bytes.Buffer{})
	if code := server.Run(); code != 0 {
		t.Fatalf("server returned %d", code)
	}
	var response protocol.Response
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &response); err != nil {
		t.Fatal(err)
	}
	if response.Error == nil || response.Error.Code != "authorization_required" {
		t.Fatalf("unexpected response: %#v", response)
	}
}

func TestAuthorizationMatrixRequiresExplicitConfirmation(t *testing.T) {
	input := strings.NewReader(`{"version":"1","id":"authz","method":"scanner.authz_matrix","params":{"cases":[{"alias":"a"},{"alias":"b"}]}}` + "\n")
	var output bytes.Buffer
	server := NewServer(input, &output, &bytes.Buffer{})
	if code := server.Run(); code != 0 {
		t.Fatalf("server returned %d", code)
	}
	var response protocol.Response
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &response); err != nil {
		t.Fatal(err)
	}
	if response.Error == nil || response.Error.Code != "authorization_required" {
		t.Fatalf("unexpected response: %#v", response)
	}
}
