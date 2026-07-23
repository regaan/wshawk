package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/regaan/wshawk/electron-desktop/backend-go/internal/store"
	"github.com/regaan/wshawk/electron-desktop/backend-go/internal/websec"
)

func TestScannerFindsLabSQLAndReflection(t *testing.T) {
	database, err := store.OpenMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	project, err := database.SaveProject(context.Background(), store.Project{Name: "scanner lab"})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		value := request.URL.Query().Get("q")
		if strings.Contains(value, "'") {
			writer.WriteHeader(500)
			_, _ = writer.Write([]byte("SQL syntax error near quote"))
			return
		}
		_, _ = writer.Write([]byte(value))
	}))
	defer server.Close()
	engine := New(websec.New(database), database, func(string, any) {})
	result, err := engine.Run(context.Background(), Options{ProjectID: project.ID, Request: websec.Request{URL: server.URL, Method: "GET"}, Parameter: "q", Location: "query", Categories: []string{"sqli", "xss"}, AuthorizationConfirmed: true})
	if err != nil {
		t.Fatal(err)
	}
	findings := result["findings"].([]map[string]any)
	if len(findings) < 2 {
		t.Fatalf("expected SQL and XSS findings, got %#v", findings)
	}
}

func TestScannerUsesBoundedConcurrency(t *testing.T) {
	database, _ := store.OpenMemory()
	defer database.Close()
	project, err := database.SaveProject(context.Background(), store.Project{Name: "concurrency lab"})
	if err != nil {
		t.Fatal(err)
	}
	var current atomic.Int32
	var maximum atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		active := current.Add(1)
		defer current.Add(-1)
		for {
			observed := maximum.Load()
			if active <= observed || maximum.CompareAndSwap(observed, active) {
				break
			}
		}
		time.Sleep(30 * time.Millisecond)
		_, _ = writer.Write([]byte(request.URL.Query().Get("q")))
	}))
	defer server.Close()
	engine := New(websec.New(database), database, func(string, any) {})
	_, err = engine.Run(context.Background(), Options{ProjectID: project.ID, Request: websec.Request{URL: server.URL, Method: "GET", TimeoutMS: 1000}, Parameter: "q", Location: "query", Categories: []string{"sqli", "xss", "command_injection", "path_traversal"}, AuthorizationConfirmed: true, Concurrency: 4})
	if err != nil {
		t.Fatal(err)
	}
	if maximum.Load() < 2 || maximum.Load() > 4 {
		t.Fatalf("expected bounded request concurrency between 2 and 4, observed %d", maximum.Load())
	}
}
func TestScannerRequiresAuthorization(t *testing.T) {
	database, _ := store.OpenMemory()
	defer database.Close()
	engine := New(websec.New(database), database, func(string, any) {})
	if _, err := engine.Run(context.Background(), Options{}); err == nil {
		t.Fatal("active scanner must require confirmation")
	}
}

func TestRedirectFindingRequiresExternalDestination(t *testing.T) {
	payload := Payload{Category: "redirect", Value: "https://wshawk.invalid/redirect-probe", Marker: "wshawk.invalid"}
	baseline := websec.Response{Status: http.StatusOK}
	preservedQuery := websec.Response{Status: http.StatusPermanentRedirect, Headers: map[string][]string{"Location": {"https://example.test/?next=https%3A%2F%2Fwshawk.invalid%2Fredirect-probe"}}}
	if finding := detectFinding(payload, baseline, preservedQuery, "https://www.example.test/?next=https%3A%2F%2Fwshawk.invalid%2Fredirect-probe"); finding != nil {
		t.Fatalf("same-site redirect preserving the canary query was a false positive: %#v", finding)
	}
	external := websec.Response{Status: http.StatusFound, Headers: map[string][]string{"Location": {"https://wshawk.invalid/redirect-probe"}}}
	if finding := detectFinding(payload, baseline, external, "https://example.test/?next=probe"); finding == nil {
		t.Fatal("expected a direct external redirect destination to be detected")
	}
}
func TestBinaryAnalysis(t *testing.T) {
	result, err := AnalyzeBinary("iVBORw0KGgo=")
	if err != nil {
		t.Fatal(err)
	}
	if result["magic"] != "png" {
		t.Fatalf("unexpected analysis: %#v", result)
	}
}

func TestAuthzDiffDoesNotFlagIdenticalResponses(t *testing.T) {
	database, _ := store.OpenMemory()
	defer database.Close()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("X-Role") == "admin" {
			_, _ = writer.Write([]byte("admin-only"))
			return
		}
		_, _ = writer.Write([]byte("same-response"))
	}))
	defer server.Close()
	engine := New(websec.New(database), database, func(string, any) {})
	identical, err := engine.AuthzDiff(context.Background(), websec.Request{URL: server.URL}, websec.Request{URL: server.URL})
	if err != nil || identical["authorization_difference"] != "none" {
		t.Fatalf("identical responses were flagged: %#v %v", identical, err)
	}
	different, err := engine.AuthzDiff(context.Background(), websec.Request{URL: server.URL}, websec.Request{URL: server.URL, Headers: map[string]string{"X-Role": "admin"}})
	if err != nil || different["authorization_difference"] != "medium" {
		t.Fatalf("different bodies were not flagged: %#v %v", different, err)
	}
}

func TestAuthzDiffOwnershipPolicyClassifiesEnforcedIDORAndStaleIdentity(t *testing.T) {
	database, _ := store.OpenMemory()
	defer database.Close()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		identity := request.Header.Get("X-Identity")
		if identity == "stale" {
			writer.WriteHeader(http.StatusUnauthorized)
			_, _ = writer.Write([]byte(`{"error":"authentication_required"}`))
			return
		}
		if request.URL.Path == "/secure" && identity == "attacker" {
			writer.WriteHeader(http.StatusForbidden)
			_, _ = writer.Write([]byte(`{"error":"forbidden"}`))
			return
		}
		_, _ = writer.Write([]byte(`{"id":"resource-b","owner":"user_b","secret":"private"}`))
	}))
	defer server.Close()
	engine := New(websec.New(database), database, func(string, any) {})
	policy := AuthzPolicy{Mode: AuthzPolicyPrimaryDeniedOwnerAllow}
	request := func(path, identity string) websec.Request {
		return websec.Request{URL: server.URL + path, Headers: map[string]string{"X-Identity": identity}}
	}

	enforced, err := engine.AuthzDiffWithPolicy(context.Background(), request("/secure", "attacker"), request("/secure", "owner"), policy)
	if err != nil || enforced["policy_evaluation"].(map[string]any)["verdict"] != "access_control_enforced" {
		t.Fatalf("expected enforced access control, got %#v %v", enforced, err)
	}

	idor, err := engine.AuthzDiffWithPolicy(context.Background(), request("/insecure", "attacker"), request("/insecure", "owner"), policy)
	evaluation := idor["policy_evaluation"].(map[string]any)
	if err != nil || evaluation["verdict"] != "potential_idor" || evaluation["finding"] != true || evaluation["confidence"] != "high" {
		t.Fatalf("expected a high-confidence potential IDOR, got %#v %v", idor, err)
	}

	stale, err := engine.AuthzDiffWithPolicy(context.Background(), request("/insecure", "stale"), request("/insecure", "owner"), policy)
	if err != nil || stale["policy_evaluation"].(map[string]any)["verdict"] != "invalid_identity" {
		t.Fatalf("expected stale identity classification, got %#v %v", stale, err)
	}
}

func TestAuthzMatrixRequiresMultipleConfirmedObjectsAndUnderstandsSemanticDenials(t *testing.T) {
	database, _ := store.OpenMemory()
	defer database.Close()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		identity := request.Header.Get("X-Identity")
		object := request.URL.Query().Get("id")
		if identity == "stale" {
			writer.WriteHeader(http.StatusUnauthorized)
			_, _ = writer.Write([]byte(`{"error":"expired"}`))
			return
		}
		if strings.HasPrefix(object, "secure") && identity == "attacker" {
			// A 200 application-level denial must not be treated as successful access.
			_, _ = writer.Write([]byte(`{"error":"access denied"}`))
			return
		}
		_, _ = writer.Write([]byte(`{"id":"` + object + `","owner":"user_b","note":"private","timestamp":"dynamic"}`))
	}))
	defer server.Close()
	engine := New(websec.New(database), database, func(string, any) {})
	request := func(identity, object string) websec.Request {
		return websec.Request{URL: server.URL + "?id=" + object, Headers: map[string]string{"X-Identity": identity}}
	}
	cases := []AuthzCase{
		{ID: "a-one", Alias: "attacker", Expectation: "deny", ObjectValue: "foreign-1", Request: request("attacker", "foreign-1")},
		{ID: "o-one", Alias: "owner", Expectation: "allow", ObjectValue: "foreign-1", Request: request("owner", "foreign-1")},
		{ID: "a-two", Alias: "attacker", Expectation: "deny", ObjectValue: "foreign-2", Request: request("attacker", "foreign-2")},
		{ID: "o-two", Alias: "owner", Expectation: "allow", ObjectValue: "foreign-2", Request: request("owner", "foreign-2")},
	}
	result, err := engine.AuthzMatrix(context.Background(), AuthzMatrixOptions{Cases: cases, Policy: AuthzPolicy{Mode: AuthzPolicyPrimaryDeniedOwnerAllow, MinimumConfirmations: 2}})
	if err != nil {
		t.Fatal(err)
	}
	evaluation := result["evaluation"].(map[string]any)
	if evaluation["verdict"] != "potential_idor" || evaluation["finding"] != true || evaluation["confirmation_count"] != 2 {
		t.Fatalf("expected a confirmed two-object IDOR, got %#v", evaluation)
	}

	secure, err := engine.AuthzMatrix(context.Background(), AuthzMatrixOptions{Cases: []AuthzCase{
		{Alias: "attacker", Expectation: "deny", ObjectValue: "secure-1", Request: request("attacker", "secure-1")},
		{Alias: "owner", Expectation: "allow", ObjectValue: "secure-1", Request: request("owner", "secure-1")},
	}, Policy: AuthzPolicy{Mode: AuthzPolicyPrimaryDeniedOwnerAllow}})
	if err != nil || secure["evaluation"].(map[string]any)["verdict"] != "access_control_enforced" {
		t.Fatalf("semantic denial was not recognized: %#v (%v)", secure, err)
	}
}

func TestAuthzMatrixRequiresWriteConfirmationAndHandlesGraphQLErrors(t *testing.T) {
	database, _ := store.OpenMemory()
	defer database.Close()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("X-Identity") == "attacker" {
			_, _ = writer.Write([]byte(`{"data":null,"errors":[{"message":"forbidden"}]}`))
			return
		}
		_, _ = writer.Write([]byte(`{"data":{"deleteInvoice":{"id":"invoice-b","secret":"owner-only"}}}`))
	}))
	defer server.Close()
	engine := New(websec.New(database), database, func(string, any) {})
	cases := []AuthzCase{
		{Alias: "attacker", Expectation: "deny", Request: websec.Request{URL: server.URL, Method: http.MethodPost, Headers: map[string]string{"X-Identity": "attacker"}}},
		{Alias: "admin", Expectation: "allow", Request: websec.Request{URL: server.URL, Method: http.MethodPost, Headers: map[string]string{"X-Identity": "admin"}}},
	}
	dryRun, err := engine.AuthzMatrix(context.Background(), AuthzMatrixOptions{Cases: cases, Policy: AuthzPolicy{Mode: AuthzPolicyFunctionLevel}, WriteMode: "dry_run"})
	if err != nil || dryRun["evaluation"].(map[string]any)["verdict"] != "dry_run_planned" {
		t.Fatalf("state-changing authorization matrix did not produce a non-transmitting dry-run plan: %#v (%v)", dryRun, err)
	}
	result, err := engine.AuthzMatrix(context.Background(), AuthzMatrixOptions{Cases: cases, Policy: AuthzPolicy{Mode: AuthzPolicyFunctionLevel}, SafeWriteConfirmed: true})
	if err != nil || result["evaluation"].(map[string]any)["verdict"] != "access_control_enforced" {
		t.Fatalf("GraphQL errors were not treated as an enforced denial: %#v (%v)", result, err)
	}
}

func TestStructuredAndXMLMutationsPreserveAttackTypes(t *testing.T) {
	request := websec.Request{URL: "https://lab.invalid", Method: "POST", Body: `{"user":"guest"}`}
	nosql, err := mutateRequest(request, "user", "json", Payload{Category: "nosql_injection", Value: `{"$ne":null}`})
	if err != nil || !strings.Contains(nosql.Body, `"user":{"$ne":null}`) {
		t.Fatalf("NoSQL operator was encoded as a string: %q (%v)", nosql.Body, err)
	}
	prototype, err := mutateRequest(request, "unused", "json", Payload{Category: "prototype_pollution", Value: `{"__proto__":{"wshawk_probe":true}}`})
	if err != nil || !strings.Contains(prototype.Body, `"__proto__":{"wshawk_probe":true}`) {
		t.Fatalf("prototype keys were not injected at document scope: %q (%v)", prototype.Body, err)
	}
	xml, err := mutateRequest(websec.Request{URL: "https://lab.invalid", Method: "POST"}, "unused", "xml", Payload{Category: "xxe", Value: "<!DOCTYPE r><r/>"})
	if err != nil || xml.Body != "<!DOCTYPE r><r/>" || xml.Headers["Content-Type"] != "application/xml" {
		t.Fatalf("XML mutation was not preserved: %#v (%v)", xml, err)
	}
}

func TestRaceFlagsRepeatedAcceptedStateChangesForManualReview(t *testing.T) {
	database, _ := store.OpenMemory()
	defer database.Close()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte(`{"accepted":true}`))
	}))
	defer server.Close()
	engine := New(websec.New(database), database, func(string, any) {})
	result, err := engine.Race(context.Background(), websec.Request{URL: server.URL, Method: http.MethodPost}, 5)
	if err != nil || result["possible_race"] != true || result["confidence"] != "manual-review" {
		t.Fatalf("repeated state changes were not surfaced for review: %#v (%v)", result, err)
	}
}
