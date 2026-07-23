package websec

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/regaan/wshawk/electron-desktop/backend-go/internal/store"
)

func TestRequestCaptureCrawlAndAnalyze(t *testing.T) {
	database, err := store.OpenMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	project, err := database.SaveProject(context.Background(), store.Project{Name: "lab"})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/" {
			writer.Header().Set("Content-Type", "text/html")
			_, _ = writer.Write([]byte(`<a href="/next">next</a><form action="/save"></form>`))
			return
		}
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	client := New(database)
	response, err := client.Do(context.Background(), Request{ProjectID: project.ID, URL: server.URL, Method: "GET"})
	if err != nil {
		t.Fatal(err)
	}
	if response.Status != 200 || response.FlowID == "" {
		t.Fatalf("unexpected response: %#v", response)
	}
	findings := Analyze(response, server.URL)
	if len(findings) == 0 {
		t.Fatal("expected header/CSRF findings")
	}
	crawl, err := client.Crawl(context.Background(), CrawlOptions{ProjectID: project.ID, URL: server.URL, MaxPages: 5, Depth: 2})
	if err != nil {
		t.Fatal(err)
	}
	if crawl["visited"].(int) < 2 {
		t.Fatalf("expected linked page: %#v", crawl)
	}
}

func TestCrawlDoesNotFollowCrossOriginRedirect(t *testing.T) {
	database, err := store.OpenMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var externalRequests atomic.Int32
	external := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		externalRequests.Add(1)
		writer.WriteHeader(http.StatusOK)
	}))
	defer external.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Location", external.URL+"/outside")
		writer.WriteHeader(http.StatusFound)
	}))
	defer origin.Close()

	client := New(database)
	result, err := client.Crawl(context.Background(), CrawlOptions{URL: origin.URL, MaxPages: 1, Depth: 1, TimeoutMS: 1000})
	if err != nil {
		t.Fatal(err)
	}
	if externalRequests.Load() != 0 {
		t.Fatalf("crawler escaped its origin and sent %d external request(s)", externalRequests.Load())
	}
	pages := result["pages"].([]map[string]any)
	if len(pages) != 1 || pages[0]["status"] != http.StatusFound {
		t.Fatalf("expected the same-origin redirect response to be retained: %#v", result)
	}
}

func TestDirectoryScanFiltersSoft404Responses(t *testing.T) {
	database, err := store.OpenMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "text/html")
		if request.URL.Path == "/admin" {
			_, _ = writer.Write([]byte("<main>real administration endpoint with unique content</main>"))
			return
		}
		_, _ = writer.Write([]byte("<main>single-page application fallback</main>"))
	}))
	defer server.Close()

	result, err := New(database).DirectoryScan(context.Background(), "", server.URL, []string{"admin", "definitely-missing"}, 2, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if result["wildcard_detected"] != true || result["soft_404_filtered"] != 1 {
		t.Fatalf("expected the wildcard fallback to be detected and filtered: %#v", result)
	}
	encoded, err := json.Marshal(result["found"])
	if err != nil {
		t.Fatal(err)
	}
	var found []struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(encoded, &found); err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 || found[0].URL != server.URL+"/admin" {
		t.Fatalf("expected only the real endpoint to remain: %#v", result)
	}
}

func TestAnalyzeDoesNotApplyDocumentHeadersToRedirectsOrDenials(t *testing.T) {
	for _, status := range []int{http.StatusPermanentRedirect, http.StatusForbidden} {
		findings := Analyze(Response{Status: status, Headers: map[string][]string{"Content-Type": {"text/html"}}}, "https://example.test")
		for _, finding := range findings {
			if finding["type"] == "missing-csp" || finding["type"] == "missing-nosniff" || finding["type"] == "missing-referrer-policy" {
				t.Fatalf("document-only header finding %q was emitted for HTTP %d", finding["type"], status)
			}
		}
	}
}
