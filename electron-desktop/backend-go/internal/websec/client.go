package websec

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/regaan/wshawk/electron-desktop/backend-go/internal/store"
)

const maxBodyBytes = 4 * 1024 * 1024

type Request struct {
	ProjectID              string            `json:"project_id"`
	URL                    string            `json:"url"`
	Method                 string            `json:"method"`
	Headers                map[string]string `json:"headers"`
	Body                   string            `json:"body"`
	BodyBase64             string            `json:"body_base64"`
	TimeoutMS              int               `json:"timeout_ms"`
	TLSSkipVerify          bool              `json:"tls_skip_verify"`
	FollowRedirects        bool              `json:"follow_redirects"`
	RestrictRedirectOrigin bool              `json:"restrict_redirect_origin"`
}

type Response struct {
	Status       int                 `json:"status"`
	StatusText   string              `json:"status_text"`
	Headers      map[string][]string `json:"headers"`
	Body         string              `json:"body,omitempty"`
	BodyBase64   string              `json:"body_base64,omitempty"`
	BodyEncoding string              `json:"body_encoding"`
	BodyBytes    int                 `json:"body_bytes"`
	Truncated    bool                `json:"truncated"`
	DurationMS   int64               `json:"duration_ms"`
	FinalURL     string              `json:"final_url"`
	SHA256       string              `json:"sha256"`
	TLS          map[string]any      `json:"tls,omitempty"`
	FlowID       string              `json:"flow_id,omitempty"`
}

type Client struct{ store *store.Store }

func New(database *store.Store) *Client { return &Client{store: database} }

func (c *Client) Do(ctx context.Context, request Request) (Response, error) {
	parsed, err := url.Parse(strings.TrimSpace(request.URL))
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return Response{}, errors.New("target must be an absolute http:// or https:// URL")
	}
	method := strings.ToUpper(strings.TrimSpace(request.Method))
	if method == "" {
		method = http.MethodGet
	}
	body := []byte(request.Body)
	if request.BodyBase64 != "" {
		body, err = base64.StdEncoding.DecodeString(request.BodyBase64)
		if err != nil {
			return Response{}, errors.New("body_base64 is invalid")
		}
	}
	if len(body) > maxBodyBytes {
		return Response{}, errors.New("request body exceeds 4 MiB limit")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: request.TLSSkipVerify} // #nosec G402 -- explicit operator-controlled lab option.
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: tlsConfig, ForceAttemptHTTP2: true, MaxIdleConns: 20, IdleConnTimeout: 30 * time.Second, ResponseHeaderTimeout: duration(request.TimeoutMS)}
	client := &http.Client{Transport: transport, Timeout: duration(request.TimeoutMS)}
	if !request.FollowRedirects {
		client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	} else if request.RestrictRedirectOrigin {
		originScheme := strings.ToLower(parsed.Scheme)
		originHost := strings.ToLower(parsed.Host)
		client.CheckRedirect = func(next *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			if strings.ToLower(next.URL.Scheme) != originScheme || strings.ToLower(next.URL.Host) != originHost {
				return http.ErrUseLastResponse
			}
			return nil
		}
	}
	httpRequest, err := http.NewRequestWithContext(ctx, method, request.URL, bytes.NewReader(body))
	if err != nil {
		return Response{}, err
	}
	for key, value := range request.Headers {
		if !validHeader(key, value) {
			return Response{}, fmt.Errorf("invalid HTTP header %q", key)
		}
		httpRequest.Header.Set(key, value)
	}
	started := time.Now()
	httpResponse, err := client.Do(httpRequest)
	elapsed := time.Since(started)
	if err != nil {
		return Response{}, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer httpResponse.Body.Close()
	limited := io.LimitReader(httpResponse.Body, maxBodyBytes+1)
	responseBody, err := io.ReadAll(limited)
	if err != nil {
		return Response{}, fmt.Errorf("read HTTP response: %w", err)
	}
	truncated := len(responseBody) > maxBodyBytes
	if truncated {
		responseBody = responseBody[:maxBodyBytes]
	}
	hash := sha256.Sum256(responseBody)
	result := Response{Status: httpResponse.StatusCode, StatusText: httpResponse.Status, Headers: httpResponse.Header.Clone(), BodyBytes: len(responseBody), Truncated: truncated, DurationMS: elapsed.Milliseconds(), FinalURL: httpResponse.Request.URL.String(), SHA256: hex.EncodeToString(hash[:]), BodyEncoding: "utf8"}
	if isText(responseBody) {
		result.Body = string(responseBody)
	} else {
		result.BodyEncoding = "base64"
		result.BodyBase64 = base64.StdEncoding.EncodeToString(responseBody)
	}
	if httpResponse.TLS != nil {
		result.TLS = tlsState(httpResponse.TLS)
	}
	if request.ProjectID != "" {
		flowValue := map[string]any{"request": request, "response": result}
		encoded := JSON(flowValue)
		entity, saveErr := c.store.SaveEntity(context.Background(), "http_flows", store.Entity{ProjectID: request.ProjectID, Name: method + " " + parsed.Path, Value: encoded, Metadata: map[string]any{"url": request.URL, "method": method, "status": result.Status, "duration_ms": result.DurationMS, "sha256": result.SHA256}})
		if saveErr != nil {
			return Response{}, saveErr
		}
		result.FlowID = entity.ID
	}
	return result, nil
}

type CrawlOptions struct {
	ProjectID, URL  string
	MaxPages, Depth int
	TimeoutMS       int
}

func (c *Client) Crawl(ctx context.Context, options CrawlOptions) (map[string]any, error) {
	root, err := url.Parse(options.URL)
	if err != nil || root.Host == "" {
		return nil, errors.New("valid crawl URL is required")
	}
	maxPages := options.MaxPages
	if maxPages <= 0 {
		maxPages = 40
	}
	if maxPages > 500 {
		maxPages = 500
	}
	depth := options.Depth
	if depth <= 0 {
		depth = 2
	}
	if depth > 6 {
		depth = 6
	}
	type item struct {
		value string
		depth int
	}
	queue := []item{{root.String(), 0}}
	visited := map[string]bool{}
	pages := []map[string]any{}
	endpoints := map[string]bool{}
	for len(queue) > 0 && len(visited) < maxPages {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		current := queue[0]
		queue = queue[1:]
		if visited[current.value] {
			continue
		}
		visited[current.value] = true
		response, requestErr := c.Do(ctx, Request{ProjectID: options.ProjectID, URL: current.value, Method: "GET", TimeoutMS: options.TimeoutMS, FollowRedirects: true, RestrictRedirectOrigin: true})
		page := map[string]any{"url": current.value, "depth": current.depth}
		if requestErr != nil {
			page["error"] = requestErr.Error()
			pages = append(pages, page)
			continue
		}
		page["status"] = response.Status
		page["bytes"] = response.BodyBytes
		pages = append(pages, page)
		if current.depth >= depth || response.Body == "" {
			continue
		}
		for _, link := range extractLinks(response.Body) {
			resolved, resolveErr := root.Parse(link)
			if resolveErr != nil || resolved.Host != root.Host {
				continue
			}
			resolved.Fragment = ""
			normalized := resolved.String()
			endpoints[normalized] = true
			if !visited[normalized] {
				queue = append(queue, item{normalized, current.depth + 1})
			}
		}
	}
	list := make([]string, 0, len(endpoints))
	for endpoint := range endpoints {
		list = append(list, endpoint)
	}
	sort.Strings(list)
	return map[string]any{"pages": pages, "endpoints": list, "visited": len(visited), "limited": len(visited) >= maxPages}, nil
}

func (c *Client) DirectoryScan(ctx context.Context, projectID, target string, words []string, concurrency, timeoutMS int) (map[string]any, error) {
	parsed, err := url.Parse(target)
	if err != nil || parsed.Host == "" {
		return nil, errors.New("valid directory scan URL is required")
	}
	if len(words) == 0 {
		words = []string{"admin", "api", "graphql", ".well-known/security.txt", "robots.txt", "sitemap.xml", "swagger.json", "openapi.json"}
	}
	if len(words) > 5000 {
		return nil, errors.New("directory word list exceeds 5000 entries")
	}
	if concurrency <= 0 {
		concurrency = 6
	}
	if concurrency > 20 {
		concurrency = 20
	}
	if timeoutMS <= 0 {
		timeoutMS = 5000
	}
	if timeoutMS > 15000 {
		timeoutMS = 15000
	}
	type soft404Signature struct {
		status int
		bytes  int
		sha256 string
	}
	soft404 := []soft404Signature{}
	for index := 0; index < 2; index++ {
		canaryBytes := make([]byte, 12)
		if _, randomErr := rand.Read(canaryBytes); randomErr != nil {
			return nil, fmt.Errorf("create soft-404 canary: %w", randomErr)
		}
		endpoint := strings.TrimRight(target, "/") + "/.wshawk-not-found-" + hex.EncodeToString(canaryBytes)
		response, requestErr := c.Do(ctx, Request{URL: endpoint, Method: "GET", TimeoutMS: timeoutMS, FollowRedirects: false})
		if requestErr == nil {
			soft404 = append(soft404, soft404Signature{status: response.Status, bytes: response.BodyBytes, sha256: response.SHA256})
		}
	}
	similarSize := func(left, right int) bool {
		largest := left
		if right > largest {
			largest = right
		}
		delta := left - right
		if delta < 0 {
			delta = -delta
		}
		tolerance := 8
		if percentage := int(float64(largest) * 0.03); percentage > tolerance {
			tolerance = percentage
		}
		return delta <= tolerance
	}
	wildcardDetected := len(soft404) == 2 && soft404[0].status == soft404[1].status && (soft404[0].sha256 == soft404[1].sha256 || similarSize(soft404[0].bytes, soft404[1].bytes))
	type result struct {
		URL    string `json:"url"`
		Status int    `json:"status"`
		Bytes  int    `json:"bytes"`
		Error  string `json:"error,omitempty"`
		SHA256 string `json:"-"`
	}
	jobs := make(chan string)
	results := make(chan result, len(words))
	var wait sync.WaitGroup
	for index := 0; index < concurrency; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for word := range jobs {
				endpoint := strings.TrimRight(target, "/") + "/" + strings.TrimLeft(strings.TrimSpace(word), "/")
				response, requestErr := c.Do(ctx, Request{ProjectID: projectID, URL: endpoint, Method: "GET", TimeoutMS: timeoutMS})
				item := result{URL: endpoint}
				if requestErr != nil {
					item.Error = requestErr.Error()
				} else {
					item.Status = response.Status
					item.Bytes = response.BodyBytes
					item.SHA256 = response.SHA256
				}
				results <- item
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, word := range words {
			select {
			case jobs <- word:
			case <-ctx.Done():
				return
			}
		}
	}()
	wait.Wait()
	close(results)
	found := []result{}
	checked := 0
	soft404Filtered := 0
	for item := range results {
		checked++
		if item.Status > 0 && item.Status != 404 {
			if wildcardDetected && item.Status == soft404[0].status && (item.SHA256 == soft404[0].sha256 || (similarSize(item.Bytes, soft404[0].bytes) && similarSize(item.Bytes, soft404[1].bytes))) {
				soft404Filtered++
				continue
			}
			found = append(found, item)
		}
	}
	return map[string]any{"checked": checked, "found": found, "baseline_checks": len(soft404), "wildcard_detected": wildcardDetected, "soft_404_filtered": soft404Filtered}, ctx.Err()
}

func Analyze(response Response, requestURL string) []map[string]any {
	findings := []map[string]any{}
	headers := http.Header(response.Headers)
	successfulHTML := response.Status >= 200 && response.Status < 300 && strings.Contains(strings.ToLower(headers.Get("Content-Type")), "text/html")
	add := func(kind, severity, detail string) {
		findings = append(findings, map[string]any{"type": kind, "severity": severity, "detail": detail, "url": requestURL})
	}
	if successfulHTML && headers.Get("Content-Security-Policy") == "" {
		add("missing-csp", "medium", "Content-Security-Policy header is absent")
	}
	if successfulHTML && headers.Get("X-Content-Type-Options") == "" {
		add("missing-nosniff", "low", "X-Content-Type-Options header is absent")
	}
	if successfulHTML && headers.Get("Referrer-Policy") == "" {
		add("missing-referrer-policy", "low", "Referrer-Policy header is absent")
	}
	if strings.HasPrefix(requestURL, "https://") && headers.Get("Strict-Transport-Security") == "" {
		add("missing-hsts", "medium", "Strict-Transport-Security header is absent")
	}
	if origin := headers.Get("Access-Control-Allow-Origin"); origin == "*" && strings.EqualFold(headers.Get("Access-Control-Allow-Credentials"), "true") {
		add("cors-wildcard-credentials", "high", "CORS allows credentials with a wildcard origin")
	}
	server := strings.ToLower(headers.Get("Server") + " " + headers.Get("X-Powered-By"))
	if server != " " {
		add("technology-disclosure", "info", strings.TrimSpace(server))
	}
	body := response.Body
	for name, pattern := range map[string]*regexp.Regexp{"private-key": regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`), "aws-access-key": regexp.MustCompile(`AKIA[0-9A-Z]{16}`), "jwt": regexp.MustCompile(`eyJ[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]{5,}`), "stack-trace": regexp.MustCompile(`(?i)(traceback \(most recent call|at [\w.$]+\([^\n]+:\d+\))`)} {
		if pattern.MatchString(body) {
			severity := "medium"
			if name == "private-key" || name == "aws-access-key" {
				severity = "critical"
			}
			add("sensitive-"+name, severity, "Response contains a possible "+name)
		}
	}
	if strings.Contains(strings.ToLower(body), "<form") && !regexp.MustCompile(`(?i)(csrf|xsrf)[_\-]?(token)?`).MatchString(body) {
		add("csrf-token-not-observed", "medium", "HTML form was found without an obvious anti-CSRF token")
	}
	for _, signature := range []string{"cloudflare", "akamai", "imperva", "sucuri", "mod_security", "awsalb"} {
		if strings.Contains(strings.ToLower(JSON(response.Headers)), signature) {
			add("waf-detected", "info", "Observed WAF/CDN signature: "+signature)
			break
		}
	}
	return findings
}

func InspectTLS(ctx context.Context, target string, skipVerify bool) (map[string]any, error) {
	parsed, err := url.Parse(target)
	if err != nil {
		return nil, err
	}
	host := parsed.Host
	if !strings.Contains(host, ":") {
		host += ":443"
	}
	dialer := &tls.Dialer{Config: &tls.Config{ServerName: parsed.Hostname(), MinVersion: tls.VersionTLS12, InsecureSkipVerify: skipVerify}} // #nosec G402 -- explicit operator lab option.
	connection, err := dialer.DialContext(ctx, "tcp", host)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	state := connection.(*tls.Conn).ConnectionState()
	result := tlsState(&state)
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		result["not_before"] = cert.NotBefore.UTC()
		result["not_after"] = cert.NotAfter.UTC()
		result["dns_names"] = cert.DNSNames
		result["issuer"] = cert.Issuer.String()
		result["subject"] = cert.Subject.String()
		result["expired"] = time.Now().After(cert.NotAfter)
	}
	return result, nil
}

func tlsState(state *tls.ConnectionState) map[string]any {
	result := map[string]any{"version": tlsVersion(state.Version), "cipher_suite": tls.CipherSuiteName(state.CipherSuite), "server_name": state.ServerName, "negotiated_protocol": state.NegotiatedProtocol, "verified_chains": len(state.VerifiedChains)}
	if len(state.PeerCertificates) > 0 {
		result["peer_sha256"] = certificateHash(state.PeerCertificates[0])
	}
	return result
}
func certificateHash(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}
func tlsVersion(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return fmt.Sprintf("0x%x", version)
	}
}
func extractLinks(body string) []string {
	pattern := regexp.MustCompile(`(?i)(?:href|src|action)\s*=\s*["']([^"'#]+)["']`)
	matches := pattern.FindAllStringSubmatch(body, 2000)
	result := make([]string, 0, len(matches))
	for _, match := range matches {
		result = append(result, strings.TrimSpace(match[1]))
	}
	return result
}
func duration(ms int) time.Duration {
	if ms <= 0 {
		return 15 * time.Second
	}
	if ms < 500 {
		return 500 * time.Millisecond
	}
	if ms > 120000 {
		return 120 * time.Second
	}
	return time.Duration(ms) * time.Millisecond
}
func validHeader(key, value string) bool {
	return key != "" && !strings.ContainsAny(key+value, "\r\n\x00")
}
func isText(value []byte) bool {
	if bytes.IndexByte(value, 0) >= 0 {
		return false
	}
	return true
}
func JSON(value any) string                 { encoded, _ := jsonMarshal(value); return string(encoded) }
func jsonMarshal(value any) ([]byte, error) { return json.Marshal(value) }
