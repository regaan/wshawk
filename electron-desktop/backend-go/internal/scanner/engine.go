package scanner

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/regaan/wshawk/electron-desktop/backend-go/internal/store"
	"github.com/regaan/wshawk/electron-desktop/backend-go/internal/websec"
)

type EmitFunc func(string, any)

type Options struct {
	OperationID            string         `json:"operation_id"`
	ProjectID              string         `json:"project_id"`
	Request                websec.Request `json:"request"`
	Parameter              string         `json:"parameter"`
	Location               string         `json:"location"`
	Categories             []string       `json:"categories"`
	OASTURL                string         `json:"oast_url"`
	AuthorizationConfirmed bool           `json:"authorization_confirmed"`
	MaxRequests            int            `json:"max_requests"`
	Concurrency            int            `json:"concurrency"`
	OperationTimeoutMS     int            `json:"operation_timeout_ms"`
}

type Engine struct {
	client *websec.Client
	store  *store.Store
	emit   EmitFunc
	mu     sync.Mutex
	ops    map[string]context.CancelFunc
}

func New(client *websec.Client, database *store.Store, emit EmitFunc) *Engine {
	return &Engine{client: client, store: database, emit: emit, ops: map[string]context.CancelFunc{}}
}

func (e *Engine) Run(parent context.Context, options Options) (map[string]any, error) {
	startedAt := time.Now()
	if !options.AuthorizationConfirmed {
		return nil, errors.New("authorization_confirmed must be true for active security testing")
	}
	if options.ProjectID == "" {
		options.ProjectID = options.Request.ProjectID
	}
	options.Request.ProjectID = options.ProjectID
	if options.ProjectID == "" {
		return nil, errors.New("project_id is required")
	}
	if strings.TrimSpace(options.Parameter) == "" {
		return nil, errors.New("parameter is required")
	}
	operationID := options.OperationID
	if operationID == "" {
		operationID = newID("scan")
	}
	ctx, cancel := context.WithCancel(parent)
	e.mu.Lock()
	e.ops[operationID] = cancel
	e.mu.Unlock()
	defer func() { cancel(); e.mu.Lock(); delete(e.ops, operationID); e.mu.Unlock() }()
	baseline, err := e.client.Do(ctx, options.Request)
	if err != nil {
		return nil, fmt.Errorf("baseline request: %w", err)
	}
	selected := selectPayloads(options.Categories, options.OASTURL)
	max := options.MaxRequests
	if max <= 0 {
		max = 100
	}
	if max > 500 {
		max = 500
	}
	if len(selected) > max {
		selected = selected[:max]
	}
	type scanTask struct {
		payload Payload
		request websec.Request
	}
	tasks := make([]scanTask, 0, len(selected))
	for _, payload := range selected {
		mutated, mutateErr := mutateRequest(options.Request, options.Parameter, options.Location, payload)
		if mutateErr != nil {
			return nil, mutateErr
		}
		tasks = append(tasks, scanTask{payload: payload, request: mutated})
	}

	run, _ := e.store.SaveEntity(context.Background(), "attack_runs", store.Entity{ProjectID: options.ProjectID, Name: "active-scanner", Value: "running", Metadata: map[string]any{"operation_id": operationID, "target": options.Request.URL, "categories": options.Categories, "request_count": len(tasks)}})
	findings := []map[string]any{}
	completed := 0
	concurrency := options.Concurrency
	if concurrency <= 0 {
		concurrency = 4
	}
	if concurrency > 16 {
		concurrency = 16
	}
	if len(tasks) > 0 && concurrency > len(tasks) {
		concurrency = len(tasks)
	}
	if concurrency == 0 {
		concurrency = 1
	}
	type scanOutcome struct {
		task     scanTask
		response websec.Response
		err      error
	}
	jobs := make(chan scanTask)
	outcomes := make(chan scanOutcome, len(tasks))
	var wait sync.WaitGroup
	for index := 0; index < concurrency; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for task := range jobs {
				response, requestErr := e.client.Do(ctx, task.request)
				outcomes <- scanOutcome{task: task, response: response, err: requestErr}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, task := range tasks {
			select {
			case jobs <- task:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		wait.Wait()
		close(outcomes)
	}()

	for outcome := range outcomes {
		payload := outcome.task.payload
		response := outcome.response
		requestErr := outcome.err
		completed++
		e.emit("scan.progress", map[string]any{"operation_id": operationID, "completed": completed, "total": len(tasks), "category": payload.Category})
		if requestErr != nil {
			e.emit("scan.response", map[string]any{"operation_id": operationID, "payload": payload.Value, "category": payload.Category, "status": 0, "error": requestErr.Error()})
			continue
		}
		finding := detectFinding(payload, baseline, response, outcome.task.request.URL)
		e.emit("scan.response", map[string]any{"operation_id": operationID, "payload": payload.Value, "category": payload.Category, "status": response.Status, "length": response.BodyBytes, "time": fmt.Sprintf("%dms", response.DurationMS), "matched": finding != nil})
		if finding != nil {
			finding["operation_id"] = operationID
			finding["payload"] = payload.Value
			findings = append(findings, finding)
			stored, _ := e.store.SaveEntity(context.Background(), "findings", store.Entity{ProjectID: options.ProjectID, Name: fmt.Sprint(finding["type"]), Value: payload.Value, Metadata: finding})
			finding["id"] = stored.ID
			e.emit("scan.finding", finding)
		}
	}
	elapsedSeconds := time.Since(startedAt).Seconds()
	if ctx.Err() != nil {
		result := map[string]any{"operation_id": operationID, "cancelled": true, "completed": completed, "findings": findings, "elapsed": elapsedSeconds, "total_findings": len(findings)}
		_, _ = e.store.SaveEntity(context.Background(), "attack_runs", store.Entity{ID: run.ID, ProjectID: options.ProjectID, Name: "active-scanner", Value: "cancelled", Metadata: result})
		e.emit("scan.cancelled", result)
		return result, ctx.Err()
	}
	_, _ = e.store.SaveEntity(context.Background(), "attack_runs", store.Entity{ID: run.ID, ProjectID: options.ProjectID, Name: "active-scanner", Value: "completed", Metadata: map[string]any{"operation_id": operationID, "target": options.Request.URL, "completed": completed, "finding_count": len(findings), "findings": findings, "elapsed": elapsedSeconds}})
	result := map[string]any{"operation_id": operationID, "completed": completed, "findings": findings, "baseline": baseline, "status": "completed", "elapsed": elapsedSeconds, "total_findings": len(findings)}
	e.emit("scan.completed", result)
	return result, nil
}

func (e *Engine) Cancel(id string) bool {
	e.mu.Lock()
	cancel := e.ops[id]
	e.mu.Unlock()
	if cancel == nil {
		return false
	}
	cancel()
	return true
}

func (e *Engine) Close() {
	e.mu.Lock()
	cancels := make([]context.CancelFunc, 0, len(e.ops))
	for _, cancel := range e.ops {
		cancels = append(cancels, cancel)
	}
	e.ops = map[string]context.CancelFunc{}
	e.mu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
}

func (e *Engine) Race(ctx context.Context, request websec.Request, count int) (map[string]any, error) {
	if count <= 0 {
		count = 10
	}
	if count > 50 {
		count = 50
	}
	start := make(chan struct{})
	responses := make(chan map[string]any, count)
	var wait sync.WaitGroup
	for index := 0; index < count; index++ {
		wait.Add(1)
		go func(i int) {
			defer wait.Done()
			select {
			case <-start:
			case <-ctx.Done():
				return
			}
			response, err := e.client.Do(ctx, request)
			item := map[string]any{"index": i}
			if err != nil {
				item["error"] = err.Error()
			} else {
				item["status"] = response.Status
				item["sha256"] = response.SHA256
				item["duration_ms"] = response.DurationMS
			}
			responses <- item
		}(index)
	}
	close(start)
	wait.Wait()
	close(responses)
	items := []map[string]any{}
	signatures := map[string]int{}
	successful := 0
	for item := range responses {
		items = append(items, item)
		signature := fmt.Sprintf("%v:%v", item["status"], item["sha256"])
		signatures[signature]++
		if status, ok := item["status"].(int); ok && status >= 200 && status < 300 {
			successful++
		}
	}
	unsafeMethod := request.Method != "" && request.Method != http.MethodGet && request.Method != http.MethodHead && request.Method != http.MethodOptions
	possibleRace := len(signatures) > 1 || (unsafeMethod && successful > 1)
	reason := "stable outcome"
	if len(signatures) > 1 {
		reason = "concurrent requests produced distinct outcomes"
	} else if unsafeMethod && successful > 1 {
		reason = "multiple concurrent state-changing requests were accepted; verify idempotency and resulting state"
	}
	return map[string]any{"responses": items, "distinct_outcomes": len(signatures), "successful_responses": successful, "possible_race": possibleRace, "reason": reason, "confidence": "manual-review"}, ctx.Err()
}

func AnalyzeBinary(encoded string) (map[string]any, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, errors.New("payload_base64 is invalid")
	}
	if len(data) > 16*1024*1024 {
		return nil, errors.New("binary payload exceeds 16 MiB limit")
	}
	frequency := [256]int{}
	for _, value := range data {
		frequency[value]++
	}
	entropy := 0.0
	if len(data) > 0 {
		for _, count := range frequency {
			if count == 0 {
				continue
			}
			p := float64(count) / float64(len(data))
			entropy -= p * math.Log2(p)
		}
	}
	magic := "unknown"
	for signature, name := range map[string]string{"89504e47": "png", "504b0304": "zip", "1f8b0800": "gzip", "7f454c46": "elf", "4d5a": "pe", "25504446": "pdf"} {
		if strings.HasPrefix(hex.EncodeToString(data), signature) {
			magic = name
			break
		}
	}
	stringsFound := regexp.MustCompile(`[\x20-\x7e]{4,}`).FindAllString(string(data), 100)
	return map[string]any{"size": len(data), "entropy": entropy, "magic": magic, "utf8": utf8.Valid(data), "printable_strings": stringsFound, "base64": encoded}, nil
}

func selectPayloads(categories []string, oast string) []Payload {
	allowed := map[string]bool{}
	for _, category := range categories {
		allowed[strings.ToLower(category)] = true
	}
	all := len(allowed) == 0
	result := []Payload{}
	for _, payload := range catalog {
		if !all && !allowed[payload.Category] {
			continue
		}
		if payload.Category == "ssrf" {
			if oast == "" {
				continue
			}
			payload.Value = strings.ReplaceAll(payload.Value, "{{OAST_URL}}", oast)
		}
		result = append(result, payload)
	}
	return result
}

func mutateRequest(request websec.Request, parameter, location string, payload Payload) (websec.Request, error) {
	result := request
	value := payload.Value
	switch strings.ToLower(location) {
	case "header":
		if result.Headers == nil {
			result.Headers = map[string]string{}
		}
		result.Headers[parameter] = value
	case "xml":
		result.Body = value
		if result.Headers == nil {
			result.Headers = map[string]string{}
		}
		result.Headers["Content-Type"] = "application/xml"
	case "body", "json":
		if strings.EqualFold(location, "json") {
			document := map[string]any{}
			if err := json.Unmarshal([]byte(result.Body), &document); err != nil {
				return result, errors.New("request body must be a JSON object")
			}
			if payload.Category == "nosql_injection" {
				var operator any
				if err := json.Unmarshal([]byte(value), &operator); err != nil {
					return result, errors.New("NoSQL payload must be valid JSON")
				}
				document[parameter] = operator
			} else if payload.Category == "prototype_pollution" {
				var keys map[string]any
				if err := json.Unmarshal([]byte(value), &keys); err != nil {
					return result, errors.New("prototype payload must be a JSON object")
				}
				for key, injected := range keys {
					document[key] = injected
				}
			} else {
				document[parameter] = value
			}
			encoded, _ := json.Marshal(document)
			result.Body = string(encoded)
			if result.Headers == nil {
				result.Headers = map[string]string{}
			}
			result.Headers["Content-Type"] = "application/json"
		} else {
			values, err := url.ParseQuery(result.Body)
			if err != nil {
				return result, err
			}
			values.Set(parameter, value)
			result.Body = values.Encode()
		}
	default:
		parsed, err := url.Parse(result.URL)
		if err != nil {
			return result, err
		}
		query := parsed.Query()
		query.Set(parameter, value)
		parsed.RawQuery = query.Encode()
		result.URL = parsed.String()
	}
	return result, nil
}

func detectFinding(payload Payload, baseline, current websec.Response, target string) map[string]any {
	body := strings.ToLower(current.Body)
	baselineBody := strings.ToLower(baseline.Body)
	sqlErrors := []string{"sql syntax", "sqlite error", "mysql_fetch", "postgresql", "ora-", "unclosed quotation", "syntax error at or near"}
	if payload.Category == "sqli" {
		for _, marker := range sqlErrors {
			if strings.Contains(body, marker) && !strings.Contains(baselineBody, marker) {
				return finding("sql-injection", "high", "Database error appeared only after the SQL probe", target, current)
			}
		}
	}
	markerObserved := payload.Marker != "" && strings.Contains(current.Body, payload.Marker) && !strings.Contains(baseline.Body, payload.Marker)
	if payload.Category == "xss" && markerObserved && strings.Contains(current.Body, payload.Value) {
		return finding("xss", "medium", "XSS canary was reflected; browser execution verification is required for confirmation", target, current)
	}
	if markerObserved && !strings.Contains(current.Body, payload.Value) {
		severity := "high"
		if payload.Category == "command_injection" || payload.Category == "path_traversal" {
			severity = "critical"
		}
		return finding(payload.Category, severity, "A probe output marker was observed without the original payload", target, current)
	}
	if current.Status >= 500 && baseline.Status < 500 {
		return finding(payload.Category, "medium", "Mutation caused a server error not present in baseline", target, current)
	}
	if payload.Category == "redirect" {
		for key, values := range current.Headers {
			if !strings.EqualFold(key, "Location") || len(values) == 0 {
				continue
			}
			base, baseErr := url.Parse(target)
			location, locationErr := url.Parse(values[0])
			if baseErr == nil && locationErr == nil && strings.EqualFold(base.ResolveReference(location).Hostname(), "wshawk.invalid") {
				return finding("open-redirect", "high", "External redirect probe was accepted as the redirect destination", target, current)
			}
		}
	}
	return nil
}
func finding(kind, severity, detail, target string, response websec.Response) map[string]any {
	return map[string]any{"type": kind, "severity": severity, "detail": detail, "url": target, "status": response.Status, "response_sha256": response.SHA256, "confidence": "medium"}
}
func bodySimilarity(left, leftHash, right, rightHash string) float64 {
	if leftHash != "" && leftHash == rightHash {
		return 1
	}
	leftTokens := map[string]bool{}
	for _, token := range strings.Fields(left) {
		leftTokens[token] = true
	}
	rightTokens := map[string]bool{}
	for _, token := range strings.Fields(right) {
		rightTokens[token] = true
	}
	union := map[string]bool{}
	intersection := 0
	for token := range leftTokens {
		union[token] = true
		if rightTokens[token] {
			intersection++
		}
	}
	for token := range rightTokens {
		union[token] = true
	}
	if len(union) == 0 {
		return 0
	}
	return float64(intersection) / float64(len(union))
}
func newID(prefix string) string {
	buffer := make([]byte, 12)
	_, _ = rand.Read(buffer)
	return prefix + "_" + hex.EncodeToString(buffer)
}

func sortedKeys(value map[string]int) []string {
	result := make([]string, 0, len(value))
	for key := range value {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}

var _ = http.MethodGet
var _ = time.Second
