package workflow

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/regaan/wshawk/electron-desktop/backend-go/internal/store"
	"github.com/regaan/wshawk/electron-desktop/backend-go/internal/websec"
)

var variablePattern = regexp.MustCompile(`\{\{([A-Za-z_][A-Za-z0-9_.-]{0,127})\}\}`)

type ExtractRule struct {
	Variable string `json:"var"`
	From     string `json:"from"`
	Regex    string `json:"regex"`
}

type Step struct {
	Name    string            `json:"name"`
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
	Extract []ExtractRule     `json:"extract"`
}

type Options struct {
	ProjectID              string         `json:"project_id"`
	DefaultURL             string         `json:"default_url"`
	Steps                  []Step         `json:"steps"`
	Variables              map[string]any `json:"variables"`
	TimeoutSeconds         int            `json:"timeout"`
	AuthorizationConfirmed bool           `json:"authorization_confirmed"`
}

type Runner struct {
	client *websec.Client
	store  *store.Store
	emit   func(string, any)
}

func New(client *websec.Client, database *store.Store, emit func(string, any)) *Runner {
	return &Runner{client: client, store: database, emit: emit}
}

func (r *Runner) Run(ctx context.Context, options Options) (map[string]any, error) {
	if !options.AuthorizationConfirmed {
		return nil, errors.New("authorization_confirmed must be true for workflow execution")
	}
	if options.ProjectID == "" {
		return nil, errors.New("project_id is required")
	}
	if len(options.Steps) == 0 || len(options.Steps) > 50 {
		return nil, errors.New("workflow must contain between 1 and 50 steps")
	}
	variables := map[string]string{}
	for key, value := range options.Variables {
		variables[key] = fmt.Sprint(value)
	}
	timeout := options.TimeoutSeconds
	if timeout <= 0 {
		timeout = 10
	}
	if timeout > 120 {
		timeout = 120
	}
	started := time.Now()
	results := make([]map[string]any, 0, len(options.Steps))
	completed, failures := 0, 0
	for index, step := range options.Steps {
		name := strings.TrimSpace(step.Name)
		if name == "" {
			name = fmt.Sprintf("Step %d", index+1)
		}
		requestURL := substitute(step.URL, variables)
		if strings.TrimSpace(requestURL) == "" {
			requestURL = substitute(options.DefaultURL, variables)
		}
		headers := map[string]string{}
		for key, value := range step.Headers {
			headers[key] = substitute(value, variables)
		}
		item := map[string]any{"step": index + 1, "name": name, "method": step.Method, "url": requestURL, "status": "error"}
		response, err := r.client.Do(ctx, websec.Request{ProjectID: options.ProjectID, URL: requestURL, Method: step.Method, Headers: headers, Body: substitute(step.Body, variables), TimeoutMS: timeout * 1000, FollowRedirects: false})
		if err != nil {
			failures++
			item["reason"] = err.Error()
			results = append(results, item)
			r.emit("chain_step", item)
			continue
		}
		item["status"] = "success"
		item["http_status"] = response.Status
		item["response_length"] = response.BodyBytes
		extracted := map[string]string{}
		for _, rule := range step.Extract {
			value, extractErr := extract(rule, response)
			if extractErr != nil {
				item["extraction_error"] = extractErr.Error()
				continue
			}
			if value != "" {
				variables[rule.Variable] = value
				extracted[rule.Variable] = value
			}
		}
		item["extracted"] = extracted
		completed++
		results = append(results, item)
		r.emit("chain_step", item)
	}
	summary := map[string]any{"total_steps": len(options.Steps), "completed": completed, "skipped": 0, "errors": failures, "elapsed": time.Since(started).Seconds()}
	_, _ = r.store.SaveEntity(context.Background(), "attack_runs", store.Entity{ProjectID: options.ProjectID, Name: "http-workflow", Value: "completed", Metadata: map[string]any{"summary": summary, "results": results, "variables": variables}})
	return map[string]any{"workflow": map[string]any{"results": results, "summary": summary, "variables": variables}}, nil
}

func substitute(value string, variables map[string]string) string {
	return variablePattern.ReplaceAllStringFunc(value, func(match string) string {
		parts := variablePattern.FindStringSubmatch(match)
		if len(parts) == 2 {
			if replacement, ok := variables[parts[1]]; ok {
				return replacement
			}
		}
		return match
	})
}

func extract(rule ExtractRule, response websec.Response) (string, error) {
	if strings.TrimSpace(rule.Variable) == "" {
		return "", errors.New("extract rule var is required")
	}
	if len(rule.Regex) == 0 || len(rule.Regex) > 1000 {
		return "", errors.New("extract rule regex length is invalid")
	}
	pattern, err := regexp.Compile(rule.Regex)
	if err != nil {
		return "", fmt.Errorf("compile extract regex: %w", err)
	}
	source := response.Body
	switch strings.ToLower(rule.From) {
	case "headers":
		source = websec.JSON(response.Headers)
	case "cookies":
		for key, values := range response.Headers {
			if strings.EqualFold(key, "Set-Cookie") {
				source = strings.Join(values, "; ")
				break
			}
		}
	case "body", "":
	default:
		return "", errors.New("extract source must be body, headers, or cookies")
	}
	match := pattern.FindStringSubmatch(source)
	if len(match) > 1 {
		return match[1], nil
	}
	if len(match) == 1 {
		return match[0], nil
	}
	return "", nil
}
