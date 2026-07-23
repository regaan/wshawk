package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Request struct {
	Kind                   string         `json:"kind"`
	URL                    string         `json:"url"`
	Token                  string         `json:"token"`
	Username               string         `json:"username"`
	Payload                map[string]any `json:"payload"`
	AuthorizationConfirmed bool           `json:"authorization_confirmed"`
}

func Send(ctx context.Context, request Request) (map[string]any, error) {
	if !request.AuthorizationConfirmed {
		return nil, errors.New("authorization_confirmed must be true before sending data to an external integration")
	}
	parsed, err := url.Parse(request.URL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return nil, errors.New("integration URL must use http or https")
	}
	payload := request.Payload
	if payload == nil {
		payload = map[string]any{}
	}
	endpoint := strings.TrimRight(request.URL, "/")
	kind := strings.ToLower(strings.TrimSpace(request.Kind))
	switch kind {
	case "jira":
		endpoint += "/rest/api/3/issue"
	case "defectdojo":
		endpoint += "/api/v2/import-scan/"
	case "webhook":
	default:
		return nil, errors.New("kind must be jira, defectdojo, or webhook")
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	if len(encoded) > 4*1024*1024 {
		return nil, errors.New("integration payload exceeds 4 MiB")
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(encoded))
	if err != nil {
		return nil, err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	if request.Token != "" {
		if kind == "defectdojo" {
			httpRequest.Header.Set("Authorization", "Token "+request.Token)
		} else {
			httpRequest.Header.Set("Authorization", "Bearer "+request.Token)
		}
	}
	if request.Username != "" && request.Token != "" && kind == "jira" {
		httpRequest.SetBasicAuth(request.Username, request.Token)
	}
	client := &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(httpRequest)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1024*1024))
	if err != nil {
		return nil, err
	}
	result := map[string]any{"status": response.StatusCode, "ok": response.StatusCode >= 200 && response.StatusCode < 300, "body": string(body)}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return result, fmt.Errorf("integration returned HTTP %d", response.StatusCode)
	}
	return result, nil
}
