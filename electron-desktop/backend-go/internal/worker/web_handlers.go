package worker

import (
	"context"
	"encoding/json"
	"time"

	"github.com/regaan/wshawk/electron-desktop/backend-go/internal/protocol"
	"github.com/regaan/wshawk/electron-desktop/backend-go/internal/websec"
)

func (s *Server) registerWebHandlers() {
	s.handlers["http.request"] = s.httpRequest
	s.handlers["web.crawl"] = s.webCrawl
	s.handlers["web.dirscan"] = s.webDirscan
	s.handlers["web.analyze"] = s.webAnalyze
	s.handlers["tls.inspect"] = s.tlsInspect
	s.handlers["oast.poll"] = s.oastPoll
}

func (s *Server) oastPoll(raw json.RawMessage) (any, *protocol.RPCError) {
	var params struct {
		ProjectID string            `json:"project_id"`
		URL       string            `json:"url"`
		Headers   map[string]string `json:"headers"`
	}
	if rpcErr := decodeParams(raw, &params); rpcErr != nil {
		return nil, rpcErr
	}
	if params.URL == "" {
		return map[string]any{"interactions": []any{}, "configured": false}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	response, err := s.web.Do(ctx, websec.Request{ProjectID: params.ProjectID, URL: params.URL, Method: "GET", Headers: params.Headers, TimeoutMS: 15000, FollowRedirects: false})
	if err != nil {
		return webResult(nil, err)
	}
	var decoded any
	if json.Unmarshal([]byte(response.Body), &decoded) != nil {
		decoded = response.Body
	}
	return map[string]any{"configured": true, "status": response.Status, "interactions": decoded}, nil
}

func (s *Server) httpRequest(raw json.RawMessage) (any, *protocol.RPCError) {
	var params websec.Request
	if rpcErr := decodeParams(raw, &params); rpcErr != nil {
		return nil, rpcErr
	}
	ctx, cancel := context.WithTimeout(context.Background(), 125*time.Second)
	defer cancel()
	response, err := s.web.Do(ctx, params)
	return webResult(map[string]any{"response": response}, err)
}

func (s *Server) webCrawl(raw json.RawMessage) (any, *protocol.RPCError) {
	var params struct {
		OperationID        string `json:"operation_id"`
		ProjectID          string `json:"project_id"`
		URL                string `json:"url"`
		MaxPages           int    `json:"max_pages"`
		Depth              int    `json:"depth"`
		TimeoutMS          int    `json:"timeout_ms"`
		OperationTimeoutMS int    `json:"operation_timeout_ms"`
	}
	if rpcErr := decodeParams(raw, &params); rpcErr != nil {
		return nil, rpcErr
	}
	timeout := boundedOperationTimeout(params.OperationTimeoutMS, 60*time.Second, 5*time.Second, 5*time.Minute)
	ctx, finish, err := s.beginOperation(params.OperationID, timeout)
	if err != nil {
		return webResult(nil, err)
	}
	defer finish()
	result, err := s.web.Crawl(ctx, websec.CrawlOptions{ProjectID: params.ProjectID, URL: params.URL, MaxPages: params.MaxPages, Depth: params.Depth, TimeoutMS: params.TimeoutMS})
	if err == nil {
		if pages, ok := result["pages"].([]map[string]any); ok {
			for _, page := range pages {
				s.emit("crawl_page", page)
			}
		}
		s.emit("crawl_complete", result)
	}
	return webResult(result, err)
}

func (s *Server) webDirscan(raw json.RawMessage) (any, *protocol.RPCError) {
	var params struct {
		OperationID        string   `json:"operation_id"`
		ProjectID          string   `json:"project_id"`
		URL                string   `json:"url"`
		Words              []string `json:"words"`
		Concurrency        int      `json:"concurrency"`
		TimeoutMS          int      `json:"timeout_ms"`
		OperationTimeoutMS int      `json:"operation_timeout_ms"`
	}
	if rpcErr := decodeParams(raw, &params); rpcErr != nil {
		return nil, rpcErr
	}
	timeout := boundedOperationTimeout(params.OperationTimeoutMS, 30*time.Second, 5*time.Second, 5*time.Minute)
	ctx, finish, err := s.beginOperation(params.OperationID, timeout)
	if err != nil {
		return webResult(nil, err)
	}
	defer finish()
	result, err := s.web.DirectoryScan(ctx, params.ProjectID, params.URL, params.Words, params.Concurrency, params.TimeoutMS)
	return webResult(result, err)
}

func (s *Server) webAnalyze(raw json.RawMessage) (any, *protocol.RPCError) {
	var params struct {
		OperationID        string         `json:"operation_id"`
		OperationTimeoutMS int            `json:"operation_timeout_ms"`
		Request            websec.Request `json:"request"`
	}
	if rpcErr := decodeParams(raw, &params); rpcErr != nil {
		return nil, rpcErr
	}
	timeout := boundedOperationTimeout(params.OperationTimeoutMS, 20*time.Second, 2*time.Second, 2*time.Minute)
	ctx, finish, err := s.beginOperation(params.OperationID, timeout)
	if err != nil {
		return webResult(nil, err)
	}
	defer finish()
	response, err := s.web.Do(ctx, params.Request)
	if err != nil {
		return webResult(nil, err)
	}
	return map[string]any{"response": response, "findings": websec.Analyze(response, params.Request.URL)}, nil
}

func (s *Server) tlsInspect(raw json.RawMessage) (any, *protocol.RPCError) {
	var params struct {
		URL        string `json:"url"`
		SkipVerify bool   `json:"skip_verify"`
	}
	if rpcErr := decodeParams(raw, &params); rpcErr != nil {
		return nil, rpcErr
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	result, err := websec.InspectTLS(ctx, params.URL, params.SkipVerify)
	return webResult(result, err)
}

func webResult(result any, err error) (any, *protocol.RPCError) {
	if err == nil {
		return result, nil
	}
	return nil, &protocol.RPCError{Code: "web_error", Message: "Web security operation failed", Detail: err.Error()}
}
