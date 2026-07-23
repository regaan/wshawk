package worker

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/regaan/wshawk/electron-desktop/backend-go/internal/protocol"
	"github.com/regaan/wshawk/electron-desktop/backend-go/internal/scanner"
	"github.com/regaan/wshawk/electron-desktop/backend-go/internal/store"
	"github.com/regaan/wshawk/electron-desktop/backend-go/internal/websec"
	"github.com/regaan/wshawk/electron-desktop/backend-go/internal/wsengine"
)

func (s *Server) registerScannerHandlers() {
	s.handlers["scanner.catalog"] = s.scannerCatalog
	s.handlers["scanner.mutate"] = s.scannerMutate
	s.handlers["scanner.run"] = s.scannerRun
	s.handlers["scanner.authz_diff"] = s.scannerAuthzDiff
	s.handlers["scanner.authz_matrix"] = s.scannerAuthzMatrix
	s.handlers["scanner.race"] = s.scannerRace
	s.handlers["scanner.binary_analyze"] = s.scannerBinaryAnalyze
	s.handlers["scanner.ws_mutate"] = s.scannerWSMutate
	s.handlers["scanner.subscription_abuse"] = s.scannerSubscriptionAbuse
	s.handlers["scanner.auth_test"] = s.scannerAuthTest
	s.handlers["operation.cancel"] = s.operationCancel
}
func (s *Server) scannerCatalog(_ json.RawMessage) (any, *protocol.RPCError) {
	return map[string]any{"payloads": scanner.Catalog()}, nil
}
func (s *Server) scannerMutate(raw json.RawMessage) (any, *protocol.RPCError) {
	var params struct {
		Payload  string `json:"payload"`
		Strategy string `json:"strategy"`
		Count    int    `json:"count"`
	}
	if rpcErr := decodeParams(raw, &params); rpcErr != nil {
		return nil, rpcErr
	}
	mutations, err := scanner.Mutate(params.Payload, params.Strategy, params.Count)
	if err != nil {
		return scanResult(nil, err)
	}
	return map[string]any{"mutations": mutations, "count": len(mutations), "strategy": params.Strategy, "engine": "go-bounded-mutation"}, nil
}
func (s *Server) scannerRun(raw json.RawMessage) (any, *protocol.RPCError) {
	var params scanner.Options
	if rpcErr := decodeParams(raw, &params); rpcErr != nil {
		return nil, rpcErr
	}
	timeout := boundedOperationTimeout(params.OperationTimeoutMS, 90*time.Second, 5*time.Second, 5*time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	result, err := s.scanner.Run(ctx, params)
	return scanResult(result, err)
}
func (s *Server) scannerAuthzDiff(raw json.RawMessage) (any, *protocol.RPCError) {
	var params struct {
		Left                   websec.Request      `json:"left"`
		Right                  websec.Request      `json:"right"`
		Policy                 scanner.AuthzPolicy `json:"policy"`
		AuthorizationConfirmed bool                `json:"authorization_confirmed"`
	}
	if rpcErr := decodeParams(raw, &params); rpcErr != nil {
		return nil, rpcErr
	}
	if !params.AuthorizationConfirmed {
		return nil, &protocol.RPCError{Code: "authorization_required", Message: "authorization_confirmed must be true for authorization-difference testing"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	result, err := s.scanner.AuthzDiffWithPolicy(ctx, params.Left, params.Right, params.Policy)
	return scanResult(result, err)
}
func (s *Server) scannerAuthzMatrix(raw json.RawMessage) (any, *protocol.RPCError) {
	var params struct {
		scanner.AuthzMatrixOptions
		AuthorizationConfirmed bool `json:"authorization_confirmed"`
	}
	if rpcErr := decodeParams(raw, &params); rpcErr != nil {
		return nil, rpcErr
	}
	if !params.AuthorizationConfirmed {
		return nil, &protocol.RPCError{Code: "authorization_required", Message: "authorization_confirmed must be true for authorization-matrix testing"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	result, err := s.scanner.AuthzMatrix(ctx, params.AuthzMatrixOptions)
	return scanResult(result, err)
}
func (s *Server) scannerRace(raw json.RawMessage) (any, *protocol.RPCError) {
	var params struct {
		Request                websec.Request `json:"request"`
		Count                  int            `json:"count"`
		AuthorizationConfirmed bool           `json:"authorization_confirmed"`
	}
	if rpcErr := decodeParams(raw, &params); rpcErr != nil {
		return nil, rpcErr
	}
	if !params.AuthorizationConfirmed {
		return nil, &protocol.RPCError{Code: "authorization_required", Message: "authorization_confirmed must be true for race testing"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	result, err := s.scanner.Race(ctx, params.Request, params.Count)
	return scanResult(result, err)
}
func (s *Server) scannerBinaryAnalyze(raw json.RawMessage) (any, *protocol.RPCError) {
	var params struct {
		PayloadBase64 string `json:"payload_base64"`
	}
	if rpcErr := decodeParams(raw, &params); rpcErr != nil {
		return nil, rpcErr
	}
	result, err := scanner.AnalyzeBinary(params.PayloadBase64)
	return scanResult(result, err)
}
func (s *Server) operationCancel(raw json.RawMessage) (any, *protocol.RPCError) {
	var params struct {
		OperationID string `json:"operation_id"`
	}
	if rpcErr := decodeParams(raw, &params); rpcErr != nil {
		return nil, rpcErr
	}
	cancelled := s.cancelOperation(params.OperationID)
	if s.scanner.Cancel(params.OperationID) {
		cancelled = true
	}
	return map[string]any{"operation_id": params.OperationID, "cancelled": cancelled}, nil
}

func (s *Server) scannerWSMutate(raw json.RawMessage) (any, *protocol.RPCError) {
	var params struct {
		ConnectionID           string   `json:"connection_id"`
		Payloads               []string `json:"payloads"`
		AuthorizationConfirmed bool     `json:"authorization_confirmed"`
	}
	if rpcErr := decodeParams(raw, &params); rpcErr != nil {
		return nil, rpcErr
	}
	if !params.AuthorizationConfirmed {
		return nil, &protocol.RPCError{Code: "authorization_required", Message: "authorization_confirmed must be true for WebSocket mutation testing"}
	}
	if len(params.Payloads) > 100 {
		return nil, &protocol.RPCError{Code: "invalid_params", Message: "payload list exceeds 100"}
	}
	results := []any{}
	for _, payload := range params.Payloads {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		result, err := s.websockets.Probe(ctx, wsengine.SendOptions{ConnectionID: params.ConnectionID, MessageType: "text", Payload: payload})
		cancel()
		if err != nil {
			results = append(results, map[string]any{"payload": payload, "error": err.Error()})
		} else {
			results = append(results, result)
		}
	}
	return map[string]any{"results": results, "count": len(results)}, nil
}

func (s *Server) scannerSubscriptionAbuse(raw json.RawMessage) (any, *protocol.RPCError) {
	var params struct {
		ProjectID              string `json:"project_id"`
		ConnectionID           string `json:"connection_id"`
		Payload                string `json:"payload"`
		AuthorizationConfirmed bool   `json:"authorization_confirmed"`
	}
	if rpcErr := decodeParams(raw, &params); rpcErr != nil {
		return nil, rpcErr
	}
	if !params.AuthorizationConfirmed {
		return nil, &protocol.RPCError{Code: "authorization_required", Message: "authorization_confirmed must be true for subscription testing"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	result, err := s.websockets.Probe(ctx, wsengine.SendOptions{ConnectionID: params.ConnectionID, MessageType: "text", Payload: params.Payload})
	if err != nil {
		return scanResult(nil, err)
	}
	encoded, _ := json.Marshal(result)
	lower := strings.ToLower(string(encoded))
	exposed := !strings.Contains(lower, "unauthorized") && !strings.Contains(lower, "forbidden") && !strings.Contains(lower, "error")
	if exposed && params.ProjectID != "" {
		_, _ = s.store.SaveEntity(context.Background(), "findings", store.Entity{ProjectID: params.ProjectID, Name: "subscription-abuse", Value: params.Payload, Metadata: map[string]any{"severity": "high", "detail": "Subscription returned data without an observed authorization error", "confidence": "medium"}})
	}
	return map[string]any{"possible_subscription_abuse": exposed, "exchange": result}, nil
}

func (s *Server) scannerAuthTest(raw json.RawMessage) (any, *protocol.RPCError) {
	var params struct {
		ProjectID              string            `json:"project_id"`
		URL                    string            `json:"url"`
		AuthenticatedHeaders   map[string]string `json:"authenticated_headers"`
		AuthorizationConfirmed bool              `json:"authorization_confirmed"`
	}
	if rpcErr := decodeParams(raw, &params); rpcErr != nil {
		return nil, rpcErr
	}
	if !params.AuthorizationConfirmed {
		return nil, &protocol.RPCError{Code: "authorization_required", Message: "authorization_confirmed must be true for authentication testing"}
	}
	unauth, unauthErr := s.websockets.Connect(context.Background(), wsengine.ConnectOptions{ProjectID: params.ProjectID, URL: params.URL, TimeoutMS: 10000})
	if unauthErr == nil {
		_ = s.websockets.Disconnect(unauth["connection_id"].(string))
	}
	auth, authErr := s.websockets.Connect(context.Background(), wsengine.ConnectOptions{ProjectID: params.ProjectID, URL: params.URL, Headers: params.AuthenticatedHeaders, TimeoutMS: 10000})
	if authErr == nil {
		_ = s.websockets.Disconnect(auth["connection_id"].(string))
	}
	return map[string]any{"unauthenticated_accepted": unauthErr == nil, "authenticated_accepted": authErr == nil, "authentication_enforced": unauthErr != nil && authErr == nil, "unauthenticated_error": errorText(unauthErr), "authenticated_error": errorText(authErr)}, nil
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
func scanResult(result any, err error) (any, *protocol.RPCError) {
	if err == nil {
		return result, nil
	}
	return nil, &protocol.RPCError{Code: "scan_error", Message: "Security test failed", Detail: err.Error()}
}
