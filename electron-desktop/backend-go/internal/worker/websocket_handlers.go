package worker

import (
	"context"
	"encoding/json"
	"time"

	"github.com/regaan/wshawk/electron-desktop/backend-go/internal/protocol"
	"github.com/regaan/wshawk/electron-desktop/backend-go/internal/wsengine"
)

func (s *Server) registerWebSocketHandlers() {
	s.handlers["ws.connect"] = s.wsConnect
	s.handlers["ws.send"] = s.wsSend
	s.handlers["ws.disconnect"] = s.wsDisconnect
	s.handlers["ws.replay"] = s.wsReplay
	s.handlers["ws.intercept.set"] = s.wsInterceptSet
	s.handlers["ws.intercept.action"] = s.wsInterceptAction
	s.handlers["ws.probe"] = s.wsProbe
	s.handlers["ws.race"] = s.wsRace
}

func (s *Server) wsProbe(raw json.RawMessage) (any, *protocol.RPCError) {
	var params struct {
		wsengine.SendOptions
		TimeoutMS int `json:"timeout_ms"`
	}
	if rpcErr := decodeParams(raw, &params); rpcErr != nil {
		return nil, rpcErr
	}
	timeout := time.Duration(params.TimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	if timeout > 60*time.Second {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	result, err := s.websockets.Probe(ctx, params.SendOptions)
	return transportResult(result, err)
}

func (s *Server) wsRace(raw json.RawMessage) (any, *protocol.RPCError) {
	var params struct {
		wsengine.SendOptions
		Count                  int  `json:"count"`
		AuthorizationConfirmed bool `json:"authorization_confirmed"`
	}
	if rpcErr := decodeParams(raw, &params); rpcErr != nil {
		return nil, rpcErr
	}
	if !params.AuthorizationConfirmed {
		return nil, &protocol.RPCError{Code: "authorization_required", Message: "authorization_confirmed must be true for WebSocket race testing"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	result, err := s.websockets.Race(ctx, params.SendOptions, params.Count)
	return transportResult(result, err)
}

func (s *Server) wsConnect(raw json.RawMessage) (any, *protocol.RPCError) {
	var params wsengine.ConnectOptions
	if rpcErr := decodeParams(raw, &params); rpcErr != nil {
		return nil, rpcErr
	}
	result, err := s.websockets.Connect(context.Background(), params)
	return transportResult(result, err)
}

func (s *Server) wsSend(raw json.RawMessage) (any, *protocol.RPCError) {
	var params wsengine.SendOptions
	if rpcErr := decodeParams(raw, &params); rpcErr != nil {
		return nil, rpcErr
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	result, err := s.websockets.Send(ctx, params)
	return transportResult(result, err)
}

func (s *Server) wsDisconnect(raw json.RawMessage) (any, *protocol.RPCError) {
	var params struct {
		ConnectionID string `json:"connection_id"`
	}
	if rpcErr := decodeParams(raw, &params); rpcErr != nil {
		return nil, rpcErr
	}
	err := s.websockets.Disconnect(params.ConnectionID)
	return transportResult(map[string]any{"disconnected": err == nil, "connection_id": params.ConnectionID}, err)
}

func (s *Server) wsReplay(raw json.RawMessage) (any, *protocol.RPCError) {
	var params struct {
		ConnectionID string `json:"connection_id"`
		FrameID      string `json:"frame_id"`
	}
	if rpcErr := decodeParams(raw, &params); rpcErr != nil {
		return nil, rpcErr
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	result, err := s.websockets.Replay(ctx, params.ConnectionID, params.FrameID)
	return transportResult(result, err)
}

func (s *Server) wsInterceptSet(raw json.RawMessage) (any, *protocol.RPCError) {
	var params struct {
		ConnectionID string `json:"connection_id"`
		Enabled      bool   `json:"enabled"`
	}
	if rpcErr := decodeParams(raw, &params); rpcErr != nil {
		return nil, rpcErr
	}
	result, err := s.websockets.SetIntercept(params.ConnectionID, params.Enabled)
	return transportResult(result, err)
}

func (s *Server) wsInterceptAction(raw json.RawMessage) (any, *protocol.RPCError) {
	var params struct {
		InterceptID   string `json:"intercept_id"`
		Action        string `json:"action"`
		Payload       string `json:"payload"`
		PayloadBase64 string `json:"payload_base64"`
	}
	if rpcErr := decodeParams(raw, &params); rpcErr != nil {
		return nil, rpcErr
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	result, err := s.websockets.InterceptAction(ctx, params.InterceptID, params.Action, params.Payload, params.PayloadBase64)
	return transportResult(result, err)
}

func transportResult(result any, err error) (any, *protocol.RPCError) {
	if err == nil {
		return result, nil
	}
	return nil, &protocol.RPCError{Code: "transport_error", Message: "WebSocket operation failed", Detail: err.Error()}
}
