package worker

import (
	"context"
	"encoding/json"
	"time"

	"github.com/regaan/wshawk/electron-desktop/backend-go/internal/netsec"
	"github.com/regaan/wshawk/electron-desktop/backend-go/internal/protocol"
)

func (s *Server) registerNetworkHandlers() {
	s.handlers["network.dns"] = s.networkDNS
	s.handlers["network.subdomains"] = s.networkSubdomains
	s.handlers["network.portscan"] = s.networkPortscan
}
func (s *Server) networkDNS(raw json.RawMessage) (any, *protocol.RPCError) {
	var params struct {
		Target string `json:"target"`
	}
	if rpcErr := decodeParams(raw, &params); rpcErr != nil {
		return nil, rpcErr
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	result, err := netsec.DNS(ctx, params.Target)
	return networkResult(result, err)
}
func (s *Server) networkSubdomains(raw json.RawMessage) (any, *protocol.RPCError) {
	var params struct {
		Target string   `json:"target"`
		Names  []string `json:"names"`
	}
	if rpcErr := decodeParams(raw, &params); rpcErr != nil {
		return nil, rpcErr
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result, err := netsec.Subdomains(ctx, params.Target, params.Names)
	return networkResult(result, err)
}
func (s *Server) networkPortscan(raw json.RawMessage) (any, *protocol.RPCError) {
	var params struct {
		Target                 string `json:"target"`
		Ports                  string `json:"ports"`
		TimeoutMS              int    `json:"timeout_ms"`
		AuthorizationConfirmed bool   `json:"authorization_confirmed"`
	}
	if rpcErr := decodeParams(raw, &params); rpcErr != nil {
		return nil, rpcErr
	}
	if !params.AuthorizationConfirmed {
		return nil, &protocol.RPCError{Code: "authorization_required", Message: "authorization_confirmed must be true for port scanning"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	result, err := netsec.PortScan(ctx, params.Target, params.Ports, params.TimeoutMS)
	return networkResult(result, err)
}
func networkResult(result any, err error) (any, *protocol.RPCError) {
	if err == nil {
		return result, nil
	}
	return nil, &protocol.RPCError{Code: "network_error", Message: "Network discovery failed", Detail: err.Error()}
}
