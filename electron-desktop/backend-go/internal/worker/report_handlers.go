package worker

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/regaan/wshawk/electron-desktop/backend-go/internal/certutil"
	"github.com/regaan/wshawk/electron-desktop/backend-go/internal/integration"
	"github.com/regaan/wshawk/electron-desktop/backend-go/internal/protocol"
	"github.com/regaan/wshawk/electron-desktop/backend-go/internal/reporting"
)

func (s *Server) registerReportHandlers() {
	s.handlers["reports.generate"] = s.reportGenerate
	s.handlers["evidence.bundle"] = s.evidenceBundle
	s.handlers["evidence.verify"] = s.evidenceVerify
	s.handlers["integration.send"] = s.integrationSend
	s.handlers["cert.ca.generate"] = s.certGenerateCA
	s.handlers["cert.host.generate"] = s.certGenerateHost
}
func (s *Server) reportGenerate(raw json.RawMessage) (any, *protocol.RPCError) {
	var params struct {
		ProjectID string `json:"project_id"`
		Format    string `json:"format"`
	}
	if rpcErr := decodeParams(raw, &params); rpcErr != nil {
		return nil, rpcErr
	}
	result, err := s.reports.Generate(context.Background(), params.ProjectID, params.Format)
	return reportResult(result, err)
}
func (s *Server) evidenceBundle(raw json.RawMessage) (any, *protocol.RPCError) {
	var params struct {
		ProjectID string `json:"project_id"`
	}
	if rpcErr := decodeParams(raw, &params); rpcErr != nil {
		return nil, rpcErr
	}
	result, err := s.reports.Bundle(context.Background(), params.ProjectID)
	return reportResult(result, err)
}
func (s *Server) evidenceVerify(raw json.RawMessage) (any, *protocol.RPCError) {
	var params struct {
		ContentBase64 string `json:"content_base64"`
	}
	if rpcErr := decodeParams(raw, &params); rpcErr != nil {
		return nil, rpcErr
	}
	result, err := reporting.VerifyBundle(params.ContentBase64)
	return reportResult(result, err)
}
func (s *Server) integrationSend(raw json.RawMessage) (any, *protocol.RPCError) {
	var params integration.Request
	if rpcErr := decodeParams(raw, &params); rpcErr != nil {
		return nil, rpcErr
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	result, err := integration.Send(ctx, params)
	return reportResult(result, err)
}
func (s *Server) certGenerateCA(raw json.RawMessage) (any, *protocol.RPCError) {
	var params struct {
		CommonName string `json:"common_name"`
		ValidDays  int    `json:"valid_days"`
	}
	if rpcErr := decodeParams(raw, &params); rpcErr != nil {
		return nil, rpcErr
	}
	if strings.TrimSpace(params.CommonName) == "" {
		params.CommonName = "WSHawk Local Lab CA"
	}
	result, err := certutil.GenerateCA(params.CommonName, params.ValidDays)
	if err != nil {
		return reportResult(nil, err)
	}
	s.certificateMu.Lock()
	s.certificateCA = &result
	s.certificateMu.Unlock()
	return map[string]any{"status": "generated", "subject": params.CommonName, "expires": result.NotAfter, "fingerprint": result.Fingerprint, "certificate_pem": result.CertificatePEM, "storage": "private-worker-memory"}, nil
}
func (s *Server) certGenerateHost(raw json.RawMessage) (any, *protocol.RPCError) {
	var params struct {
		CACertificatePEM string `json:"ca_certificate_pem"`
		CAKeyPEM         string `json:"ca_key_pem"`
		Hostname         string `json:"hostname"`
		ValidDays        int    `json:"valid_days"`
	}
	if rpcErr := decodeParams(raw, &params); rpcErr != nil {
		return nil, rpcErr
	}
	if params.CACertificatePEM == "" || params.CAKeyPEM == "" {
		s.certificateMu.Lock()
		if s.certificateCA != nil {
			params.CACertificatePEM = s.certificateCA.CertificatePEM
			params.CAKeyPEM = s.certificateCA.PrivateKeyPEM
		}
		s.certificateMu.Unlock()
	}
	result, err := certutil.GenerateHost(params.CACertificatePEM, params.CAKeyPEM, params.Hostname, params.ValidDays)
	if err != nil {
		return reportResult(nil, err)
	}
	return map[string]any{"status": "generated", "hostname": params.Hostname, "san": []string{params.Hostname}, "expires": result.NotAfter, "fingerprint": result.Fingerprint, "certificate_pem": result.CertificatePEM, "storage": "private-worker-memory"}, nil
}
func reportResult(result any, err error) (any, *protocol.RPCError) {
	if err == nil {
		return result, nil
	}
	return nil, &protocol.RPCError{Code: "report_error", Message: "Report or integration operation failed", Detail: err.Error()}
}
