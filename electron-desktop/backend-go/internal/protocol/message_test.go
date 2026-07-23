package protocol

import "testing"

func TestDecodeRequestValidatesEnvelope(t *testing.T) {
	request, rpcError := DecodeRequest([]byte(`{"version":"1","id":"req-1","method":"system.health","params":{}}`))
	if rpcError != nil {
		t.Fatalf("unexpected RPC error: %#v", rpcError)
	}
	if request.ID != "req-1" || request.Method != "system.health" {
		t.Fatalf("unexpected request: %#v", request)
	}
}

func TestDecodeRequestRejectsUnknownFields(t *testing.T) {
	_, rpcError := DecodeRequest([]byte(`{"version":"1","id":"req-1","method":"system.health","params":{},"extra":true}`))
	if rpcError == nil || rpcError.Code != "invalid_json" {
		t.Fatalf("expected invalid_json, got %#v", rpcError)
	}
}

func TestDecodeRequestRejectsNonObjectParams(t *testing.T) {
	_, rpcError := DecodeRequest([]byte(`{"version":"1","id":"req-1","method":"system.health","params":[]}`))
	if rpcError == nil || rpcError.Code != "invalid_params" {
		t.Fatalf("expected invalid_params, got %#v", rpcError)
	}
}

func TestDecodeRequestRejectsVersionMismatch(t *testing.T) {
	_, rpcError := DecodeRequest([]byte(`{"version":"99","id":"req-1","method":"system.health","params":{}}`))
	if rpcError == nil || rpcError.Code != "version_mismatch" {
		t.Fatalf("expected version_mismatch, got %#v", rpcError)
	}
}
