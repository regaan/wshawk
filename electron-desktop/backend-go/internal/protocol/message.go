package protocol

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

const (
	Version         = "1"
	MaxRequestBytes = 8 * 1024 * 1024
)

type Request struct {
	Version string          `json:"version"`
	ID      string          `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type RPCError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Detail  any    `json:"detail,omitempty"`
}

type Response struct {
	Version string    `json:"version"`
	ID      string    `json:"id"`
	Result  any       `json:"result,omitempty"`
	Error   *RPCError `json:"error,omitempty"`
}

func DecodeRequest(line []byte) (Request, *RPCError) {
	if len(line) == 0 || len(line) > MaxRequestBytes {
		return Request{}, &RPCError{Code: "invalid_request", Message: "Request size is invalid"}
	}

	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	var request Request
	if err := decoder.Decode(&request); err != nil {
		return Request{}, &RPCError{Code: "invalid_json", Message: "Request is not valid JSON"}
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return Request{}, &RPCError{Code: "invalid_json", Message: "Request contains multiple JSON values"}
	}

	if request.Version != Version {
		return request, &RPCError{Code: "version_mismatch", Message: "Unsupported protocol version"}
	}
	if request.ID == "" || len(request.ID) > 128 {
		return request, &RPCError{Code: "invalid_request", Message: "Request ID is required"}
	}
	if request.Method == "" || len(request.Method) > 128 {
		return request, &RPCError{Code: "invalid_request", Message: "Method is required"}
	}
	if len(request.Params) == 0 {
		request.Params = json.RawMessage(`{}`)
	}
	var params map[string]any
	if err := json.Unmarshal(request.Params, &params); err != nil || params == nil {
		return request, &RPCError{Code: "invalid_params", Message: "Params must be a JSON object"}
	}
	return request, nil
}

func Success(id string, result any) Response {
	return Response{Version: Version, ID: id, Result: result}
}

func Failure(id string, rpcError *RPCError) Response {
	if rpcError == nil {
		rpcError = &RPCError{Code: "internal_error", Message: "Internal worker error"}
	}
	return Response{Version: Version, ID: id, Error: rpcError}
}

func EncodeResponse(response Response) ([]byte, error) {
	data, err := json.Marshal(response)
	if err != nil {
		return nil, fmt.Errorf("encode response: %w", err)
	}
	return data, nil
}
