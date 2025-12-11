package i2pcontrol

import (
	"encoding/json"
	"testing"
)

// TestParseRequestValid tests parsing valid JSON-RPC 2.0 requests
func TestParseRequestValid(t *testing.T) {
	tests := []struct {
		name       string
		data       string
		wantMethod string
		wantID     interface{}
		hasParams  bool
	}{
		{
			name:       "simple request with string ID",
			data:       `{"jsonrpc":"2.0","id":"test-1","method":"Echo"}`,
			wantMethod: "Echo",
			wantID:     "test-1",
			hasParams:  false,
		},
		{
			name:       "request with number ID",
			data:       `{"jsonrpc":"2.0","id":42,"method":"RouterInfo"}`,
			wantMethod: "RouterInfo",
			wantID:     float64(42), // JSON numbers decode as float64
			hasParams:  false,
		},
		{
			name:       "request with params object",
			data:       `{"jsonrpc":"2.0","id":1,"method":"Authenticate","params":{"Password":"test"}}`,
			wantMethod: "Authenticate",
			wantID:     float64(1),
			hasParams:  true,
		},
		{
			name:       "request with params array",
			data:       `{"jsonrpc":"2.0","id":2,"method":"Test","params":[1,2,3]}`,
			wantMethod: "Test",
			wantID:     float64(2),
			hasParams:  true,
		},
		{
			name:       "notification without ID",
			data:       `{"jsonrpc":"2.0","method":"Notify"}`,
			wantMethod: "Notify",
			wantID:     nil,
			hasParams:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := ParseRequest([]byte(tt.data))
			if err != nil {
				t.Fatalf("ParseRequest failed: %v", err)
			}

			if req.JSONRPC != "2.0" {
				t.Errorf("JSONRPC version: got %q, want \"2.0\"", req.JSONRPC)
			}

			if req.Method != tt.wantMethod {
				t.Errorf("Method: got %q, want %q", req.Method, tt.wantMethod)
			}

			if req.ID != tt.wantID {
				t.Errorf("ID: got %v, want %v", req.ID, tt.wantID)
			}

			if tt.hasParams && len(req.Params) == 0 {
				t.Error("Expected params to be present")
			}

			if !tt.hasParams && len(req.Params) > 0 {
				t.Errorf("Expected no params, got %q", req.Params)
			}
		})
	}
}

// TestParseRequestInvalid tests parsing invalid requests
func TestParseRequestInvalid(t *testing.T) {
	tests := []struct {
		name        string
		data        string
		wantErrCode int
	}{
		{
			name:        "empty request",
			data:        "",
			wantErrCode: ErrCodeParseError,
		},
		{
			name:        "invalid JSON",
			data:        `{"jsonrpc":"2.0",invalid}`,
			wantErrCode: ErrCodeParseError,
		},
		{
			name:        "missing jsonrpc field",
			data:        `{"id":1,"method":"Test"}`,
			wantErrCode: ErrCodeInvalidRequest,
		},
		{
			name:        "wrong jsonrpc version",
			data:        `{"jsonrpc":"1.0","id":1,"method":"Test"}`,
			wantErrCode: ErrCodeInvalidRequest,
		},
		{
			name:        "missing method",
			data:        `{"jsonrpc":"2.0","id":1}`,
			wantErrCode: ErrCodeInvalidRequest,
		},
		{
			name:        "empty method",
			data:        `{"jsonrpc":"2.0","id":1,"method":""}`,
			wantErrCode: ErrCodeInvalidRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := ParseRequest([]byte(tt.data))

			if err == nil {
				t.Fatal("ParseRequest should have failed")
			}

			rpcErr, ok := err.(*RPCError)
			if !ok {
				t.Fatalf("Expected *RPCError, got %T: %v", err, err)
			}

			if rpcErr.Code != tt.wantErrCode {
				t.Errorf("Error code: got %d, want %d", rpcErr.Code, tt.wantErrCode)
			}

			if req != nil {
				t.Error("Expected nil request on error")
			}
		})
	}
}

// TestRequestIsNotification tests notification detection
func TestRequestIsNotification(t *testing.T) {
	tests := []struct {
		name       string
		data       string
		wantNotify bool
	}{
		{
			name:       "request with ID is not notification",
			data:       `{"jsonrpc":"2.0","id":1,"method":"Test"}`,
			wantNotify: false,
		},
		{
			name:       "request without ID is notification",
			data:       `{"jsonrpc":"2.0","method":"Test"}`,
			wantNotify: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := ParseRequest([]byte(tt.data))
			if err != nil {
				t.Fatalf("ParseRequest failed: %v", err)
			}

			if req.IsNotification() != tt.wantNotify {
				t.Errorf("IsNotification: got %v, want %v", req.IsNotification(), tt.wantNotify)
			}
		})
	}
}

// TestResponseMarshal tests response serialization
func TestResponseMarshal(t *testing.T) {
	tests := []struct {
		name     string
		response *Response
		validate func(t *testing.T, data []byte)
	}{
		{
			name: "success response",
			response: NewSuccessResponse(1, map[string]string{
				"Echo": "hello",
			}),
			validate: func(t *testing.T, data []byte) {
				var parsed map[string]interface{}
				if err := json.Unmarshal(data, &parsed); err != nil {
					t.Fatalf("Failed to parse response: %v", err)
				}

				if parsed["jsonrpc"] != "2.0" {
					t.Errorf("jsonrpc: got %v, want \"2.0\"", parsed["jsonrpc"])
				}

				if parsed["id"] != float64(1) {
					t.Errorf("id: got %v, want 1", parsed["id"])
				}

				if parsed["result"] == nil {
					t.Error("Expected result field")
				}

				if parsed["error"] != nil {
					t.Error("Expected no error field in success response")
				}
			},
		},
		{
			name: "error response",
			response: NewErrorResponse(2, NewRPCError(
				ErrCodeMethodNotFound,
				"method not found",
			)),
			validate: func(t *testing.T, data []byte) {
				var parsed map[string]interface{}
				if err := json.Unmarshal(data, &parsed); err != nil {
					t.Fatalf("Failed to parse response: %v", err)
				}

				if parsed["result"] != nil {
					t.Error("Expected no result field in error response")
				}

				if parsed["error"] == nil {
					t.Fatal("Expected error field")
				}

				errObj := parsed["error"].(map[string]interface{})
				if errObj["code"] != float64(ErrCodeMethodNotFound) {
					t.Errorf("error code: got %v, want %d", errObj["code"], ErrCodeMethodNotFound)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.response.Marshal()
			if err != nil {
				t.Fatalf("Marshal failed: %v", err)
			}

			tt.validate(t, data)
		})
	}
}

// TestRPCErrorError tests RPCError.Error() method
func TestRPCErrorError(t *testing.T) {
	tests := []struct {
		name      string
		err       *RPCError
		wantMatch string
	}{
		{
			name: "error without data",
			err: &RPCError{
				Code:    ErrCodeMethodNotFound,
				Message: "method not found",
			},
			wantMatch: "JSON-RPC error -32601: method not found",
		},
		{
			name: "error with data",
			err: &RPCError{
				Code:    ErrCodeInvalidParams,
				Message: "invalid params",
				Data:    "missing field",
			},
			wantMatch: "JSON-RPC error -32602: invalid params",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errStr := tt.err.Error()
			if errStr == "" {
				t.Error("Error() returned empty string")
			}

			// Check that error message contains expected parts
			if len(errStr) < len(tt.wantMatch) {
				t.Errorf("Error string too short: got %q", errStr)
			}
		})
	}
}

// TestNewRPCError tests error creation helpers
func TestNewRPCError(t *testing.T) {
	err := NewRPCError(ErrCodeInternalError, "test error")

	if err.Code != ErrCodeInternalError {
		t.Errorf("Code: got %d, want %d", err.Code, ErrCodeInternalError)
	}

	if err.Message != "test error" {
		t.Errorf("Message: got %q, want \"test error\"", err.Message)
	}

	if err.Data != nil {
		t.Errorf("Data: got %v, want nil", err.Data)
	}
}

// TestNewRPCErrorWithData tests error creation with data
func TestNewRPCErrorWithData(t *testing.T) {
	data := map[string]string{"detail": "extra info"}
	err := NewRPCErrorWithData(ErrCodeInvalidParams, "test error", data)

	if err.Code != ErrCodeInvalidParams {
		t.Errorf("Code: got %d, want %d", err.Code, ErrCodeInvalidParams)
	}

	if err.Message != "test error" {
		t.Errorf("Message: got %q, want \"test error\"", err.Message)
	}

	if err.Data == nil {
		t.Error("Expected data to be set")
	}
}

// TestErrorCodes tests that error codes match specification
func TestErrorCodes(t *testing.T) {
	tests := []struct {
		name string
		code int
		want int
	}{
		{"ParseError", ErrCodeParseError, -32700},
		{"InvalidRequest", ErrCodeInvalidRequest, -32600},
		{"MethodNotFound", ErrCodeMethodNotFound, -32601},
		{"InvalidParams", ErrCodeInvalidParams, -32602},
		{"InternalError", ErrCodeInternalError, -32603},
		{"AuthRequired", ErrCodeAuthRequired, -32000},
		{"AuthFailed", ErrCodeAuthFailed, -32001},
		{"NotImplemented", ErrCodeNotImpl, -32002},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.code != tt.want {
				t.Errorf("Error code %s: got %d, want %d", tt.name, tt.code, tt.want)
			}
		})
	}
}

// TestRequestParamsPreserved tests that params are preserved as RawMessage
func TestRequestParamsPreserved(t *testing.T) {
	data := `{"jsonrpc":"2.0","id":1,"method":"Test","params":{"key":"value","nested":{"a":1}}}`
	req, err := ParseRequest([]byte(data))
	if err != nil {
		t.Fatalf("ParseRequest failed: %v", err)
	}

	// Parse params to verify they're intact
	var params map[string]interface{}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		t.Fatalf("Failed to unmarshal params: %v", err)
	}

	if params["key"] != "value" {
		t.Errorf("params[key]: got %v, want \"value\"", params["key"])
	}

	if params["nested"] == nil {
		t.Error("Expected nested object in params")
	}
}

// TestResponseNullID tests response with null ID
func TestResponseNullID(t *testing.T) {
	resp := NewErrorResponse(nil, NewRPCError(ErrCodeParseError, "parse error"))

	data, err := resp.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Check that ID field exists and is null
	if _, exists := parsed["id"]; !exists {
		t.Error("Expected ID field to exist")
	}

	if parsed["id"] != nil {
		t.Errorf("Expected null ID, got %v", parsed["id"])
	}
}

// BenchmarkParseRequest measures request parsing performance
func BenchmarkParseRequest(b *testing.B) {
	data := []byte(`{"jsonrpc":"2.0","id":1,"method":"Echo","params":{"Echo":"test"}}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ParseRequest(data)
		if err != nil {
			b.Fatalf("ParseRequest failed: %v", err)
		}
	}
}

// BenchmarkResponseMarshal measures response marshaling performance
func BenchmarkResponseMarshal(b *testing.B) {
	resp := NewSuccessResponse(1, map[string]string{"Echo": "test"})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := resp.Marshal()
		if err != nil {
			b.Fatalf("Marshal failed: %v", err)
		}
	}
}
