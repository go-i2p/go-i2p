package i2pcontrol

import (
	"encoding/json"
	"fmt"
)

// JSON-RPC 2.0 specification error codes
// Reference: https://www.jsonrpc.org/specification
const (
	// Standard JSON-RPC 2.0 error codes
	ErrCodeParseError     = -32700 // Invalid JSON received by server
	ErrCodeInvalidRequest = -32600 // JSON is not a valid Request object
	ErrCodeMethodNotFound = -32601 // Method does not exist
	ErrCodeInvalidParams  = -32602 // Invalid method parameters
	ErrCodeInternalError  = -32603 // Internal JSON-RPC error

	// I2PControl-specific error codes
	// Using -32000 to -32099 range (reserved for implementation-defined errors)
	ErrCodeAuthRequired = -32000 // Authentication token required
	ErrCodeAuthFailed   = -32001 // Authentication failed (invalid password)
	ErrCodeNotImpl      = -32002 // Method not yet implemented
)

// Request represents a JSON-RPC 2.0 request.
// Follows the specification at https://www.jsonrpc.org/specification
//
// A Request object has four properties:
//   - jsonrpc: Must be exactly "2.0"
//   - method: Name of the method to invoke
//   - params: Parameters for the method (can be omitted)
//   - id: Request identifier (string, number, or null)
type Request struct {
	// JSONRPC specifies the version of the JSON-RPC protocol
	// MUST be exactly "2.0"
	JSONRPC string `json:"jsonrpc"`

	// ID is the request identifier established by the client
	// Can be string, number, or null
	// If omitted, the request is a notification (no response expected)
	ID interface{} `json:"id,omitempty"`

	// Method is the name of the method to be invoked
	// Method names that begin with "rpc." are reserved for system extensions
	Method string `json:"method"`

	// Params holds the parameter values to be used during method invocation
	// Can be omitted (treated as empty object) or provided as object/array
	// We use json.RawMessage to defer parsing until method handler needs it
	Params json.RawMessage `json:"params,omitempty"`
}

// Response represents a JSON-RPC 2.0 response.
// A Response object has four properties:
//   - jsonrpc: Must be exactly "2.0"
//   - result: Result of the method invocation (success case)
//   - error: Error object (failure case)
//   - id: Request identifier (copied from request)
//
// Note: Either result OR error MUST be present, never both.
type Response struct {
	// JSONRPC specifies the version of the JSON-RPC protocol
	// MUST be exactly "2.0"
	JSONRPC string `json:"jsonrpc"`

	// ID is the request identifier copied from the request
	// MUST be the same as the request ID
	// Can be null if the request ID was invalid or missing
	ID interface{} `json:"id"`

	// Result holds the method invocation result
	// MUST NOT exist if there was an error
	// Omitted from JSON if nil
	Result interface{} `json:"result,omitempty"`

	// Error holds the error object if method invocation failed
	// MUST NOT exist if the method succeeded
	// Omitted from JSON if nil
	Error *RPCError `json:"error,omitempty"`
}

// RPCError represents a JSON-RPC 2.0 error object.
// An error object has three properties:
//   - code: A number that indicates the error type
//   - message: A short description of the error
//   - data: Additional information about the error (optional)
type RPCError struct {
	// Code indicates the error type
	// Standard codes: -32700 to -32603
	// Implementation-defined: -32000 to -32099
	Code int `json:"code"`

	// Message provides a short description of the error
	// Should be a single sentence
	Message string `json:"message"`

	// Data provides additional error information (optional)
	// Can be omitted or contain any JSON value
	Data interface{} `json:"data,omitempty"`
}

// Error implements the error interface for RPCError
// Allows RPCError to be used as a standard Go error
func (e *RPCError) Error() string {
	if e.Data != nil {
		return fmt.Sprintf("JSON-RPC error %d: %s (data: %v)", e.Code, e.Message, e.Data)
	}
	return fmt.Sprintf("JSON-RPC error %d: %s", e.Code, e.Message)
}

// ParseRequest parses a JSON-RPC 2.0 request from raw bytes.
// Returns an error if the JSON is invalid or the request is malformed.
//
// Validation performed:
//   - Valid JSON structure
//   - "jsonrpc" field equals "2.0"
//   - "method" field is present and non-empty
//
// Note: ID field is optional (omitted for notifications)
// Note: Params field is optional (treated as empty if omitted)
func ParseRequest(data []byte) (*Request, error) {
	// Check for empty input
	if len(data) == 0 {
		return nil, &RPCError{
			Code:    ErrCodeParseError,
			Message: "empty request",
		}
	}

	// Parse JSON into Request struct
	var req Request
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, &RPCError{
			Code:    ErrCodeParseError,
			Message: "invalid JSON",
			Data:    err.Error(),
		}
	}

	// Validate JSON-RPC version
	if req.JSONRPC != "2.0" {
		return nil, &RPCError{
			Code:    ErrCodeInvalidRequest,
			Message: "invalid JSON-RPC version",
			Data:    fmt.Sprintf("expected \"2.0\", got %q", req.JSONRPC),
		}
	}

	// Validate method name
	if req.Method == "" {
		return nil, &RPCError{
			Code:    ErrCodeInvalidRequest,
			Message: "missing method name",
		}
	}

	return &req, nil
}

// IsNotification checks if this request is a notification.
// Notifications are requests without an ID field.
// The server MUST NOT reply to notifications.
func (r *Request) IsNotification() bool {
	return r.ID == nil
}

// Marshal serializes the response to JSON.
// Returns JSON bytes ready to send to the client.
func (r *Response) Marshal() ([]byte, error) {
	return json.Marshal(r)
}

// NewSuccessResponse creates a successful JSON-RPC response.
// The result parameter will be serialized as the "result" field.
func NewSuccessResponse(id interface{}, result interface{}) *Response {
	return &Response{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}
}

// NewErrorResponse creates an error JSON-RPC response.
// The error will be included in the "error" field.
func NewErrorResponse(id interface{}, err *RPCError) *Response {
	return &Response{
		JSONRPC: "2.0",
		ID:      id,
		Error:   err,
	}
}

// NewRPCError creates a new RPCError with the given code and message.
// This is a convenience function for creating standard errors.
func NewRPCError(code int, message string) *RPCError {
	return &RPCError{
		Code:    code,
		Message: message,
	}
}

// NewRPCErrorWithData creates a new RPCError with additional data.
// The data field can contain any additional error context.
func NewRPCErrorWithData(code int, message string, data interface{}) *RPCError {
	return &RPCError{
		Code:    code,
		Message: message,
		Data:    data,
	}
}
