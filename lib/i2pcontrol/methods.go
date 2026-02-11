package i2pcontrol

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
)

// RPCHandler is the interface that RPC method handlers must implement.
// Each handler processes a specific JSON-RPC method.
//
// The Handle method receives:
//   - ctx: Context for cancellation and deadlines
//   - params: The "params" field from the JSON-RPC request as json.RawMessage
//
// The Handle method returns:
//   - result: The method result (will be serialized as "result" in response)
//   - error: An error if the method failed (should be *RPCError for proper JSON-RPC errors)
type RPCHandler interface {
	Handle(ctx context.Context, params json.RawMessage) (interface{}, error)
}

// RPCHandlerFunc is a function adapter for RPCHandler interface.
// Allows using simple functions as RPC handlers without creating a type.
type RPCHandlerFunc func(ctx context.Context, params json.RawMessage) (interface{}, error)

// Handle calls the underlying function.
// This makes RPCHandlerFunc satisfy the RPCHandler interface.
func (f RPCHandlerFunc) Handle(ctx context.Context, params json.RawMessage) (interface{}, error) {
	return f(ctx, params)
}

// MethodRegistry manages the registration and dispatch of RPC methods.
// It maps method names to their corresponding handlers.
// Thread-safe for concurrent registration and dispatch.
//
// Usage:
//
//	registry := NewMethodRegistry()
//	registry.Register("Echo", echoHandler)
//	result, err := registry.Dispatch(ctx, "Echo", params)
type MethodRegistry struct {
	handlers map[string]RPCHandler
	mu       sync.RWMutex
}

// NewMethodRegistry creates a new method registry.
// The registry starts empty; handlers must be registered via Register().
func NewMethodRegistry() *MethodRegistry {
	return &MethodRegistry{
		handlers: make(map[string]RPCHandler),
	}
}

// Register adds a handler for the given method name.
// If a handler already exists for this method, it will be replaced.
//
// Parameters:
//   - method: The method name (e.g., "Echo", "RouterInfo")
//   - handler: The handler implementation
//
// Example:
//
//	registry.Register("Echo", &EchoHandler{})
//	registry.Register("Authenticate", RPCHandlerFunc(authFunc))
func (mr *MethodRegistry) Register(method string, handler RPCHandler) {
	mr.mu.Lock()
	defer mr.mu.Unlock()

	mr.handlers[method] = handler

	log.WithFields(map[string]interface{}{
		"at":     "MethodRegistry.Register",
		"method": method,
	}).Debug("registered RPC method")
}

// Unregister removes a handler for the given method name.
// Does nothing if the method is not registered.
//
// Parameters:
//   - method: The method name to unregister
func (mr *MethodRegistry) Unregister(method string) {
	mr.mu.Lock()
	defer mr.mu.Unlock()

	delete(mr.handlers, method)

	log.WithFields(map[string]interface{}{
		"at":     "MethodRegistry.Unregister",
		"method": method,
	}).Debug("unregistered RPC method")
}

// IsRegistered checks if a handler exists for the given method.
//
// Parameters:
//   - method: The method name to check
//
// Returns:
//   - bool: true if a handler is registered, false otherwise
func (mr *MethodRegistry) IsRegistered(method string) bool {
	mr.mu.RLock()
	defer mr.mu.RUnlock()

	_, exists := mr.handlers[method]
	return exists
}

// ListMethods returns a list of all registered method names.
// The order is not guaranteed to be consistent.
//
// Returns:
//   - []string: List of registered method names
func (mr *MethodRegistry) ListMethods() []string {
	mr.mu.RLock()
	defer mr.mu.RUnlock()

	methods := make([]string, 0, len(mr.handlers))
	for method := range mr.handlers {
		methods = append(methods, method)
	}
	return methods
}

// MethodCount returns the number of registered methods.
//
// Returns:
//   - int: Number of registered methods
func (mr *MethodRegistry) MethodCount() int {
	mr.mu.RLock()
	defer mr.mu.RUnlock()

	return len(mr.handlers)
}

// Dispatch invokes the handler for the given method with the provided parameters.
// This is the main entry point for executing RPC methods.
//
// Parameters:
//   - ctx: Context for cancellation and deadlines
//   - method: The method name to invoke
//   - params: The method parameters as json.RawMessage
//
// Returns:
//   - result: The method result (nil if error occurred)
//   - error: An error if method not found or handler failed
//
// Error handling:
//   - Returns RPCError with ErrCodeMethodNotFound if method not registered
//   - Returns handler's error if invocation fails (should be *RPCError)
//   - Wraps non-RPCError errors as ErrCodeInternalError
func (mr *MethodRegistry) Dispatch(ctx context.Context, method string, params json.RawMessage) (interface{}, error) {
	// Look up handler (read lock only)
	mr.mu.RLock()
	handler, exists := mr.handlers[method]
	mr.mu.RUnlock()

	// Check if method exists
	if !exists {
		log.WithFields(map[string]interface{}{
			"at":     "MethodRegistry.Dispatch",
			"method": method,
			"reason": "method_not_found",
		}).Warn("attempted to call unregistered method")

		return nil, &RPCError{
			Code:    ErrCodeMethodNotFound,
			Message: fmt.Sprintf("method %q not found", method),
		}
	}

	// Invoke the handler
	log.WithFields(map[string]interface{}{
		"at":     "MethodRegistry.Dispatch",
		"method": method,
	}).Debug("dispatching RPC method")

	result, err := handler.Handle(ctx, params)
	if err != nil {
		// If error is already an RPCError, return it as-is
		if rpcErr, ok := err.(*RPCError); ok {
			return nil, rpcErr
		}

		// Wrap non-RPC errors as internal errors
		log.WithFields(map[string]interface{}{
			"at":     "MethodRegistry.Dispatch",
			"method": method,
			"error":  err.Error(),
		}).Error("method handler returned error")

		return nil, &RPCError{
			Code:    ErrCodeInternalError,
			Message: "internal error",
			Data:    err.Error(),
		}
	}

	return result, nil
}

// HandleRequest is a convenience method that processes a complete JSON-RPC request.
// It parses the request, dispatches to the appropriate handler, and returns a response.
//
// Parameters:
//   - ctx: Context for cancellation and deadlines
//   - requestData: Raw JSON-RPC request bytes
//
// Returns:
//   - *Response: The JSON-RPC response (always non-nil)
//
// This method never returns an error; all errors are encoded in the Response object
// following JSON-RPC 2.0 specification. Parse errors, invalid requests, and method
// errors are all returned as proper JSON-RPC error responses.
//
// Note: Notifications (requests without ID) are handled but no response is returned.
func (mr *MethodRegistry) HandleRequest(ctx context.Context, requestData []byte) *Response {
	// Parse the request
	req, err := ParseRequest(requestData)
	if err != nil {
		// Parse error - use null ID since we couldn't parse the request
		if rpcErr, ok := err.(*RPCError); ok {
			return NewErrorResponse(nil, rpcErr)
		}
		// Shouldn't happen since ParseRequest returns *RPCError, but handle it anyway
		return NewErrorResponse(nil, NewRPCError(ErrCodeParseError, err.Error()))
	}

	return mr.HandleParsedRequest(ctx, req)
}

// HandleParsedRequest processes an already-parsed JSON-RPC request and returns a response.
// This avoids double-parsing when the caller has already parsed the request (e.g., for authentication).
func (mr *MethodRegistry) HandleParsedRequest(ctx context.Context, req *Request) *Response {
	// Check if this is a notification (no response needed)
	if req.IsNotification() {
		log.WithFields(map[string]interface{}{
			"at":     "MethodRegistry.HandleParsedRequest",
			"method": req.Method,
		}).Debug("received notification (no response will be sent)")

		// Still dispatch the method, but don't return a response
		_, _ = mr.Dispatch(ctx, req.Method, req.Params)
		return nil
	}

	// Dispatch to handler
	result, err := mr.Dispatch(ctx, req.Method, req.Params)
	if err != nil {
		// Method error
		if rpcErr, ok := err.(*RPCError); ok {
			return NewErrorResponse(req.ID, rpcErr)
		}
		// Shouldn't happen since Dispatch returns *RPCError, but handle it anyway
		return NewErrorResponse(req.ID, NewRPCError(ErrCodeInternalError, err.Error()))
	}

	// Success
	return NewSuccessResponse(req.ID, result)
}
