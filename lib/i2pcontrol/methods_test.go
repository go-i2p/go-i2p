package i2pcontrol

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
)

// mockHandler is a simple handler for testing
type mockHandler struct {
	result interface{}
	err    error
}

func (h *mockHandler) Handle(ctx context.Context, params json.RawMessage) (interface{}, error) {
	return h.result, h.err
}

// TestNewMethodRegistry tests registry creation
func TestNewMethodRegistry(t *testing.T) {
	registry := NewMethodRegistry()

	if registry == nil {
		t.Fatal("NewMethodRegistry returned nil")
	}

	if registry.handlers == nil {
		t.Error("handlers map not initialized")
	}

	if registry.MethodCount() != 0 {
		t.Errorf("initial method count: got %d, want 0", registry.MethodCount())
	}
}

// TestRegister tests method registration
func TestRegister(t *testing.T) {
	registry := NewMethodRegistry()
	handler := &mockHandler{result: "test"}

	registry.Register("TestMethod", handler)

	if !registry.IsRegistered("TestMethod") {
		t.Error("Method should be registered")
	}

	if registry.MethodCount() != 1 {
		t.Errorf("method count: got %d, want 1", registry.MethodCount())
	}
}

// TestRegisterReplace tests replacing an existing handler
func TestRegisterReplace(t *testing.T) {
	registry := NewMethodRegistry()
	handler1 := &mockHandler{result: "first"}
	handler2 := &mockHandler{result: "second"}

	registry.Register("TestMethod", handler1)
	registry.Register("TestMethod", handler2)

	if registry.MethodCount() != 1 {
		t.Errorf("method count: got %d, want 1", registry.MethodCount())
	}

	// Verify the second handler replaced the first
	result, err := registry.Dispatch(context.Background(), "TestMethod", nil)
	if err != nil {
		t.Fatalf("Dispatch failed: %v", err)
	}

	if result != "second" {
		t.Errorf("result: got %v, want \"second\"", result)
	}
}

// TestUnregister tests method unregistration
func TestUnregister(t *testing.T) {
	registry := NewMethodRegistry()
	handler := &mockHandler{result: "test"}

	registry.Register("TestMethod", handler)
	registry.Unregister("TestMethod")

	if registry.IsRegistered("TestMethod") {
		t.Error("Method should not be registered after unregister")
	}

	if registry.MethodCount() != 0 {
		t.Errorf("method count: got %d, want 0", registry.MethodCount())
	}
}

// TestUnregisterNonexistent tests unregistering non-existent method
func TestUnregisterNonexistent(t *testing.T) {
	registry := NewMethodRegistry()

	// Should not panic
	registry.Unregister("NonexistentMethod")

	if registry.MethodCount() != 0 {
		t.Errorf("method count: got %d, want 0", registry.MethodCount())
	}
}

// TestIsRegistered tests registration checking
func TestIsRegistered(t *testing.T) {
	registry := NewMethodRegistry()
	handler := &mockHandler{result: "test"}

	if registry.IsRegistered("TestMethod") {
		t.Error("Method should not be registered initially")
	}

	registry.Register("TestMethod", handler)

	if !registry.IsRegistered("TestMethod") {
		t.Error("Method should be registered")
	}

	if registry.IsRegistered("OtherMethod") {
		t.Error("OtherMethod should not be registered")
	}
}

// TestListMethods tests listing registered methods
func TestListMethods(t *testing.T) {
	registry := NewMethodRegistry()

	methods := registry.ListMethods()
	if len(methods) != 0 {
		t.Errorf("initial methods: got %d, want 0", len(methods))
	}

	registry.Register("Method1", &mockHandler{})
	registry.Register("Method2", &mockHandler{})
	registry.Register("Method3", &mockHandler{})

	methods = registry.ListMethods()
	if len(methods) != 3 {
		t.Errorf("method count: got %d, want 3", len(methods))
	}

	// Verify all methods are in the list
	methodMap := make(map[string]bool)
	for _, m := range methods {
		methodMap[m] = true
	}

	expected := []string{"Method1", "Method2", "Method3"}
	for _, m := range expected {
		if !methodMap[m] {
			t.Errorf("Method %q not in list", m)
		}
	}
}

// TestDispatchSuccess tests successful method dispatch
func TestDispatchSuccess(t *testing.T) {
	registry := NewMethodRegistry()
	expectedResult := "test_result"
	handler := &mockHandler{result: expectedResult}

	registry.Register("TestMethod", handler)

	result, err := registry.Dispatch(context.Background(), "TestMethod", nil)
	if err != nil {
		t.Fatalf("Dispatch failed: %v", err)
	}

	if result != expectedResult {
		t.Errorf("result: got %v, want %v", result, expectedResult)
	}
}

// TestDispatchMethodNotFound tests dispatch with non-existent method
func TestDispatchMethodNotFound(t *testing.T) {
	registry := NewMethodRegistry()

	result, err := registry.Dispatch(context.Background(), "NonexistentMethod", nil)

	if err == nil {
		t.Fatal("Expected error for non-existent method")
	}

	rpcErr, ok := err.(*RPCError)
	if !ok {
		t.Fatalf("Expected *RPCError, got %T: %v", err, err)
	}

	if rpcErr.Code != ErrCodeMethodNotFound {
		t.Errorf("error code: got %d, want %d", rpcErr.Code, ErrCodeMethodNotFound)
	}

	if result != nil {
		t.Errorf("expected nil result, got %v", result)
	}
}

// TestDispatchHandlerError tests dispatch with handler returning error
func TestDispatchHandlerError(t *testing.T) {
	registry := NewMethodRegistry()
	expectedErr := &RPCError{
		Code:    ErrCodeInvalidParams,
		Message: "test error",
	}
	handler := &mockHandler{err: expectedErr}

	registry.Register("TestMethod", handler)

	result, err := registry.Dispatch(context.Background(), "TestMethod", nil)

	if err == nil {
		t.Fatal("Expected error from handler")
	}

	rpcErr, ok := err.(*RPCError)
	if !ok {
		t.Fatalf("Expected *RPCError, got %T: %v", err, err)
	}

	if rpcErr.Code != ErrCodeInvalidParams {
		t.Errorf("error code: got %d, want %d", rpcErr.Code, ErrCodeInvalidParams)
	}

	if result != nil {
		t.Errorf("expected nil result, got %v", result)
	}
}

// TestDispatchHandlerNonRPCError tests dispatch with handler returning non-RPC error
func TestDispatchHandlerNonRPCError(t *testing.T) {
	registry := NewMethodRegistry()
	handler := &mockHandler{err: errors.New("standard error")}

	registry.Register("TestMethod", handler)

	result, err := registry.Dispatch(context.Background(), "TestMethod", nil)

	if err == nil {
		t.Fatal("Expected error from handler")
	}

	rpcErr, ok := err.(*RPCError)
	if !ok {
		t.Fatalf("Expected *RPCError, got %T: %v", err, err)
	}

	// Non-RPC errors should be wrapped as internal errors
	if rpcErr.Code != ErrCodeInternalError {
		t.Errorf("error code: got %d, want %d", rpcErr.Code, ErrCodeInternalError)
	}

	if result != nil {
		t.Errorf("expected nil result, got %v", result)
	}
}

// TestRPCHandlerFunc tests function adapter
func TestRPCHandlerFunc(t *testing.T) {
	registry := NewMethodRegistry()
	called := false

	handler := RPCHandlerFunc(func(ctx context.Context, params json.RawMessage) (interface{}, error) {
		called = true
		return "success", nil
	})

	registry.Register("TestMethod", handler)

	result, err := registry.Dispatch(context.Background(), "TestMethod", nil)
	if err != nil {
		t.Fatalf("Dispatch failed: %v", err)
	}

	if !called {
		t.Error("Handler function was not called")
	}

	if result != "success" {
		t.Errorf("result: got %v, want \"success\"", result)
	}
}

// TestHandleRequestSuccess tests complete request handling
func TestHandleRequestSuccess(t *testing.T) {
	registry := NewMethodRegistry()
	handler := &mockHandler{result: map[string]string{"Echo": "test"}}
	registry.Register("Echo", handler)

	requestData := []byte(`{"jsonrpc":"2.0","id":1,"method":"Echo","params":{}}`)
	response := registry.HandleRequest(context.Background(), requestData)

	if response == nil {
		t.Fatal("Expected response, got nil")
	}

	if response.Error != nil {
		t.Errorf("Expected success response, got error: %v", response.Error)
	}

	if response.Result == nil {
		t.Error("Expected result in response")
	}

	if response.ID != float64(1) {
		t.Errorf("response ID: got %v, want 1", response.ID)
	}
}

// TestHandleRequestParseError tests handling invalid JSON
func TestHandleRequestParseError(t *testing.T) {
	registry := NewMethodRegistry()

	requestData := []byte(`invalid json`)
	response := registry.HandleRequest(context.Background(), requestData)

	if response == nil {
		t.Fatal("Expected response, got nil")
	}

	if response.Error == nil {
		t.Fatal("Expected error response")
	}

	if response.Error.Code != ErrCodeParseError {
		t.Errorf("error code: got %d, want %d", response.Error.Code, ErrCodeParseError)
	}

	if response.ID != nil {
		t.Errorf("Expected null ID for parse error, got %v", response.ID)
	}
}

// TestHandleRequestMethodNotFound tests handling unknown method
func TestHandleRequestMethodNotFound(t *testing.T) {
	registry := NewMethodRegistry()

	requestData := []byte(`{"jsonrpc":"2.0","id":1,"method":"UnknownMethod"}`)
	response := registry.HandleRequest(context.Background(), requestData)

	if response == nil {
		t.Fatal("Expected response, got nil")
	}

	if response.Error == nil {
		t.Fatal("Expected error response")
	}

	if response.Error.Code != ErrCodeMethodNotFound {
		t.Errorf("error code: got %d, want %d", response.Error.Code, ErrCodeMethodNotFound)
	}
}

// TestHandleRequestNotification tests handling notifications
func TestHandleRequestNotification(t *testing.T) {
	registry := NewMethodRegistry()
	called := false
	handler := RPCHandlerFunc(func(ctx context.Context, params json.RawMessage) (interface{}, error) {
		called = true
		return nil, nil
	})
	registry.Register("Notify", handler)

	// Notification has no ID field
	requestData := []byte(`{"jsonrpc":"2.0","method":"Notify"}`)
	response := registry.HandleRequest(context.Background(), requestData)

	// Notifications should not return a response
	if response != nil {
		t.Errorf("Expected nil response for notification, got %v", response)
	}

	// Handler should still be called
	if !called {
		t.Error("Handler was not called for notification")
	}
}

// TestConcurrentRegister tests concurrent registration
func TestConcurrentRegister(t *testing.T) {
	registry := NewMethodRegistry()
	var wg sync.WaitGroup
	numGoroutines := 50

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			handler := &mockHandler{result: n}
			registry.Register("Method"+string(rune(n)), handler)
		}(i)
	}

	wg.Wait()

	count := registry.MethodCount()
	if count != numGoroutines {
		t.Errorf("method count: got %d, want %d", count, numGoroutines)
	}
}

// TestConcurrentDispatch tests concurrent dispatch
func TestConcurrentDispatch(t *testing.T) {
	registry := NewMethodRegistry()
	handler := &mockHandler{result: "success"}
	registry.Register("TestMethod", handler)

	var wg sync.WaitGroup
	numGoroutines := 100
	errors := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := registry.Dispatch(context.Background(), "TestMethod", nil)
			if err != nil {
				errors <- err
			}
		}()
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Errorf("Dispatch error: %v", err)
	}
}

// TestConcurrentMethodOperations tests concurrent register/dispatch/unregister
func TestConcurrentMethodOperations(t *testing.T) {
	registry := NewMethodRegistry()
	var wg sync.WaitGroup

	// Concurrent registers
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			handler := &mockHandler{result: n}
			registry.Register("Method"+string(rune(n)), handler)
		}(i)
	}

	// Concurrent dispatches
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = registry.Dispatch(context.Background(), "Method0", nil)
		}()
	}

	// Concurrent checks
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			registry.IsRegistered("Method0")
			registry.ListMethods()
		}()
	}

	wg.Wait()

	// Should complete without panics or deadlocks
}

// TestContextCancellation tests that context cancellation is respected
func TestContextCancellation(t *testing.T) {
	registry := NewMethodRegistry()

	// Handler that checks context
	handler := RPCHandlerFunc(func(ctx context.Context, params json.RawMessage) (interface{}, error) {
		if ctx.Err() != nil {
			return nil, &RPCError{
				Code:    ErrCodeInternalError,
				Message: "context cancelled",
			}
		}
		return "success", nil
	})

	registry.Register("TestMethod", handler)

	// Create cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result, err := registry.Dispatch(ctx, "TestMethod", nil)

	// Handler should see cancelled context
	if err == nil {
		t.Error("Expected error with cancelled context")
	}

	if result != nil {
		t.Errorf("Expected nil result, got %v", result)
	}
}

// BenchmarkDispatch measures dispatch performance
func BenchmarkDispatch(b *testing.B) {
	registry := NewMethodRegistry()
	handler := &mockHandler{result: "test"}
	registry.Register("TestMethod", handler)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := registry.Dispatch(ctx, "TestMethod", nil)
		if err != nil {
			b.Fatalf("Dispatch failed: %v", err)
		}
	}
}

// BenchmarkHandleRequest measures full request handling performance
func BenchmarkHandleRequest(b *testing.B) {
	registry := NewMethodRegistry()
	handler := &mockHandler{result: map[string]string{"Echo": "test"}}
	registry.Register("Echo", handler)
	ctx := context.Background()
	requestData := []byte(`{"jsonrpc":"2.0","id":1,"method":"Echo","params":{}}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		response := registry.HandleRequest(ctx, requestData)
		if response.Error != nil {
			b.Fatalf("HandleRequest failed: %v", response.Error)
		}
	}
}
