package i2pcontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newRegistryWithMethod creates a MethodRegistry with a single mockHandler
// registered under the given name. The handler returns result when invoked.
func newRegistryWithMethod(t *testing.T, name string, result interface{}) *MethodRegistry {
	t.Helper()
	registry := NewMethodRegistry()
	registry.Register(name, &mockHandler{result: result})
	return registry
}

// assertMethodState asserts that the given method has the expected registration
// state and that the registry has the expected total method count.
func assertMethodState(t *testing.T, registry *MethodRegistry, method string, wantRegistered bool, wantCount int) {
	t.Helper()
	if got := registry.IsRegistered(method); got != wantRegistered {
		t.Errorf("IsRegistered(%q) = %v, want %v", method, got, wantRegistered)
	}
	if got := registry.MethodCount(); got != wantCount {
		t.Errorf("MethodCount() = %d, want %d", got, wantCount)
	}
}

// assertHandlerError calls handler.Handle with the given JSON params and asserts
// that it returns an *RPCError with the expected error code.
func assertHandlerError(t *testing.T, handler RPCHandler, paramsJSON string, expectedCode int) {
	t.Helper()
	_, err := handler.Handle(context.Background(), json.RawMessage(paramsJSON))
	if err == nil {
		t.Fatal("Handle() expected error, got nil")
	}
	requireRPCError(t, err, expectedCode)
}

// postRPC sends a JSON-RPC request to tsURL and returns the decoded Response.
func postRPC(t *testing.T, tsURL string, method string, params map[string]interface{}) Response {
	t.Helper()
	reqBody, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  method,
		"params":  params,
	})
	resp, err := http.Post(tsURL, "application/json", bytes.NewReader(reqBody))
	require.NoError(t, err)
	defer resp.Body.Close()
	var rpcResp Response
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&rpcResp))
	return rpcResp
}

// assertPasswordChangeSucceeds invokes handler.Handle with a password-change
// payload and asserts common post-conditions: no error, authMgr updated,
// SettingsSaved=true. Returns the result map for callers to add extra checks.
func assertPasswordChangeSucceeds(t *testing.T, handler *I2PControlHandler, authMgr *mockAuthManager) map[string]interface{} {
	t.Helper()
	params := json.RawMessage(`{"i2pcontrol.password": "newpass123"}`)
	result, err := handler.Handle(context.Background(), params)
	require.NoError(t, err)

	resultMap, ok := result.(map[string]interface{})
	require.True(t, ok, "result is not map[string]interface{}: %T", result)

	assert.Equal(t, "newpass123", authMgr.password)

	settingsSaved, ok := resultMap["SettingsSaved"].(bool)
	assert.True(t, ok && settingsSaved, "SettingsSaved should be true")
	return resultMap
}
