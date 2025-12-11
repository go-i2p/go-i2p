package i2pcontrol

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/go-i2p/go-i2p/lib/config"
)

// Test Echo Handler

func TestEchoHandler_String(t *testing.T) {
	handler := NewEchoHandler()
	params := json.RawMessage(`{"Echo": "test message"}`)

	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("Handle() error = %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("result is not map[string]interface{}: %T", result)
	}

	if resultMap["Result"] != "test message" {
		t.Errorf("Result = %v, want %v", resultMap["Result"], "test message")
	}
}

func TestEchoHandler_Number(t *testing.T) {
	handler := NewEchoHandler()
	params := json.RawMessage(`{"Echo": 12345}`)

	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("Handle() error = %v", err)
	}

	resultMap := result.(map[string]interface{})
	// JSON numbers are decoded as float64
	if resultMap["Result"] != float64(12345) {
		t.Errorf("Result = %v, want %v", resultMap["Result"], 12345)
	}
}

func TestEchoHandler_Object(t *testing.T) {
	handler := NewEchoHandler()
	params := json.RawMessage(`{"Echo": {"nested": "value"}}`)

	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("Handle() error = %v", err)
	}

	resultMap := result.(map[string]interface{})
	resultVal, ok := resultMap["Result"].(map[string]interface{})
	if !ok {
		t.Fatalf("Result is not map: %T", resultMap["Result"])
	}

	if resultVal["nested"] != "value" {
		t.Errorf("nested = %v, want value", resultVal["nested"])
	}
}

func TestEchoHandler_InvalidJSON(t *testing.T) {
	handler := NewEchoHandler()
	params := json.RawMessage(`{invalid json}`)

	_, err := handler.Handle(context.Background(), params)
	if err == nil {
		t.Fatal("Handle() expected error for invalid JSON, got nil")
	}

	rpcErr, ok := err.(*RPCError)
	if !ok {
		t.Fatalf("error is not *RPCError: %T", err)
	}

	if rpcErr.Code != ErrCodeInvalidParams {
		t.Errorf("error code = %d, want %d", rpcErr.Code, ErrCodeInvalidParams)
	}
}

// Test GetRate Handler

func TestGetRateHandler_AllFields(t *testing.T) {
	mockStats := &mockRouterAccess{
		running: true,
	}
	statsProvider := NewRouterStatsProvider(mockStats, "0.1.0")

	handler := NewGetRateHandler(statsProvider)
	params := json.RawMessage(`{
		"i2p.router.net.bw.inbound.15s": null,
		"i2p.router.net.bw.outbound.15s": null
	}`)

	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("Handle() error = %v", err)
	}

	resultMap := result.(map[string]interface{})

	if _, ok := resultMap["i2p.router.net.bw.inbound.15s"]; !ok {
		t.Error("missing i2p.router.net.bw.inbound.15s")
	}
	if _, ok := resultMap["i2p.router.net.bw.outbound.15s"]; !ok {
		t.Error("missing i2p.router.net.bw.outbound.15s")
	}

	// Should return actual bandwidth from mock (1024 bytes/sec from GetBandwidthRates)
	if resultMap["i2p.router.net.bw.inbound.15s"] != 0.0 {
		t.Errorf("inbound = %v, want 0.0", resultMap["i2p.router.net.bw.inbound.15s"])
	}
	if resultMap["i2p.router.net.bw.outbound.15s"] != 1024.0 {
		t.Errorf("outbound = %v, want 1024.0", resultMap["i2p.router.net.bw.outbound.15s"])
	}
}

func TestGetRateHandler_SingleField(t *testing.T) {
	mockStats := &mockRouterAccess{running: true}
	statsProvider := NewRouterStatsProvider(mockStats, "0.1.0")

	handler := NewGetRateHandler(statsProvider)
	params := json.RawMessage(`{"i2p.router.net.bw.inbound.15s": null}`)

	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("Handle() error = %v", err)
	}

	resultMap := result.(map[string]interface{})

	if _, ok := resultMap["i2p.router.net.bw.inbound.15s"]; !ok {
		t.Error("missing requested field")
	}
	if _, ok := resultMap["i2p.router.net.bw.outbound.15s"]; ok {
		t.Error("should not include unrequested field")
	}
}

func TestGetRateHandler_NoFields(t *testing.T) {
	mockStats := &mockRouterAccess{running: true}
	statsProvider := NewRouterStatsProvider(mockStats, "0.1.0")

	handler := NewGetRateHandler(statsProvider)
	params := json.RawMessage(`{}`)

	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("Handle() error = %v", err)
	}

	resultMap := result.(map[string]interface{})

	// Should return all fields when none specified
	if len(resultMap) != 2 {
		t.Errorf("result has %d fields, want 2", len(resultMap))
	}
}

func TestGetRateHandler_InvalidJSON(t *testing.T) {
	mockStats := &mockRouterAccess{running: true}
	statsProvider := NewRouterStatsProvider(mockStats, "0.1.0")

	handler := NewGetRateHandler(statsProvider)
	params := json.RawMessage(`{invalid}`)

	_, err := handler.Handle(context.Background(), params)
	if err == nil {
		t.Fatal("Handle() expected error for invalid JSON, got nil")
	}

	rpcErr := err.(*RPCError)
	if rpcErr.Code != ErrCodeInvalidParams {
		t.Errorf("error code = %d, want %d", rpcErr.Code, ErrCodeInvalidParams)
	}
}

// Test RouterInfo Handler

func TestRouterInfoHandler_AllFields(t *testing.T) {
	mockStats := &mockRouterAccess{running: true}
	statsProvider := NewRouterStatsProvider(mockStats, "0.1.0-test")

	handler := NewRouterInfoHandler(statsProvider)
	params := json.RawMessage(`{
		"i2p.router.uptime": null,
		"i2p.router.version": null,
		"i2p.router.net.status": null
	}`)

	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("Handle() error = %v", err)
	}

	resultMap := result.(map[string]interface{})

	// Check uptime exists and is >= 0
	uptime, ok := resultMap["i2p.router.uptime"].(int64)
	if !ok {
		t.Errorf("uptime not int64: %T", resultMap["i2p.router.uptime"])
	}
	if uptime < 0 {
		t.Errorf("uptime = %d, want >= 0", uptime)
	}

	// Check version
	if resultMap["i2p.router.version"] != "0.1.0-test" {
		t.Errorf("version = %v, want 0.1.0-test", resultMap["i2p.router.version"])
	}

	// Check status (0 = OK for running router)
	if resultMap["i2p.router.net.status"] != 0 {
		t.Errorf("status = %v, want 0", resultMap["i2p.router.net.status"])
	}
}

func TestRouterInfoHandler_DefaultFields(t *testing.T) {
	mockStats := &mockRouterAccess{running: true}
	statsProvider := NewRouterStatsProvider(mockStats, "0.1.0")

	handler := NewRouterInfoHandler(statsProvider)
	params := json.RawMessage(`{}`)

	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("Handle() error = %v", err)
	}

	resultMap := result.(map[string]interface{})

	// Should include default fields
	expectedFields := []string{
		"i2p.router.uptime",
		"i2p.router.version",
		"i2p.router.net.tunnels.participating",
		"i2p.router.netdb.knownpeers",
		"i2p.router.net.status",
	}

	for _, field := range expectedFields {
		if _, ok := resultMap[field]; !ok {
			t.Errorf("missing default field: %s", field)
		}
	}
}

func TestRouterInfoHandler_NotRunning(t *testing.T) {
	mockStats := &mockRouterAccess{running: false}
	statsProvider := NewRouterStatsProvider(mockStats, "0.1.0")

	handler := NewRouterInfoHandler(statsProvider)
	params := json.RawMessage(`{"i2p.router.net.status": null}`)

	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("Handle() error = %v", err)
	}

	resultMap := result.(map[string]interface{})

	// Status should be 5 (Error) when not running
	if resultMap["i2p.router.net.status"] != 5 {
		t.Errorf("status = %v, want 5 (Error)", resultMap["i2p.router.net.status"])
	}
}

func TestRouterInfoHandler_InvalidJSON(t *testing.T) {
	mockStats := &mockRouterAccess{running: true}
	statsProvider := NewRouterStatsProvider(mockStats, "0.1.0")

	handler := NewRouterInfoHandler(statsProvider)
	params := json.RawMessage(`{bad json}`)

	_, err := handler.Handle(context.Background(), params)
	if err == nil {
		t.Fatal("Handle() expected error for invalid JSON, got nil")
	}
}

func TestRouterInfoHandler_BandwidthFields(t *testing.T) {
	mockStats := &mockRouterAccess{running: true}
	statsProvider := NewRouterStatsProvider(mockStats, "0.1.0")

	handler := NewRouterInfoHandler(statsProvider)
	params := json.RawMessage(`{
		"i2p.router.net.bw.inbound.1s": null,
		"i2p.router.net.bw.inbound.15s": null,
		"i2p.router.net.bw.outbound.1s": null,
		"i2p.router.net.bw.outbound.15s": null
	}`)

	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("Handle() error = %v", err)
	}

	resultMap := result.(map[string]interface{})

	// Check all bandwidth fields are present
	if _, ok := resultMap["i2p.router.net.bw.inbound.1s"]; !ok {
		t.Error("missing i2p.router.net.bw.inbound.1s")
	}
	if _, ok := resultMap["i2p.router.net.bw.inbound.15s"]; !ok {
		t.Error("missing i2p.router.net.bw.inbound.15s")
	}
	if _, ok := resultMap["i2p.router.net.bw.outbound.1s"]; !ok {
		t.Error("missing i2p.router.net.bw.outbound.1s")
	}
	if _, ok := resultMap["i2p.router.net.bw.outbound.15s"]; !ok {
		t.Error("missing i2p.router.net.bw.outbound.15s")
	}

	// Check that bandwidth values are from mock (1024 bytes/sec)
	// Inbound should be 0 (not tracked separately yet)
	if resultMap["i2p.router.net.bw.inbound.1s"] != 0.0 {
		t.Errorf("inbound.1s = %v, want 0.0", resultMap["i2p.router.net.bw.inbound.1s"])
	}
	// Outbound should be 1024.0 from mock
	if resultMap["i2p.router.net.bw.outbound.1s"] != 1024.0 {
		t.Errorf("outbound.1s = %v, want 1024.0", resultMap["i2p.router.net.bw.outbound.1s"])
	}
}

// Test RouterManager Handler

type mockRouterControl struct {
	shutdownCalled bool
}

func (m *mockRouterControl) Stop() {
	m.shutdownCalled = true
}

func TestRouterManagerHandler_Shutdown(t *testing.T) {
	mockControl := &mockRouterControl{}
	handler := NewRouterManagerHandler(mockControl)

	params := json.RawMessage(`{"Shutdown": null}`)

	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("Handle() error = %v", err)
	}

	resultMap := result.(map[string]interface{})

	if resultMap["Shutdown"] != nil {
		t.Errorf("Shutdown result = %v, want nil", resultMap["Shutdown"])
	}

	// Give the goroutine time to execute
	// Note: In production this would shut down router
	// In test we just verify the call would happen
}

func TestRouterManagerHandler_Restart(t *testing.T) {
	mockControl := &mockRouterControl{}
	handler := NewRouterManagerHandler(mockControl)

	params := json.RawMessage(`{"Restart": null}`)

	_, err := handler.Handle(context.Background(), params)
	if err == nil {
		t.Fatal("Handle() expected error for Restart, got nil")
	}

	rpcErr := err.(*RPCError)
	if rpcErr.Code != ErrCodeNotImpl {
		t.Errorf("error code = %d, want %d", rpcErr.Code, ErrCodeNotImpl)
	}
}

func TestRouterManagerHandler_Reseed(t *testing.T) {
	mockControl := &mockRouterControl{}
	handler := NewRouterManagerHandler(mockControl)

	params := json.RawMessage(`{"Reseed": null}`)

	_, err := handler.Handle(context.Background(), params)
	if err == nil {
		t.Fatal("Handle() expected error for Reseed, got nil")
	}

	rpcErr := err.(*RPCError)
	if rpcErr.Code != ErrCodeNotImpl {
		t.Errorf("error code = %d, want %d", rpcErr.Code, ErrCodeNotImpl)
	}
}

func TestRouterManagerHandler_NoOperations(t *testing.T) {
	mockControl := &mockRouterControl{}
	handler := NewRouterManagerHandler(mockControl)

	params := json.RawMessage(`{}`)

	_, err := handler.Handle(context.Background(), params)
	if err == nil {
		t.Fatal("Handle() expected error for no operations, got nil")
	}

	rpcErr := err.(*RPCError)
	if rpcErr.Code != ErrCodeInvalidParams {
		t.Errorf("error code = %d, want %d", rpcErr.Code, ErrCodeInvalidParams)
	}
}

func TestRouterManagerHandler_InvalidJSON(t *testing.T) {
	mockControl := &mockRouterControl{}
	handler := NewRouterManagerHandler(mockControl)

	params := json.RawMessage(`{invalid}`)

	_, err := handler.Handle(context.Background(), params)
	if err == nil {
		t.Fatal("Handle() expected error for invalid JSON, got nil")
	}
}

// Test NetworkSetting Handler

func TestNetworkSettingHandler_AllSettings(t *testing.T) {
	cfg := &config.RouterConfig{}
	handler := NewNetworkSettingHandler(cfg)

	params := json.RawMessage(`{
		"i2p.router.net.ntcp.port": null,
		"i2p.router.net.ntcp.hostname": null
	}`)

	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("Handle() error = %v", err)
	}

	resultMap := result.(map[string]interface{})

	// Port should be 0 (not exposed in config yet)
	if resultMap["i2p.router.net.ntcp.port"] != 0 {
		t.Errorf("port = %v, want 0", resultMap["i2p.router.net.ntcp.port"])
	}

	// Hostname should be empty string
	if resultMap["i2p.router.net.ntcp.hostname"] != "" {
		t.Errorf("hostname = %v, want empty string", resultMap["i2p.router.net.ntcp.hostname"])
	}
}

func TestNetworkSettingHandler_DefaultSettings(t *testing.T) {
	cfg := &config.RouterConfig{}
	handler := NewNetworkSettingHandler(cfg)

	params := json.RawMessage(`{}`)

	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("Handle() error = %v", err)
	}

	resultMap := result.(map[string]interface{})

	// Should return default fields
	expectedFields := []string{
		"i2p.router.net.ntcp.port",
		"i2p.router.net.ntcp.hostname",
	}

	for _, field := range expectedFields {
		if _, ok := resultMap[field]; !ok {
			t.Errorf("missing default field: %s", field)
		}
	}
}

func TestNetworkSettingHandler_UnknownSetting(t *testing.T) {
	cfg := &config.RouterConfig{}
	handler := NewNetworkSettingHandler(cfg)

	params := json.RawMessage(`{"unknown.setting": null}`)

	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("Handle() error = %v", err)
	}

	resultMap := result.(map[string]interface{})

	// Unknown setting should return nil
	if resultMap["unknown.setting"] != nil {
		t.Errorf("unknown setting = %v, want nil", resultMap["unknown.setting"])
	}
}

func TestNetworkSettingHandler_WriteOperation(t *testing.T) {
	cfg := &config.RouterConfig{}
	handler := NewNetworkSettingHandler(cfg)

	// Try to write a value (non-null)
	params := json.RawMessage(`{"i2p.router.net.ntcp.port": 12345}`)

	_, err := handler.Handle(context.Background(), params)
	if err == nil {
		t.Fatal("Handle() expected error for write operation, got nil")
	}

	rpcErr := err.(*RPCError)
	if rpcErr.Code != ErrCodeNotImpl {
		t.Errorf("error code = %d, want %d", rpcErr.Code, ErrCodeNotImpl)
	}
}

func TestNetworkSettingHandler_InvalidJSON(t *testing.T) {
	cfg := &config.RouterConfig{}
	handler := NewNetworkSettingHandler(cfg)

	params := json.RawMessage(`{invalid}`)

	_, err := handler.Handle(context.Background(), params)
	if err == nil {
		t.Fatal("Handle() expected error for invalid JSON, got nil")
	}
}

// Test getStatusCode helper

func TestGetStatusCode(t *testing.T) {
	tests := []struct {
		name    string
		running bool
		want    int
	}{
		{"running", true, 0},
		{"not running", false, 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getStatusCode(tt.running)
			if got != tt.want {
				t.Errorf("getStatusCode(%v) = %d, want %d", tt.running, got, tt.want)
			}
		})
	}
}

// Benchmark tests

func BenchmarkEchoHandler(b *testing.B) {
	handler := NewEchoHandler()
	params := json.RawMessage(`{"Echo": "benchmark test"}`)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = handler.Handle(ctx, params)
	}
}

func BenchmarkGetRateHandler(b *testing.B) {
	mockStats := &mockRouterAccess{running: true}
	statsProvider := NewRouterStatsProvider(mockStats, "0.1.0")
	handler := NewGetRateHandler(statsProvider)
	params := json.RawMessage(`{"i2p.router.net.bw.inbound.15s": null}`)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = handler.Handle(ctx, params)
	}
}

func BenchmarkRouterInfoHandler(b *testing.B) {
	mockStats := &mockRouterAccess{running: true}
	statsProvider := NewRouterStatsProvider(mockStats, "0.1.0")
	handler := NewRouterInfoHandler(statsProvider)
	params := json.RawMessage(`{"i2p.router.uptime": null}`)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = handler.Handle(ctx, params)
	}
}

func BenchmarkNetworkSettingHandler(b *testing.B) {
	cfg := &config.RouterConfig{}
	handler := NewNetworkSettingHandler(cfg)
	params := json.RawMessage(`{"i2p.router.net.ntcp.port": null}`)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = handler.Handle(ctx, params)
	}
}
