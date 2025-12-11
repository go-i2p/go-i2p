package i2pcontrol

import (
	"context"
	"encoding/json"
	"testing"
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

func TestRouterInfoHandler_StatusField(t *testing.T) {
	t.Run("status_when_running", func(t *testing.T) {
		mockStats := &mockRouterAccess{running: true}
		statsProvider := NewRouterStatsProvider(mockStats, "0.1.0")

		handler := NewRouterInfoHandler(statsProvider)
		params := json.RawMessage(`{"i2p.router.status": null}`)

		result, err := handler.Handle(context.Background(), params)
		if err != nil {
			t.Fatalf("Handle() error = %v", err)
		}

		resultMap := result.(map[string]interface{})

		// Status should be "OK" when running
		if resultMap["i2p.router.status"] != "OK" {
			t.Errorf("status = %v, want OK", resultMap["i2p.router.status"])
		}
	})

	t.Run("status_when_not_running", func(t *testing.T) {
		mockStats := &mockRouterAccess{running: false}
		statsProvider := NewRouterStatsProvider(mockStats, "0.1.0")

		handler := NewRouterInfoHandler(statsProvider)
		params := json.RawMessage(`{"i2p.router.status": null}`)

		result, err := handler.Handle(context.Background(), params)
		if err != nil {
			t.Fatalf("Handle() error = %v", err)
		}

		resultMap := result.(map[string]interface{})

		// Status should be "ERROR" when not running
		if resultMap["i2p.router.status"] != "ERROR" {
			t.Errorf("status = %v, want ERROR", resultMap["i2p.router.status"])
		}
	})
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
	stats := &mockServerStatsProvider{
		network: NetworkConfig{
			NTCP2Port:    12345,
			NTCP2Address: "127.0.0.1:12345",
		},
	}
	handler := NewNetworkSettingHandler(stats)

	params := json.RawMessage(`{
		"i2p.router.net.ntcp.port": null,
		"i2p.router.net.ntcp.hostname": null
	}`)

	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("Handle() error = %v", err)
	}

	resultMap := result.(map[string]interface{})

	// Port should return mock value
	if resultMap["i2p.router.net.ntcp.port"] != 12345 {
		t.Errorf("port = %v, want 12345", resultMap["i2p.router.net.ntcp.port"])
	}

	// Hostname should be empty string (not yet implemented)
	if resultMap["i2p.router.net.ntcp.hostname"] != "" {
		t.Errorf("hostname = %v, want empty string", resultMap["i2p.router.net.ntcp.hostname"])
	}
}

func TestNetworkSettingHandler_DefaultSettings(t *testing.T) {
	stats := &mockServerStatsProvider{
		network: NetworkConfig{
			NTCP2Port:    9999,
			NTCP2Address: "0.0.0.0:9999",
		},
	}
	handler := NewNetworkSettingHandler(stats)

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

	// Verify port value
	if resultMap["i2p.router.net.ntcp.port"] != 9999 {
		t.Errorf("port = %v, want 9999", resultMap["i2p.router.net.ntcp.port"])
	}
}

func TestNetworkSettingHandler_UnknownSetting(t *testing.T) {
	stats := &mockServerStatsProvider{}
	handler := NewNetworkSettingHandler(stats)

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
	stats := &mockServerStatsProvider{}
	handler := NewNetworkSettingHandler(stats)

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
	stats := &mockServerStatsProvider{}
	handler := NewNetworkSettingHandler(stats)

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

// TestRouterInfoHandler_PeerClassificationFields tests that peer classification fields are exposed
func TestRouterInfoHandler_PeerClassificationFields(t *testing.T) {
	mockStats := &mockRouterAccess{running: true}
	statsProvider := NewRouterStatsProvider(mockStats, "0.1.0-test")

	handler := NewRouterInfoHandler(statsProvider)

	// Request the new peer classification fields
	params := json.RawMessage(`{
		"i2p.router.netdb.activepeers": null,
		"i2p.router.netdb.fastpeers": null,
		"i2p.router.netdb.highcapacitypeers": null
	}`)

	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("Handle() error = %v", err)
	}

	resultMap := result.(map[string]interface{})

	// Verify all requested fields are present
	if _, ok := resultMap["i2p.router.netdb.activepeers"]; !ok {
		t.Error("missing field: i2p.router.netdb.activepeers")
	}
	if _, ok := resultMap["i2p.router.netdb.fastpeers"]; !ok {
		t.Error("missing field: i2p.router.netdb.fastpeers")
	}
	if _, ok := resultMap["i2p.router.netdb.highcapacitypeers"]; !ok {
		t.Error("missing field: i2p.router.netdb.highcapacitypeers")
	}

	// Verify fields are numeric (should be 0 for mock)
	activePeers, ok := resultMap["i2p.router.netdb.activepeers"].(int)
	if !ok {
		t.Errorf("activepeers not int: %T", resultMap["i2p.router.netdb.activepeers"])
	}
	if activePeers < 0 {
		t.Errorf("activepeers = %d, want >= 0", activePeers)
	}

	fastPeers, ok := resultMap["i2p.router.netdb.fastpeers"].(int)
	if !ok {
		t.Errorf("fastpeers not int: %T", resultMap["i2p.router.netdb.fastpeers"])
	}
	if fastPeers < 0 {
		t.Errorf("fastpeers = %d, want >= 0", fastPeers)
	}

	highCapPeers, ok := resultMap["i2p.router.netdb.highcapacitypeers"].(int)
	if !ok {
		t.Errorf("highcapacitypeers not int: %T", resultMap["i2p.router.netdb.highcapacitypeers"])
	}
	if highCapPeers < 0 {
		t.Errorf("highcapacitypeers = %d, want >= 0", highCapPeers)
	}
}

// TestRouterInfoHandler_IsReseedingField tests that isreseeding field is exposed
func TestRouterInfoHandler_IsReseedingField(t *testing.T) {
	mockStats := &mockRouterAccess{running: true}
	statsProvider := NewRouterStatsProvider(mockStats, "0.1.0")
	handler := NewRouterInfoHandler(statsProvider)

	// Request the isreseeding field
	params := json.RawMessage(`{"i2p.router.netdb.isreseeding": null}`)
	ctx := context.Background()

	result, err := handler.Handle(ctx, params)
	if err != nil {
		t.Fatalf("Handle() error = %v", err)
	}

	// Result should be a map
	response, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("Handle() result type = %T, want map[string]interface{}", result)
	}

	// Verify isreseeding field exists and is boolean
	isReseeding, exists := response["i2p.router.netdb.isreseeding"]
	if !exists {
		t.Error("i2p.router.netdb.isreseeding field not found in response")
	}

	// Verify it's a boolean
	_, isBool := isReseeding.(bool)
	if !isBool {
		t.Errorf("i2p.router.netdb.isreseeding = %v (%T), want bool", isReseeding, isReseeding)
	}

	// Verify it's false (mock always returns false)
	if isReseeding != false {
		t.Errorf("i2p.router.netdb.isreseeding = %v, want false", isReseeding)
	}
}

func BenchmarkEchoHandler(b *testing.B) {
	handler := NewEchoHandler()
	params := json.RawMessage(`{"Echo": "test"}`)
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
	stats := &mockServerStatsProvider{
		network: NetworkConfig{
			NTCP2Port:    12345,
			NTCP2Address: "127.0.0.1:12345",
		},
	}
	handler := NewNetworkSettingHandler(stats)
	params := json.RawMessage(`{"i2p.router.net.ntcp.port": null}`)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = handler.Handle(ctx, params)
	}
}
