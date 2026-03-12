package i2pcontrol

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// requireRPCError asserts that err is a non-nil *RPCError with the expected code.
func requireRPCError(t *testing.T, err error, expectedCode int) {
	t.Helper()
	require.Error(t, err, "expected RPC error, got nil")
	rpcErr, ok := err.(*RPCError)
	require.True(t, ok, "error is not *RPCError: %T", err)
	assert.Equal(t, expectedCode, rpcErr.Code)
}

// invokeHandler calls handler.Handle and returns the result as a map.
func invokeHandler(t *testing.T, handler RPCHandler, paramsJSON string) map[string]interface{} {
	t.Helper()
	result, err := handler.Handle(context.Background(), json.RawMessage(paramsJSON))
	require.NoError(t, err)
	resultMap, ok := result.(map[string]interface{})
	require.True(t, ok, "result type = %T, want map[string]interface{}", result)
	return resultMap
}

// newStatsHandler creates a stats provider and returns it for building handler-specific instances.
func newStatsHandler(running bool, version string) RouterStatsProvider {
	return NewRouterStatsProvider(&mockRouterAccess{running: running}, version)
}

// Test Echo Handler

func TestEchoHandler_String(t *testing.T) {
	handler := NewEchoHandler()
	params := json.RawMessage(`{"Echo": "test message"}`)

	result, err := handler.Handle(context.Background(), params)
	require.NoError(t, err)

	resultMap, ok := result.(map[string]interface{})
	require.True(t, ok, "result is not map[string]interface{}: %T", result)

	assert.Equal(t, "test message", resultMap["Result"])
}

func TestEchoHandler_Number(t *testing.T) {
	handler := NewEchoHandler()
	params := json.RawMessage(`{"Echo": 12345}`)

	result, err := handler.Handle(context.Background(), params)
	require.NoError(t, err)

	resultMap := result.(map[string]interface{})
	assert.Equal(t, float64(12345), resultMap["Result"])
}

func TestEchoHandler_Object(t *testing.T) {
	handler := NewEchoHandler()
	params := json.RawMessage(`{"Echo": {"nested": "value"}}`)

	result, err := handler.Handle(context.Background(), params)
	require.NoError(t, err)

	resultMap := result.(map[string]interface{})
	resultVal, ok := resultMap["Result"].(map[string]interface{})
	require.True(t, ok, "Result is not map: %T", resultMap["Result"])

	assert.Equal(t, "value", resultVal["nested"])
}

func TestEchoHandler_InvalidJSON(t *testing.T) {
	handler := NewEchoHandler()
	params := json.RawMessage(`{invalid json}`)

	_, err := handler.Handle(context.Background(), params)
	if err == nil {
		t.Fatal("Handle() expected error for invalid JSON, got nil")
	}

	requireRPCError(t, err, ErrCodeInvalidParams)
}

// Test GetRate Handler

func TestGetRateHandler_AllFields(t *testing.T) {
	handler := NewGetRateHandler(newStatsHandler(true, "0.1.0"))
	resultMap := invokeHandler(t, handler, `{
		"i2p.router.net.bw.inbound.15s": null,
		"i2p.router.net.bw.outbound.15s": null
	}`)

	assert.Contains(t, resultMap, "i2p.router.net.bw.inbound.15s")
	assert.Contains(t, resultMap, "i2p.router.net.bw.outbound.15s")

	// Should return actual bandwidth from mock (1024 bytes/sec from GetBandwidthRates)
	assert.Equal(t, 0.0, resultMap["i2p.router.net.bw.inbound.15s"])
	assert.Equal(t, 1024.0, resultMap["i2p.router.net.bw.outbound.15s"])
}

func TestGetRateHandler_SingleField(t *testing.T) {
	handler := NewGetRateHandler(newStatsHandler(true, "0.1.0"))
	resultMap := invokeHandler(t, handler, `{"i2p.router.net.bw.inbound.15s": null}`)

	assert.Contains(t, resultMap, "i2p.router.net.bw.inbound.15s")
	assert.NotContains(t, resultMap, "i2p.router.net.bw.outbound.15s")
}

func TestGetRateHandler_NoFields(t *testing.T) {
	handler := NewGetRateHandler(newStatsHandler(true, "0.1.0"))
	resultMap := invokeHandler(t, handler, `{}`)

	// Should return all fields when none specified
	assert.Equal(t, 2, len(resultMap))
}

func TestGetRateHandler_InvalidJSON(t *testing.T) {
	handler := NewGetRateHandler(newStatsHandler(true, "0.1.0"))

	_, err := handler.Handle(context.Background(), json.RawMessage(`{invalid}`))
	if err == nil {
		t.Fatal("Handle() expected error for invalid JSON, got nil")
	}

	requireRPCError(t, err, ErrCodeInvalidParams)
}

// Test RouterInfo Handler

func TestRouterInfoHandler_AllFields(t *testing.T) {
	handler := NewRouterInfoHandler(newStatsHandler(true, "0.1.0-test"))
	resultMap := invokeHandler(t, handler, `{
		"i2p.router.uptime": null,
		"i2p.router.version": null,
		"i2p.router.net.status": null
	}`)

	// Check uptime exists and is >= 0
	uptime, ok := resultMap["i2p.router.uptime"].(int64)
	require.True(t, ok, "uptime not int64: %T", resultMap["i2p.router.uptime"])
	assert.GreaterOrEqual(t, uptime, int64(0))

	assert.Equal(t, "0.1.0-test", resultMap["i2p.router.version"])
	assert.Equal(t, 0, resultMap["i2p.router.net.status"])
}

func TestRouterInfoHandler_DefaultFields(t *testing.T) {
	handler := NewRouterInfoHandler(newStatsHandler(true, "0.1.0"))
	resultMap := invokeHandler(t, handler, `{}`)

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
	handler := NewRouterInfoHandler(newStatsHandler(false, "0.1.0"))
	resultMap := invokeHandler(t, handler, `{"i2p.router.net.status": null}`)

	// Status should be 5 (Error) when not running
	if resultMap["i2p.router.net.status"] != 5 {
		t.Errorf("status = %v, want 5 (Error)", resultMap["i2p.router.net.status"])
	}
}

func TestRouterInfoHandler_InvalidJSON(t *testing.T) {
	handler := NewRouterInfoHandler(newStatsHandler(true, "0.1.0"))

	_, err := handler.Handle(context.Background(), json.RawMessage(`{bad json}`))
	if err == nil {
		t.Fatal("Handle() expected error for invalid JSON, got nil")
	}
}

func TestRouterInfoHandler_StatusField(t *testing.T) {
	t.Run("status_when_running", func(t *testing.T) {
		handler := NewRouterInfoHandler(newStatsHandler(true, "0.1.0"))
		resultMap := invokeHandler(t, handler, `{"i2p.router.status": null}`)

		if resultMap["i2p.router.status"] != "OK" {
			t.Errorf("status = %v, want OK", resultMap["i2p.router.status"])
		}
	})

	t.Run("status_when_not_running", func(t *testing.T) {
		handler := NewRouterInfoHandler(newStatsHandler(false, "0.1.0"))
		resultMap := invokeHandler(t, handler, `{"i2p.router.status": null}`)

		if resultMap["i2p.router.status"] != "ERROR" {
			t.Errorf("status = %v, want ERROR", resultMap["i2p.router.status"])
		}
	})
}

func TestRouterInfoHandler_BandwidthFields(t *testing.T) {
	handler := NewRouterInfoHandler(newStatsHandler(true, "0.1.0"))
	resultMap := invokeHandler(t, handler, `{
		"i2p.router.net.bw.inbound.1s": null,
		"i2p.router.net.bw.inbound.15s": null,
		"i2p.router.net.bw.outbound.1s": null,
		"i2p.router.net.bw.outbound.15s": null
	}`)

	// Check all bandwidth fields are present
	for _, field := range []string{
		"i2p.router.net.bw.inbound.1s",
		"i2p.router.net.bw.inbound.15s",
		"i2p.router.net.bw.outbound.1s",
		"i2p.router.net.bw.outbound.15s",
	} {
		if _, ok := resultMap[field]; !ok {
			t.Errorf("missing %s", field)
		}
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
	reseedCalled   bool
}

func (m *mockRouterControl) Stop() {
	m.shutdownCalled = true
}

func (m *mockRouterControl) Reseed() error {
	m.reseedCalled = true
	return nil
}

func TestRouterManagerHandler_Operations(t *testing.T) {
	operations := []struct {
		name      string
		operation string
	}{
		{"Shutdown", "Shutdown"},
		{"Restart", "Restart"},
		{"Reseed", "Reseed"},
	}

	for _, op := range operations {
		t.Run(op.name, func(t *testing.T) {
			mockControl := &mockRouterControl{}
			handler := NewRouterManagerHandler(mockControl)
			resultMap := invokeHandler(t, handler, `{"`+op.operation+`": null}`)

			if _, ok := resultMap[op.operation]; !ok {
				t.Errorf("result should contain %s key", op.operation)
			}
		})
	}
}

func TestRouterManagerHandler_NoOperations(t *testing.T) {
	mockControl := &mockRouterControl{}
	handler := NewRouterManagerHandler(mockControl)

	_, err := handler.Handle(context.Background(), json.RawMessage(`{}`))
	if err == nil {
		t.Fatal("Handle() expected error for no operations, got nil")
	}

	requireRPCError(t, err, ErrCodeInvalidParams)
}

func TestRouterManagerHandler_InvalidJSON(t *testing.T) {
	mockControl := &mockRouterControl{}
	handler := NewRouterManagerHandler(mockControl)

	_, err := handler.Handle(context.Background(), json.RawMessage(`{invalid}`))
	if err == nil {
		t.Fatal("Handle() expected error for invalid JSON, got nil")
	}
}

// Test NetworkSetting Handler

func TestNetworkSettingHandler_AllSettings(t *testing.T) {
	stats := &mockServerStatsProvider{
		network: NetworkConfig{
			NTCP2Port:         12345,
			NTCP2Address:      "127.0.0.1:12345",
			NTCP2Hostname:     "127.0.0.1",
			BandwidthLimitIn:  1024,
			BandwidthLimitOut: 2048,
		},
	}
	handler := NewNetworkSettingHandler(stats)

	params := json.RawMessage(`{
		"i2p.router.net.ntcp.port": null,
		"i2p.router.net.ntcp.hostname": null,
		"i2p.router.bandwidth.in": null,
		"i2p.router.bandwidth.out": null
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

	// Hostname should return mock value
	if resultMap["i2p.router.net.ntcp.hostname"] != "127.0.0.1" {
		t.Errorf("hostname = %v, want 127.0.0.1", resultMap["i2p.router.net.ntcp.hostname"])
	}

	// Bandwidth in should return mock value
	if resultMap["i2p.router.bandwidth.in"] != 1024 {
		t.Errorf("bandwidth.in = %v, want 1024", resultMap["i2p.router.bandwidth.in"])
	}

	// Bandwidth out should return mock value
	if resultMap["i2p.router.bandwidth.out"] != 2048 {
		t.Errorf("bandwidth.out = %v, want 2048", resultMap["i2p.router.bandwidth.out"])
	}
}

func TestNetworkSettingHandler_DefaultSettings(t *testing.T) {
	stats := &mockServerStatsProvider{
		network: NetworkConfig{
			NTCP2Port:         9999,
			NTCP2Address:      "0.0.0.0:9999",
			NTCP2Hostname:     "0.0.0.0",
			BandwidthLimitIn:  512,
			BandwidthLimitOut: 1024,
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

	// Verify hostname value
	if resultMap["i2p.router.net.ntcp.hostname"] != "0.0.0.0" {
		t.Errorf("hostname = %v, want 0.0.0.0", resultMap["i2p.router.net.ntcp.hostname"])
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

	requireRPCError(t, err, ErrCodeNotImpl)
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

func TestNetworkSettingHandler_HostnameAndBandwidth(t *testing.T) {
	tests := []struct {
		name             string
		config           NetworkConfig
		wantHostname     string
		wantBandwidthIn  int
		wantBandwidthOut int
	}{
		{
			name: "IPv4 with bandwidth limits",
			config: NetworkConfig{
				NTCP2Port:         8080,
				NTCP2Address:      "192.168.1.1:8080",
				NTCP2Hostname:     "192.168.1.1",
				BandwidthLimitIn:  500,
				BandwidthLimitOut: 1000,
			},
			wantHostname:     "192.168.1.1",
			wantBandwidthIn:  500,
			wantBandwidthOut: 1000,
		},
		{
			name: "IPv6 with unlimited bandwidth",
			config: NetworkConfig{
				NTCP2Port:         9090,
				NTCP2Address:      "[::1]:9090",
				NTCP2Hostname:     "::1",
				BandwidthLimitIn:  0,
				BandwidthLimitOut: 0,
			},
			wantHostname:     "::1",
			wantBandwidthIn:  0,
			wantBandwidthOut: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stats := &mockServerStatsProvider{
				network: tt.config,
			}
			handler := NewNetworkSettingHandler(stats)

			params := json.RawMessage(`{
				"i2p.router.net.ntcp.hostname": null,
				"i2p.router.bandwidth.in": null,
				"i2p.router.bandwidth.out": null
			}`)

			result, err := handler.Handle(context.Background(), params)
			if err != nil {
				t.Fatalf("Handle() error = %v", err)
			}

			resultMap := result.(map[string]interface{})

			if resultMap["i2p.router.net.ntcp.hostname"] != tt.wantHostname {
				t.Errorf("hostname = %v, want %v", resultMap["i2p.router.net.ntcp.hostname"], tt.wantHostname)
			}

			if resultMap["i2p.router.bandwidth.in"] != tt.wantBandwidthIn {
				t.Errorf("bandwidth.in = %v, want %v", resultMap["i2p.router.bandwidth.in"], tt.wantBandwidthIn)
			}

			if resultMap["i2p.router.bandwidth.out"] != tt.wantBandwidthOut {
				t.Errorf("bandwidth.out = %v, want %v", resultMap["i2p.router.bandwidth.out"], tt.wantBandwidthOut)
			}
		})
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
	handler := NewRouterInfoHandler(newStatsHandler(true, "0.1.0-test"))
	resultMap := invokeHandler(t, handler, `{
		"i2p.router.netdb.activepeers": null,
		"i2p.router.netdb.fastpeers": null,
		"i2p.router.netdb.highcapacitypeers": null
	}`)

	// Verify all requested fields are present and non-negative integers
	for _, field := range []string{
		"i2p.router.netdb.activepeers",
		"i2p.router.netdb.fastpeers",
		"i2p.router.netdb.highcapacitypeers",
	} {
		val, ok := resultMap[field].(int)
		if !ok {
			t.Errorf("%s not int: %T", field, resultMap[field])
		} else if val < 0 {
			t.Errorf("%s = %d, want >= 0", field, val)
		}
	}
}

// TestRouterInfoHandler_IsReseedingField tests that isreseeding field is exposed
func TestRouterInfoHandler_IsReseedingField(t *testing.T) {
	handler := NewRouterInfoHandler(newStatsHandler(true, "0.1.0"))
	resultMap := invokeHandler(t, handler, `{"i2p.router.netdb.isreseeding": null}`)

	// Verify isreseeding field exists and is boolean
	isReseeding, exists := resultMap["i2p.router.netdb.isreseeding"]
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

// Test I2PControl Handler

// mockAuthManager provides a test implementation of password management
type mockAuthManager struct {
	password      string
	changeCount   int
	revokedTokens int
}

func (m *mockAuthManager) ChangePassword(newPassword string) int {
	m.password = newPassword
	m.changeCount++
	m.revokedTokens = 5 // Simulate 5 tokens being revoked
	return m.revokedTokens
}

func TestI2PControlHandler_PasswordChange(t *testing.T) {
	authMgr := &mockAuthManager{password: "oldpass"}
	cfg := &config.I2PControlConfig{Password: "oldpass"}
	handler := NewI2PControlHandler(authMgr, cfg)
	params := json.RawMessage(`{"i2pcontrol.password": "newpass123"}`)

	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("Handle() error = %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("result is not map[string]interface{}: %T", result)
	}

	// Check password was changed in auth manager
	if authMgr.password != "newpass123" {
		t.Errorf("authManager password = %v, want newpass123", authMgr.password)
	}

	// Check password was persisted to config struct
	if cfg.Password != "newpass123" {
		t.Errorf("config.Password = %v, want newpass123", cfg.Password)
	}

	// Check SettingsSaved flag
	if settingsSaved, ok := resultMap["SettingsSaved"].(bool); !ok || !settingsSaved {
		t.Errorf("SettingsSaved = %v, want true", resultMap["SettingsSaved"])
	}

	// Check password field is null in response
	if resultMap["i2pcontrol.password"] != nil {
		t.Errorf("i2pcontrol.password = %v, want nil", resultMap["i2pcontrol.password"])
	}
}

func TestI2PControlHandler_PasswordChange_NilConfig(t *testing.T) {
	authMgr := &mockAuthManager{password: "oldpass"}
	// Passing nil config should not panic — password change still works in auth manager
	handler := NewI2PControlHandler(authMgr, nil)
	params := json.RawMessage(`{"i2pcontrol.password": "newpass123"}`)

	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("Handle() error = %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("result is not map[string]interface{}: %T", result)
	}

	if authMgr.password != "newpass123" {
		t.Errorf("authManager password = %v, want newpass123", authMgr.password)
	}

	if settingsSaved, ok := resultMap["SettingsSaved"].(bool); !ok || !settingsSaved {
		t.Errorf("SettingsSaved = %v, want true", resultMap["SettingsSaved"])
	}
}

func TestI2PControlHandler_InvalidPasswordInputs(t *testing.T) {
	tests := []struct {
		name   string
		params string
	}{
		{"EmptyPassword", `{"i2pcontrol.password": ""}`},
		{"NumericPassword", `{"i2pcontrol.password": 12345}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authMgr := &mockAuthManager{password: "oldpass"}
			cfg := &config.I2PControlConfig{Password: "oldpass"}
			handler := NewI2PControlHandler(authMgr, cfg)
			params := json.RawMessage(tt.params)

			_, err := handler.Handle(context.Background(), params)
			if err == nil {
				t.Fatalf("expected error for %s, got nil", tt.name)
			}

			requireRPCError(t, err, ErrCodeInvalidParams)

			if authMgr.password != "oldpass" {
				t.Errorf("password changed to %v, should remain oldpass", authMgr.password)
			}
			if cfg.Password != "oldpass" {
				t.Errorf("config.Password changed to %v, should remain oldpass", cfg.Password)
			}
		})
	}
}

func TestI2PControlHandler_NotImplementedOperations(t *testing.T) {
	tests := []struct {
		name   string
		params string
		code   int
	}{
		{"PortChange", `{"i2pcontrol.port": 7657}`, ErrCodeNotImpl},
		{"AddressChange", `{"i2pcontrol.address": "127.0.0.1"}`, ErrCodeNotImpl},
		{"NoSettings", `{}`, ErrCodeInvalidParams},
		{"InvalidJSON", `{"invalid json`, ErrCodeInvalidParams},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authMgr := &mockAuthManager{}
			handler := NewI2PControlHandler(authMgr, &config.I2PControlConfig{})
			_, err := handler.Handle(context.Background(), json.RawMessage(tt.params))
			if err == nil {
				t.Fatalf("expected error for %s, got nil", tt.name)
			}
			requireRPCError(t, err, tt.code)
		})
	}
}

func TestI2PControlHandler_MultiplePasswordChanges(t *testing.T) {
	authMgr := &mockAuthManager{password: "pass1"}
	cfg := &config.I2PControlConfig{Password: "pass1"}
	handler := NewI2PControlHandler(authMgr, cfg)

	// First change
	params1 := json.RawMessage(`{"i2pcontrol.password": "pass2"}`)
	_, err := handler.Handle(context.Background(), params1)
	if err != nil {
		t.Fatalf("first Handle() error = %v", err)
	}

	if authMgr.password != "pass2" {
		t.Errorf("after first change, password = %v, want pass2", authMgr.password)
	}
	if cfg.Password != "pass2" {
		t.Errorf("after first change, config.Password = %v, want pass2", cfg.Password)
	}

	// Second change
	params2 := json.RawMessage(`{"i2pcontrol.password": "pass3"}`)
	_, err = handler.Handle(context.Background(), params2)
	if err != nil {
		t.Fatalf("second Handle() error = %v", err)
	}

	if authMgr.password != "pass3" {
		t.Errorf("after second change, password = %v, want pass3", authMgr.password)
	}
	if cfg.Password != "pass3" {
		t.Errorf("after second change, config.Password = %v, want pass3", cfg.Password)
	}

	if authMgr.changeCount != 2 {
		t.Errorf("changeCount = %v, want 2", authMgr.changeCount)
	}
}

func BenchmarkI2PControlHandler(b *testing.B) {
	authMgr := &mockAuthManager{}
	handler := NewI2PControlHandler(authMgr, &config.I2PControlConfig{})
	params := json.RawMessage(`{"i2pcontrol.password": "newpass"}`)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = handler.Handle(ctx, params)
	}
}
