package i2pcontrol

import (
	"context"
	"encoding/json"
	"sync"
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
	assertHandlerError(t, NewEchoHandler(), `{invalid json}`, ErrCodeInvalidParams)
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
	assertHandlerError(t, NewGetRateHandler(newStatsHandler(true, "0.1.0")), `{invalid}`, ErrCodeInvalidParams)
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
		assert.Contains(t, resultMap, field, "missing default field")
	}
}

func TestRouterInfoHandler_NotRunning(t *testing.T) {
	handler := NewRouterInfoHandler(newStatsHandler(false, "0.1.0"))
	resultMap := invokeHandler(t, handler, `{"i2p.router.net.status": null}`)

	// Status should be 5 (Error) when not running
	assert.Equal(t, 5, resultMap["i2p.router.net.status"])
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
			assert.Equal(t, "OK", resultMap["i2p.router.status"])
		}
	})

	t.Run("status_when_not_running", func(t *testing.T) {
		handler := NewRouterInfoHandler(newStatsHandler(false, "0.1.0"))
		resultMap := invokeHandler(t, handler, `{"i2p.router.status": null}`)

		assert.Equal(t, "ERROR", resultMap["i2p.router.status"])
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
		assert.Contains(t, resultMap, field)
	}

	assert.Equal(t, 0.0, resultMap["i2p.router.net.bw.inbound.1s"])
	assert.Equal(t, 1024.0, resultMap["i2p.router.net.bw.outbound.1s"])
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
			handler := NewRouterManagerHandler(context.Background(), &sync.WaitGroup{}, mockControl)
			resultMap := invokeHandler(t, handler, `{"`+op.operation+`": null}`)

			assert.Contains(t, resultMap, op.operation)
		})
	}
}

func TestRouterManagerHandler_NoOperations(t *testing.T) {
	assertHandlerError(t, NewRouterManagerHandler(context.Background(), &sync.WaitGroup{}, &mockRouterControl{}), `{}`, ErrCodeInvalidParams)
}

func TestRouterManagerHandler_InvalidJSON(t *testing.T) {
	mockControl := &mockRouterControl{}
	handler := NewRouterManagerHandler(context.Background(), &sync.WaitGroup{}, mockControl)

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
	require.NoError(t, err)

	resultMap := result.(map[string]interface{})

	assert.Equal(t, 12345, resultMap["i2p.router.net.ntcp.port"])
	assert.Equal(t, "127.0.0.1", resultMap["i2p.router.net.ntcp.hostname"])
	assert.Equal(t, 1024, resultMap["i2p.router.bandwidth.in"])
	assert.Equal(t, 2048, resultMap["i2p.router.bandwidth.out"])
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
	require.NoError(t, err)

	resultMap := result.(map[string]interface{})

	for _, field := range []string{
		"i2p.router.net.ntcp.port",
		"i2p.router.net.ntcp.hostname",
		"i2p.router.bandwidth.in",
		"i2p.router.bandwidth.out",
	} {
		assert.Contains(t, resultMap, field)
	}

	assert.Equal(t, 9999, resultMap["i2p.router.net.ntcp.port"])
	assert.Equal(t, "0.0.0.0", resultMap["i2p.router.net.ntcp.hostname"])
}

func TestNetworkSettingHandler_UnknownSetting(t *testing.T) {
	stats := &mockServerStatsProvider{}
	handler := NewNetworkSettingHandler(stats)

	params := json.RawMessage(`{"unknown.setting": null}`)

	result, err := handler.Handle(context.Background(), params)
	require.NoError(t, err)

	resultMap := result.(map[string]interface{})
	assert.Nil(t, resultMap["unknown.setting"])
}

func TestNetworkSettingHandler_WriteOperation(t *testing.T) {
	// Write a value (non-null) — should succeed and persist via Viper
	stats := &mockServerStatsProvider{}
	handler := NewNetworkSettingHandler(stats)

	params := json.RawMessage(`{"i2p.router.net.ntcp.port": 12345}`)
	result, err := handler.Handle(context.Background(), params)
	require.NoError(t, err)

	resultMap := result.(map[string]interface{})
	// Port is normalized to int by applySettingChange so it round-trips
	// through viper as an integer rather than a float64.
	assert.Equal(t, 12345, resultMap["i2p.router.net.ntcp.port"])
	assert.Equal(t, true, resultMap["SettingsSaved"])
	assert.Equal(t, true, resultMap["RestartNeeded"])
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
			require.NoError(t, err)

			resultMap := result.(map[string]interface{})

			assert.Equal(t, tt.wantHostname, resultMap["i2p.router.net.ntcp.hostname"])
			assert.Equal(t, tt.wantBandwidthIn, resultMap["i2p.router.bandwidth.in"])
			assert.Equal(t, tt.wantBandwidthOut, resultMap["i2p.router.bandwidth.out"])
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
			assert.Equal(t, tt.want, got)
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
		require.True(t, ok, "%s not int: %T", field, resultMap[field])
		assert.GreaterOrEqual(t, val, 0, "%s should be >= 0", field)
	}
}

// TestRouterInfoHandler_IsReseedingField tests that isreseeding field is exposed
func TestRouterInfoHandler_IsReseedingField(t *testing.T) {
	handler := NewRouterInfoHandler(newStatsHandler(true, "0.1.0"))
	resultMap := invokeHandler(t, handler, `{"i2p.router.netdb.isreseeding": null}`)

	// Verify isreseeding field exists and is boolean
	isReseeding, exists := resultMap["i2p.router.netdb.isreseeding"]
	assert.True(t, exists, "i2p.router.netdb.isreseeding field not found")

	_, isBool := isReseeding.(bool)
	assert.True(t, isBool, "i2p.router.netdb.isreseeding = %v (%T), want bool", isReseeding, isReseeding)
	assert.Equal(t, false, isReseeding)
}

func BenchmarkEchoHandler(b *testing.B) {
	benchmarkRPCHandler(b, NewEchoHandler(), json.RawMessage(`{"Echo": "test"}`))
}

func BenchmarkGetRateHandler(b *testing.B) {
	mockStats := &mockRouterAccess{running: true}
	statsProvider := NewRouterStatsProvider(mockStats, "0.1.0")
	benchmarkRPCHandler(b, NewGetRateHandler(statsProvider), json.RawMessage(`{"i2p.router.net.bw.inbound.15s": null}`))
}

func BenchmarkRouterInfoHandler(b *testing.B) {
	mockStats := &mockRouterAccess{running: true}
	statsProvider := NewRouterStatsProvider(mockStats, "0.1.0")
	benchmarkRPCHandler(b, NewRouterInfoHandler(statsProvider), json.RawMessage(`{"i2p.router.uptime": null}`))
}

func BenchmarkNetworkSettingHandler(b *testing.B) {
	stats := &mockServerStatsProvider{
		network: NetworkConfig{
			NTCP2Port:    12345,
			NTCP2Address: "127.0.0.1:12345",
		},
	}
	benchmarkRPCHandler(b, NewNetworkSettingHandler(stats), json.RawMessage(`{"i2p.router.net.ntcp.port": null}`))
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

	resultMap := assertPasswordChangeSucceeds(t, handler, authMgr)
	assert.Equal(t, "newpass123", cfg.Password)
	assert.Nil(t, resultMap["i2pcontrol.password"])
}

func TestI2PControlHandler_PasswordChange_NilConfig(t *testing.T) {
	authMgr := &mockAuthManager{password: "oldpass"}
	// Passing nil config should not panic — password change still works in auth manager
	handler := NewI2PControlHandler(authMgr, nil)

	assertPasswordChangeSucceeds(t, handler, authMgr)
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

			assert.Equal(t, "oldpass", authMgr.password)
			assert.Equal(t, "oldpass", cfg.Password)
		})
	}
}

func TestI2PControlHandler_NotImplementedOperations(t *testing.T) {
	tests := []struct {
		name   string
		params string
		code   int
	}{
		{"NoSettings", `{}`, ErrCodeInvalidParams},
		{"InvalidJSON", `{"invalid json`, ErrCodeInvalidParams},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authMgr := &mockAuthManager{}
			handler := NewI2PControlHandler(authMgr, &config.I2PControlConfig{})
			assertHandlerError(t, handler, tt.params, tt.code)
		})
	}
}

func TestI2PControlHandler_PortAndAddressChange(t *testing.T) {
	authMgr := &mockAuthManager{}
	cfg := &config.I2PControlConfig{}
	handler := NewI2PControlHandler(authMgr, cfg)

	// Port change should succeed and flag restart needed
	params := json.RawMessage(`{"i2pcontrol.port": 7657}`)
	result, err := handler.Handle(context.Background(), params)
	require.NoError(t, err)

	resultMap := result.(map[string]interface{})
	assert.Equal(t, true, resultMap["SettingsSaved"])
	assert.Equal(t, true, resultMap["RestartNeeded"])

	// Address change should succeed and flag restart needed
	params = json.RawMessage(`{"i2pcontrol.address": "127.0.0.1"}`)
	result, err = handler.Handle(context.Background(), params)
	require.NoError(t, err)

	resultMap = result.(map[string]interface{})
	assert.Equal(t, true, resultMap["SettingsSaved"])
	assert.Equal(t, true, resultMap["RestartNeeded"])
}

func TestI2PControlHandler_MultiplePasswordChanges(t *testing.T) {
	authMgr := &mockAuthManager{password: "pass1"}
	cfg := &config.I2PControlConfig{Password: "pass1"}
	handler := NewI2PControlHandler(authMgr, cfg)

	// First change
	params1 := json.RawMessage(`{"i2pcontrol.password": "pass2"}`)
	_, err := handler.Handle(context.Background(), params1)
	require.NoError(t, err)

	assert.Equal(t, "pass2", authMgr.password)
	assert.Equal(t, "pass2", cfg.Password)

	// Second change
	params2 := json.RawMessage(`{"i2pcontrol.password": "pass3"}`)
	_, err = handler.Handle(context.Background(), params2)
	require.NoError(t, err)

	assert.Equal(t, "pass3", authMgr.password)
	assert.Equal(t, "pass3", cfg.Password)
	assert.Equal(t, 2, authMgr.changeCount)
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
