package router

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/go-i2p/lib/i2pcontrol"
	"github.com/go-i2p/go-i2p/lib/testutil"
)

// TestI2PControlStartStop tests that I2PControl server can be started and stopped
func TestI2PControlStartStop(t *testing.T) {
	// Create minimal router configuration with I2PControl enabled on ephemeral port
	cfg := &config.RouterConfig{
		I2PControl: &config.I2PControlConfig{
			Enabled:         true,
			Address:         "127.0.0.1:0",
			Password:        "test-password",
			UseHTTPS:        false,
			TokenExpiration: 10 * time.Minute,
		},
	}

	// Create a minimal router (without full initialization)
	r := &Router{
		cfg: cfg,
	}

	// Set running state manually for this test
	r.running = true

	// Test starting I2PControl server
	err := r.startI2PControlServer()
	if err != nil {
		t.Fatalf("Failed to start I2PControl server: %v", err)
	}

	if r.i2pcontrolServer == nil {
		t.Fatal("Expected i2pcontrolServer to be set")
	}

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Get the actual bound address
	serverAddr := r.i2pcontrolServer.Addr().String()

	// Test that server is responding
	resp := doRPCRequest(t, serverAddr, "Authenticate", map[string]interface{}{
		"API":      1,
		"Password": cfg.I2PControl.Password,
	})

	if resp.Error != nil {
		t.Fatalf("Authenticate failed: %v", resp.Error)
	}

	// Test stopping I2PControl server
	r.stopI2PControlServer()

	// Wait for shutdown
	time.Sleep(100 * time.Millisecond)

	// Verify server is stopped
	_, err = http.Get(fmt.Sprintf("http://%s/jsonrpc", serverAddr))
	if err == nil {
		t.Error("Expected error connecting to stopped server")
	}
}

// TestI2PControlDisabledInConfig tests that I2PControl doesn't start when disabled
func TestI2PControlDisabledInConfig(t *testing.T) {
	// Create router configuration with I2PControl disabled
	cfg := &config.RouterConfig{
		I2PControl: &config.I2PControlConfig{
			Enabled:  false,
			Address:  "127.0.0.1:0",
			Password: "test",
		},
	}

	r := &Router{
		cfg: cfg,
	}

	// Attempt to start I2PControl server
	err := r.startI2PControlServer()
	if err != nil {
		t.Fatalf("startI2PControlServer should not error when disabled: %v", err)
	}

	if r.i2pcontrolServer != nil {
		t.Error("i2pcontrolServer should not be set when disabled")
	}
}

// TestI2PControlNilConfig tests behavior when I2PControl config is nil
func TestI2PControlNilConfig(t *testing.T) {
	cfg := &config.RouterConfig{
		I2PControl: nil,
	}

	r := &Router{
		cfg: cfg,
	}

	// Should not error, just skip starting
	err := r.startI2PControlServer()
	if err != nil {
		t.Fatalf("startI2PControlServer should not error with nil config: %v", err)
	}

	if r.i2pcontrolServer != nil {
		t.Error("i2pcontrolServer should not be set when config is nil")
	}
}

// TestI2PControlStartupFailure_OccupiedPort verifies startup fails when the
// configured control port is already bound.
func TestI2PControlStartupFailure_OccupiedPort(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to reserve test port: %v", err)
	}
	defer listener.Close()

	cfg := &config.RouterConfig{
		I2PControl: &config.I2PControlConfig{
			Enabled:         true,
			Address:         listener.Addr().String(),
			Password:        "test-password",
			UseHTTPS:        false,
			TokenExpiration: 10 * time.Minute,
		},
	}

	r := &Router{cfg: cfg, running: true}

	err = r.startI2PControlServer()
	if err == nil {
		t.Fatal("expected startup error when control port is occupied")
	}
	if !strings.Contains(err.Error(), "failed to create listener") {
		t.Fatalf("expected listener creation error, got: %v", err)
	}
	if r.i2pcontrolServer != nil {
		t.Fatal("i2pcontrolServer should remain nil on startup failure")
	}
}

// TestI2PControlStartupFailure_BadCertificate verifies startup fails before
// reporting success when HTTPS certificate files are invalid.
func TestI2PControlStartupFailure_BadCertificate(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &config.RouterConfig{
		I2PControl: &config.I2PControlConfig{
			Enabled:         true,
			Address:         "127.0.0.1:0",
			Password:        "test-password",
			UseHTTPS:        true,
			CertFile:        tmpDir + "/missing-cert.pem",
			KeyFile:         tmpDir + "/missing-key.pem",
			TokenExpiration: 10 * time.Minute,
		},
	}

	r := &Router{cfg: cfg, running: true}

	err := r.startI2PControlServer()
	if err == nil {
		t.Fatal("expected startup error with invalid HTTPS certificate files")
	}
	if !strings.Contains(err.Error(), "failed to load TLS certificate/key") {
		t.Fatalf("expected TLS load error, got: %v", err)
	}
	if r.i2pcontrolServer != nil {
		t.Fatal("i2pcontrolServer should remain nil on startup failure")
	}
}

// TestRouterAccessInterface tests that Router implements RouterAccess interface
func TestRouterAccessInterface(t *testing.T) {
	cfg := &config.RouterConfig{}
	r := &Router{
		cfg: cfg,
	}

	// Verify RealRouter wrapping Router implements RouterAccess
	var _ i2pcontrol.RouterAccess = i2pcontrol.RealRouter{Router: r}

	// Test GetConfig
	if r.GetConfig() != cfg {
		t.Error("GetConfig should return router config")
	}

	// Test GetNetDB (can be nil)
	_ = r.GetNetDB()

	// Test GetTunnelManager (can be nil)
	_ = r.GetTunnelManager()

	// Test IsRunning
	if r.IsRunning() {
		t.Error("Expected IsRunning to be false initially")
	}

	r.running = true
	if !r.IsRunning() {
		t.Error("Expected IsRunning to be true after setting running")
	}
}

// doRPCRequest sends a JSON-RPC request and returns the response
func doRPCRequest(t *testing.T, address, method string, params interface{}) *RPCResponse {
	t.Helper()

	reqData := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  method,
		"params":  params,
	}

	body, err := json.Marshal(reqData)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	url := fmt.Sprintf("http://%s/jsonrpc", address)
	respBody := testutil.PostJSON(t, url, body)

	var resp RPCResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	return &resp
}

// RPCResponse represents a JSON-RPC 2.0 response
type RPCResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Result  interface{} `json:"result,omitempty"`
	Error   *RPCError   `json:"error,omitempty"`
}

// RPCError represents a JSON-RPC 2.0 error
type RPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}
