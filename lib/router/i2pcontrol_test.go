package router

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/go-i2p/lib/i2pcontrol"
)

// TestI2PControlStartStop tests that I2PControl server can be started and stopped
func TestI2PControlStartStop(t *testing.T) {
	// Create minimal router configuration with I2PControl enabled
	cfg := &config.RouterConfig{
		I2PControl: &config.I2PControlConfig{
			Enabled:  true,
			Address:  "127.0.0.1:17650",
			Password: "test-password",
			UseHTTPS: false,
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

	// Test that server is responding
	resp := doRPCRequest(t, cfg.I2PControl.Address, "Authenticate", map[string]interface{}{
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
	_, err = http.Get(fmt.Sprintf("http://%s/jsonrpc", cfg.I2PControl.Address))
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
			Address:  "127.0.0.1:17651",
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

// TestRouterAccessInterface tests that Router implements RouterAccess interface
func TestRouterAccessInterface(t *testing.T) {
	cfg := &config.RouterConfig{}
	r := &Router{
		cfg: cfg,
	}

	// Verify Router implements RouterAccess
	var _ i2pcontrol.RouterAccess = r

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
	httpReq, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	httpResp, err := client.Do(httpReq)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	defer httpResp.Body.Close()

	respBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

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
