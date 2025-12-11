package i2pcontrol

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/go-i2p/go-i2p/lib/config"
)

// mockStatsProvider implements RouterStatsProvider for testing
type mockServerStatsProvider struct {
	bandwidth BandwidthStats
	info      RouterInfoStats
	tunnels   TunnelStats
	netdb     NetDBStats
	running   bool
}

func (m *mockServerStatsProvider) GetBandwidthStats() BandwidthStats { return m.bandwidth }
func (m *mockServerStatsProvider) GetRouterInfo() RouterInfoStats    { return m.info }
func (m *mockServerStatsProvider) GetTunnelStats() TunnelStats       { return m.tunnels }
func (m *mockServerStatsProvider) GetNetDBStats() NetDBStats         { return m.netdb }
func (m *mockServerStatsProvider) IsRunning() bool                   { return m.running }
func (m *mockServerStatsProvider) GetRouterControl() interface{ Stop() } {
	// Return a simple mock that implements Stop()
	return mockStopControl{}
}

type mockStopControl struct{}

func (mockStopControl) Stop() {}

// testConfig creates a test I2PControl configuration
func testConfig(port int) *config.I2PControlConfig {
	return &config.I2PControlConfig{
		Enabled:  true,
		Address:  fmt.Sprintf("127.0.0.1:%d", port),
		Password: "testpassword123",
		UseHTTPS: false,
	}
}

// getFreePort finds an available TCP port for testing
func getFreePort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

// doRequest sends a JSON-RPC request and returns the raw response
func doRequest(t *testing.T, url, method string, params interface{}) *Response {
	t.Helper()

	// Build the request object
	reqData := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  method,
	}
	if params != nil {
		reqData["params"] = params
	}

	body, err := json.Marshal(reqData)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	httpReq, err := http.NewRequest("POST", url+"/jsonrpc", bytes.NewReader(body))
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

	var resp Response
	if err := json.Unmarshal(respBody, &resp); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	return &resp
}

// TestNewServer tests the NewServer constructor
func TestNewServer(t *testing.T) {
	stats := &mockServerStatsProvider{}
	port, err := getFreePort()
	if err != nil {
		t.Fatalf("Failed to get free port: %v", err)
	}
	cfg := testConfig(port)

	t.Run("valid_config", func(t *testing.T) {
		server, err := NewServer(cfg, stats)
		if err != nil {
			t.Fatalf("NewServer failed: %v", err)
		}
		if server == nil {
			t.Fatal("Expected server, got nil")
		}
		if server.config != cfg {
			t.Error("Config not set correctly")
		}
		if server.authManager == nil {
			t.Error("AuthManager not initialized")
		}
		if server.registry == nil {
			t.Error("MethodRegistry not initialized")
		}
	})

	t.Run("nil_config", func(t *testing.T) {
		_, err := NewServer(nil, stats)
		if err == nil {
			t.Fatal("Expected error for nil config")
		}
	})

	t.Run("nil_stats", func(t *testing.T) {
		_, err := NewServer(cfg, nil)
		if err == nil {
			t.Fatal("Expected error for nil stats")
		}
	})

	t.Run("empty_password", func(t *testing.T) {
		cfgNoPass := *cfg
		cfgNoPass.Password = ""
		_, err := NewServer(&cfgNoPass, stats)
		if err == nil {
			t.Fatal("Expected error for empty password")
		}
	})

	t.Run("handlers_registered", func(t *testing.T) {
		server, err := NewServer(cfg, stats)
		if err != nil {
			t.Fatalf("NewServer failed: %v", err)
		}

		// Verify expected handlers are registered
		expectedMethods := []string{"Echo", "GetRate", "RouterInfo"}
		for _, method := range expectedMethods {
			if !server.registry.IsRegistered(method) {
				t.Errorf("Handler not registered: %s", method)
			}
		}
	})
}

// TestServerLifecycle tests server start and stop
func TestServerLifecycle(t *testing.T) {
	stats := &mockServerStatsProvider{}
	port, err := getFreePort()
	if err != nil {
		t.Fatalf("Failed to get free port: %v", err)
	}
	cfg := testConfig(port)

	server, err := NewServer(cfg, stats)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	if err := server.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Verify server is listening
	url := fmt.Sprintf("http://%s", cfg.Address)
	resp := doRequest(t, url, "Authenticate", map[string]interface{}{
		"API":      1,
		"Password": cfg.Password,
	})

	if resp.Error != nil {
		t.Fatalf("Authenticate failed: %v", resp.Error.Message)
	}

	// Stop server
	server.Stop()

	// Verify server stopped
	time.Sleep(100 * time.Millisecond)
}

// TestAuthentication tests the authentication flow
func TestAuthentication(t *testing.T) {
	stats := &mockServerStatsProvider{}
	port, err := getFreePort()
	if err != nil {
		t.Fatalf("Failed to get free port: %v", err)
	}
	cfg := testConfig(port)

	server, err := NewServer(cfg, stats)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	if err := server.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer server.Stop()

	time.Sleep(100 * time.Millisecond)
	url := fmt.Sprintf("http://%s", cfg.Address)

	t.Run("valid_password", func(t *testing.T) {
		resp := doRequest(t, url, "Authenticate", map[string]interface{}{
			"API":      1,
			"Password": cfg.Password,
		})

		if resp.Error != nil {
			t.Fatalf("Authenticate failed: %v", resp.Error.Message)
		}

		result, ok := resp.Result.(map[string]interface{})
		if !ok {
			t.Fatal("Expected result to be a map")
		}

		token, ok := result["Token"].(string)
		if !ok || token == "" {
			t.Error("Expected Token in result")
		}
	})

	t.Run("invalid_password", func(t *testing.T) {
		resp := doRequest(t, url, "Authenticate", map[string]interface{}{
			"API":      1,
			"Password": "wrongpassword",
		})

		if resp.Error == nil {
			t.Fatal("Expected error for invalid password")
		}
		if resp.Error.Code != ErrCodeAuthFailed {
			t.Errorf("Expected ErrCodeAuthFailed, got %d", resp.Error.Code)
		}
	})
}

// TestEchoHandler tests the Echo RPC method via the server
func TestEchoHandler(t *testing.T) {
	stats := &mockServerStatsProvider{}
	port, err := getFreePort()
	if err != nil {
		t.Fatalf("Failed to get free port: %v", err)
	}
	cfg := testConfig(port)

	server, err := NewServer(cfg, stats)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	if err := server.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer server.Stop()

	time.Sleep(100 * time.Millisecond)
	url := fmt.Sprintf("http://%s", cfg.Address)

	// Authenticate first
	authResp := doRequest(t, url, "Authenticate", map[string]interface{}{
		"API":      1,
		"Password": cfg.Password,
	})

	if authResp.Error != nil {
		t.Fatalf("Authenticate failed: %v", authResp.Error.Message)
	}

	result := authResp.Result.(map[string]interface{})
	token := result["Token"].(string)

	t.Run("echo_valid", func(t *testing.T) {
		resp := doRequest(t, url, "Echo", map[string]interface{}{
			"Token": token,
			"Echo":  "test message",
		})

		if resp.Error != nil {
			t.Fatalf("Echo failed: %v", resp.Error.Message)
		}

		result, ok := resp.Result.(map[string]interface{})
		if !ok {
			t.Fatal("Expected result to be a map")
		}

		echo, ok := result["Result"].(string)
		if !ok || echo != "test message" {
			t.Errorf("Expected Result='test message', got %v", echo)
		}
	})

	t.Run("missing_token", func(t *testing.T) {
		resp := doRequest(t, url, "Echo", map[string]interface{}{
			"Echo": "test",
		})

		if resp.Error == nil {
			t.Fatal("Expected error for missing token")
		}
		if resp.Error.Code != ErrCodeInvalidParams {
			t.Errorf("Expected ErrCodeInvalidParams, got %d", resp.Error.Code)
		}
	})

	t.Run("invalid_token", func(t *testing.T) {
		resp := doRequest(t, url, "Echo", map[string]interface{}{
			"Token": "invalid_token",
			"Echo":  "test",
		})

		if resp.Error == nil {
			t.Fatal("Expected error for invalid token")
		}
		if resp.Error.Code != ErrCodeAuthRequired {
			t.Errorf("Expected ErrCodeAuthRequired, got %d", resp.Error.Code)
		}
	})
}

// TestHTTPErrors tests HTTP-level error conditions
func TestHTTPErrors(t *testing.T) {
	stats := &mockServerStatsProvider{}
	port, err := getFreePort()
	if err != nil {
		t.Fatalf("Failed to get free port: %v", err)
	}
	cfg := testConfig(port)

	server, err := NewServer(cfg, stats)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	if err := server.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer server.Stop()

	time.Sleep(100 * time.Millisecond)
	url := fmt.Sprintf("http://%s/jsonrpc", cfg.Address)
	client := &http.Client{Timeout: 5 * time.Second}

	t.Run("wrong_method", func(t *testing.T) {
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		var jsonResp Response
		json.Unmarshal(body, &jsonResp)

		if jsonResp.Error == nil {
			t.Fatal("Expected error for GET request")
		}
		if jsonResp.Error.Code != ErrCodeInvalidRequest {
			t.Errorf("Expected ErrCodeInvalidRequest, got %d", jsonResp.Error.Code)
		}
	})

	t.Run("wrong_content_type", func(t *testing.T) {
		req, _ := http.NewRequest("POST", url, bytes.NewReader([]byte("{}")))
		req.Header.Set("Content-Type", "text/plain")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		var jsonResp Response
		json.Unmarshal(body, &jsonResp)

		if jsonResp.Error == nil {
			t.Fatal("Expected error for wrong content type")
		}
	})

	t.Run("invalid_json", func(t *testing.T) {
		req, _ := http.NewRequest("POST", url, bytes.NewReader([]byte("not json")))
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		var jsonResp Response
		json.Unmarshal(body, &jsonResp)

		if jsonResp.Error == nil {
			t.Fatal("Expected error for invalid JSON")
		}
		if jsonResp.Error.Code != ErrCodeParseError {
			t.Errorf("Expected ErrCodeParseError, got %d", jsonResp.Error.Code)
		}
	})

	t.Run("options_request", func(t *testing.T) {
		req, _ := http.NewRequest("OPTIONS", url, nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200 for OPTIONS, got %d", resp.StatusCode)
		}

		// Verify CORS headers
		if origin := resp.Header.Get("Access-Control-Allow-Origin"); origin != "*" {
			t.Errorf("Expected CORS origin *, got %s", origin)
		}
	})
}

// TestMethodNotFound tests non-existent method calls
func TestMethodNotFound(t *testing.T) {
	stats := &mockServerStatsProvider{}
	port, err := getFreePort()
	if err != nil {
		t.Fatalf("Failed to get free port: %v", err)
	}
	cfg := testConfig(port)

	server, err := NewServer(cfg, stats)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	if err := server.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer server.Stop()

	time.Sleep(100 * time.Millisecond)
	url := fmt.Sprintf("http://%s", cfg.Address)

	// Authenticate first
	authResp := doRequest(t, url, "Authenticate", map[string]interface{}{
		"API":      1,
		"Password": cfg.Password,
	})

	result := authResp.Result.(map[string]interface{})
	token := result["Token"].(string)

	resp := doRequest(t, url, "NonExistentMethod", map[string]interface{}{
		"Token": token,
	})

	if resp.Error == nil {
		t.Fatal("Expected error for non-existent method")
	}
	if resp.Error.Code != ErrCodeMethodNotFound {
		t.Errorf("Expected ErrCodeMethodNotFound, got %d", resp.Error.Code)
	}
}
