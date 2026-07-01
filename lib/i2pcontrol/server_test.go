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
	"github.com/go-i2p/go-i2p/lib/testutil"
)

// mockStatsProvider implements RouterStatsProvider for testing
type mockServerStatsProvider struct {
	bandwidth BandwidthStats
	info      RouterInfoStats
	tunnels   TunnelStats
	netdb     NetDBStats
	network   NetworkConfig
	running   bool
}

func (m *mockServerStatsProvider) GetBandwidthStats() BandwidthStats { return m.bandwidth }
func (m *mockServerStatsProvider) GetRouterInfo() RouterInfoStats    { return m.info }
func (m *mockServerStatsProvider) GetTunnelStats() TunnelStats       { return m.tunnels }
func (m *mockServerStatsProvider) GetNetDBStats() NetDBStats         { return m.netdb }
func (m *mockServerStatsProvider) GetNetworkConfig() NetworkConfig   { return m.network }
func (m *mockServerStatsProvider) IsRunning() bool                   { return m.running }
func (m *mockServerStatsProvider) GetRateForPeriod(stat string, periodMs int64) float64 {
	return 0
}

func (m *mockServerStatsProvider) GetNetworkStatus() int {
	if !m.running {
		return 8
	}
	return 0
}

func (m *mockServerStatsProvider) GetRouterControl() interface {
	Stop()
	Reseed() error
} {
	// Return a simple mock that implements Stop() and Reseed()
	return mockStopControl{}
}

func (m *mockServerStatsProvider) GetLocalRouterIdentityHash() (string, error) {
	// Return a base64-encoded test hash
	return "dGVzdC1yb3V0ZXItaGFzaA==", nil
}

type mockStopControl struct{}

func (mockStopControl) Stop()         {}
func (mockStopControl) Reseed() error { return nil }

// testConfig creates a test I2PControl configuration
func testConfig(port int) *config.I2PControlConfig {
	return &config.I2PControlConfig{
		Enabled:         true,
		Address:         fmt.Sprintf("127.0.0.1:%d", port),
		Password:        "testpassword123",
		UseHTTPS:        false,
		TokenExpiration: 10 * time.Minute,
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

	respBody := testutil.PostJSON(t, url+"/jsonrpc", body)

	var resp Response
	if err := json.Unmarshal(respBody, &resp); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	return &resp
}

// startTestServer creates, starts and returns a running test server with its
// config and a cleanup function. Callers must defer the cleanup.
func startTestServer(t *testing.T) (*Server, *config.I2PControlConfig, string) {
	t.Helper()
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
	t.Cleanup(func() { server.Stop() })
	time.Sleep(100 * time.Millisecond)
	url := fmt.Sprintf("http://%s", cfg.Address)
	return server, cfg, url
}

// authenticateTestServer authenticates against a running test server and
// returns the auth token.
func authenticateTestServer(t *testing.T, url, password string) string {
	t.Helper()
	authResp := doRequest(t, url, "Authenticate", map[string]interface{}{
		"API":      1,
		"Password": password,
	})
	if authResp.Error != nil {
		t.Fatalf("Authenticate failed: %v", authResp.Error.Message)
	}
	result := authResp.Result.(map[string]interface{})
	return result["Token"].(string)
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
	_, cfg, url := startTestServer(t)

	// Verify server is listening
	resp := doRequest(t, url, "Authenticate", map[string]interface{}{
		"API":      1,
		"Password": cfg.Password,
	})

	if resp.Error != nil {
		t.Fatalf("Authenticate failed: %v", resp.Error.Message)
	}
}

// TestAuthentication tests the authentication flow
func TestAuthentication(t *testing.T) {
	_, cfg, url := startTestServer(t)

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
	_, cfg, url := startTestServer(t)
	token := authenticateTestServer(t, url, cfg.Password)

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

	t.Run("missing_token_rejected", func(t *testing.T) {
		resp := doRequest(t, url, "Echo", map[string]interface{}{
			"Echo": "test",
		})

		if resp.Error == nil {
			t.Fatal("Expected auth error when token is missing")
		}
		if resp.Error.Code != ErrCodeAuthRequired {
			t.Fatalf("Expected ErrCodeAuthRequired, got %d", resp.Error.Code)
		}
	})

	t.Run("invalid_token_rejected", func(t *testing.T) {
		resp := doRequest(t, url, "Echo", map[string]interface{}{
			"Token": "invalid_token",
			"Echo":  "test",
		})

		if resp.Error == nil {
			t.Fatal("Expected auth error when token is invalid")
		}
		if resp.Error.Code != ErrCodeTokenNotExist {
			t.Fatalf("Expected ErrCodeTokenNotExist, got %d", resp.Error.Code)
		}
	})
}

// TestHTTPErrors tests HTTP-level error conditions
func TestHTTPErrors(t *testing.T) {
	_, cfg, baseURL := startTestServer(t)
	url := baseURL + "/jsonrpc"
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

		// Verify CORS headers - origin should match the server's own address (not "*")
		// to prevent CSRF attacks per the implementation's security design
		expectedOrigin := fmt.Sprintf("http://%s", cfg.Address)
		if origin := resp.Header.Get("Access-Control-Allow-Origin"); origin != expectedOrigin {
			t.Errorf("Expected CORS origin %s, got %s", expectedOrigin, origin)
		}
	})
}

// TestMethodNotFound tests non-existent method calls
func TestMethodNotFound(t *testing.T) {
	_, cfg, url := startTestServer(t)
	token := authenticateTestServer(t, url, cfg.Password)

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

// TestSecurityHeaders verifies that security headers are set correctly
// (see AUDIT.md LOW finding).
func TestSecurityHeaders(t *testing.T) {
	stats := &mockServerStatsProvider{}

	t.Run("http_includes_nosniff", func(t *testing.T) {
		port, err := getFreePort()
		if err != nil {
			t.Fatalf("Failed to get free port: %v", err)
		}
		cfg := testConfig(port)
		cfg.UseHTTPS = false

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
		resp, err := http.Post(url, "application/json", bytes.NewReader([]byte(`{}`)))
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		// X-Content-Type-Options should always be set
		if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("Expected X-Content-Type-Options: nosniff, got %q", got)
		}

		// Strict-Transport-Security should NOT be set for HTTP
		if got := resp.Header.Get("Strict-Transport-Security"); got != "" {
			t.Errorf("Expected no Strict-Transport-Security for HTTP, got %q", got)
		}
	})

	t.Run("https_includes_hsts", func(t *testing.T) {
		port, err := getFreePort()
		if err != nil {
			t.Fatalf("Failed to get free port: %v", err)
		}
		cfg := testConfig(port)
		cfg.UseHTTPS = true

		// For this test, we only check that the server would set the header
		// We can't actually test HTTPS without certificates, but we can verify
		// the header-setting logic by inspecting a mock response writer
		server, err := NewServer(cfg, stats)
		if err != nil {
			t.Fatalf("NewServer failed: %v", err)
		}

		// Use a mock ResponseWriter to capture headers
		mockW := &mockResponseWriter{header: make(http.Header)}
		req, _ := http.NewRequest("OPTIONS", "https://127.0.0.1/jsonrpc", nil)
		req.Host = cfg.Address
		server.setCORSHeaders(mockW, req)

		// X-Content-Type-Options should be set
		if got := mockW.header.Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("Expected X-Content-Type-Options: nosniff, got %q", got)
		}

		// Strict-Transport-Security should be set for HTTPS
		if got := mockW.header.Get("Strict-Transport-Security"); got != "max-age=31536000" {
			t.Errorf("Expected Strict-Transport-Security: max-age=31536000, got %q", got)
		}
	})

	t.Run("wildcard_bind_uses_request_host_for_origin", func(t *testing.T) {
		cfg := testConfig(7650)
		cfg.Address = "0.0.0.0:7650"
		cfg.UseHTTPS = false
		cfg.AllowPlaintextNonLoopback = true

		server, err := NewServer(cfg, stats)
		if err != nil {
			t.Fatalf("NewServer failed: %v", err)
		}

		mockW := &mockResponseWriter{header: make(http.Header)}
		req, _ := http.NewRequest("OPTIONS", "http://127.0.0.1:7650/jsonrpc", nil)
		req.Host = "127.0.0.1:7650"
		server.setCORSHeaders(mockW, req)

		if got := mockW.header.Get("Access-Control-Allow-Origin"); got != "http://127.0.0.1:7650" {
			t.Errorf("Expected wildcard bind CORS origin to use request host, got %q", got)
		}
	})
}

// mockResponseWriter is a minimal http.ResponseWriter for testing header setting
type mockResponseWriter struct {
	header http.Header
}

func (m *mockResponseWriter) Header() http.Header {
	return m.header
}

func (m *mockResponseWriter) Write([]byte) (int, error) {
	return 0, nil
}

func (m *mockResponseWriter) WriteHeader(statusCode int) {
}
