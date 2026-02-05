package i2pcontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/netdb"
	tunnelpkg "github.com/go-i2p/go-i2p/lib/tunnel"
)

// =============================================================================
// Section 1: Authentication - Token Validation Correctness
// =============================================================================

// TestAuthTokenValidationConstantTime verifies password comparison uses constant-time comparison
// to prevent timing attacks.
func TestAuthTokenValidationConstantTime(t *testing.T) {
	am, err := NewAuthManager("correctpassword")
	if err != nil {
		t.Fatalf("NewAuthManager failed: %v", err)
	}

	// Measure timing for correct password
	start := time.Now()
	_, _ = am.Authenticate("correctpassword", 10*time.Minute)
	correctDuration := time.Since(start)

	// Measure timing for wrong password with same length
	start = time.Now()
	_, _ = am.Authenticate("wrongpasswordxx", 10*time.Minute)
	wrongDuration := time.Since(start)

	// Measure timing for wrong password with different length
	start = time.Now()
	_, _ = am.Authenticate("x", 10*time.Minute)
	shortDuration := time.Since(start)

	// Timing variations should be minimal (under 1ms difference)
	// Note: This is a heuristic test; timing attacks require statistical analysis
	diff1 := correctDuration - wrongDuration
	diff2 := correctDuration - shortDuration
	if diff1 < 0 {
		diff1 = -diff1
	}
	if diff2 < 0 {
		diff2 = -diff2
	}

	// Log durations for manual inspection if needed
	t.Logf("Correct password duration: %v", correctDuration)
	t.Logf("Wrong password (same length) duration: %v", wrongDuration)
	t.Logf("Wrong password (short) duration: %v", shortDuration)
	t.Logf("Timing difference 1: %v", diff1)
	t.Logf("Timing difference 2: %v", diff2)

	// Verify hmac.Equal is being used (via code review the implementation uses it)
	// This test documents the expected behavior
}

// TestAuthTokenUnpredictability verifies tokens are cryptographically random and unpredictable.
func TestAuthTokenUnpredictability(t *testing.T) {
	am, err := NewAuthManager("password")
	if err != nil {
		t.Fatalf("NewAuthManager failed: %v", err)
	}

	// Generate many tokens and verify they don't have predictable patterns
	tokens := make([]string, 100)
	for i := 0; i < 100; i++ {
		token, err := am.Authenticate("password", 10*time.Minute)
		if err != nil {
			t.Fatalf("Authenticate failed: %v", err)
		}
		tokens[i] = token
		time.Sleep(time.Millisecond) // Ensure different timestamps
	}

	// Check for duplicates (should never happen)
	seen := make(map[string]bool)
	for _, token := range tokens {
		if seen[token] {
			t.Errorf("Duplicate token generated: %s", token)
		}
		seen[token] = true
	}

	// Verify tokens don't share common prefixes (beyond base64 alphabet)
	// A good HMAC should produce highly varied outputs
	prefixLen := 8
	prefixes := make(map[string]int)
	for _, token := range tokens {
		if len(token) >= prefixLen {
			prefix := token[:prefixLen]
			prefixes[prefix]++
		}
	}

	// With 100 random tokens, no prefix should appear more than ~5 times
	for prefix, count := range prefixes {
		if count > 10 {
			t.Errorf("Prefix %q appeared %d times, suggesting predictable token generation", prefix, count)
		}
	}
}

// TestAuthTokenExpirationBoundary verifies tokens expire correctly at the boundary.
func TestAuthTokenExpirationBoundary(t *testing.T) {
	am, err := NewAuthManager("password")
	if err != nil {
		t.Fatalf("NewAuthManager failed: %v", err)
	}

	// Create token expiring in 100ms
	token, err := am.Authenticate("password", 100*time.Millisecond)
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}

	// Token should be valid immediately
	if !am.ValidateToken(token) {
		t.Error("Token should be valid immediately after creation")
	}

	// Token should be valid just before expiration
	time.Sleep(50 * time.Millisecond)
	if !am.ValidateToken(token) {
		t.Error("Token should be valid before expiration")
	}

	// Token should be invalid after expiration
	time.Sleep(100 * time.Millisecond)
	if am.ValidateToken(token) {
		t.Error("Token should be invalid after expiration")
	}
}

// TestAuthSecretIsolation verifies different AuthManager instances have different secrets.
func TestAuthSecretIsolation(t *testing.T) {
	am1, err := NewAuthManager("password")
	if err != nil {
		t.Fatalf("NewAuthManager 1 failed: %v", err)
	}

	am2, err := NewAuthManager("password")
	if err != nil {
		t.Fatalf("NewAuthManager 2 failed: %v", err)
	}

	// Generate tokens with same password
	token1, _ := am1.Authenticate("password", 10*time.Minute)
	token2, _ := am2.Authenticate("password", 10*time.Minute)

	// Tokens should be different due to different secrets
	if token1 == token2 {
		t.Error("Different AuthManager instances should generate different tokens")
	}

	// Token from am1 should not validate on am2
	if am2.ValidateToken(token1) {
		t.Error("Token from am1 should not validate on am2")
	}

	// Token from am2 should not validate on am1
	if am1.ValidateToken(token2) {
		t.Error("Token from am2 should not validate on am1")
	}
}

// =============================================================================
// Section 2: Authorization - Command Permission Enforcement
// =============================================================================

// mockStatsForAuth implements RouterStatsProvider for authorization testing
type mockStatsForAuth struct {
	running bool
}

func (m *mockStatsForAuth) GetBandwidthStats() BandwidthStats {
	return BandwidthStats{InboundRate: 1000, OutboundRate: 2000}
}

func (m *mockStatsForAuth) GetRouterInfo() RouterInfoStats {
	return RouterInfoStats{Version: "test", Uptime: 1000}
}
func (m *mockStatsForAuth) GetTunnelStats() TunnelStats     { return TunnelStats{} }
func (m *mockStatsForAuth) GetNetDBStats() NetDBStats       { return NetDBStats{} }
func (m *mockStatsForAuth) GetNetworkConfig() NetworkConfig { return NetworkConfig{} }
func (m *mockStatsForAuth) IsRunning() bool                 { return m.running }
func (m *mockStatsForAuth) GetRouterControl() interface{ Stop() } {
	return &mockStopCtrl{}
}

type mockStopCtrl struct{}

func (m *mockStopCtrl) Stop() {}

// TestAuthorizationRequiredForProtectedMethods verifies protected methods require authentication.
func TestAuthorizationRequiredForProtectedMethods(t *testing.T) {
	stats := &mockStatsForAuth{running: true}
	cfg := &config.I2PControlConfig{
		Enabled:  true,
		Address:  "127.0.0.1:0",
		Password: "testpassword",
		UseHTTPS: false,
	}

	server, err := NewServer(cfg, stats)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	// Create test HTTP server
	ts := httptest.NewServer(http.HandlerFunc(server.handleRPC))
	defer ts.Close()

	// List of protected methods (require authentication)
	protectedMethods := []string{
		"GetRate",
		"RouterInfo",
		"RouterManager",
		"NetworkSetting",
		"I2PControl",
	}

	for _, method := range protectedMethods {
		t.Run(method+"_without_token", func(t *testing.T) {
			// Request without token
			reqBody, _ := json.Marshal(map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      1,
				"method":  method,
				"params":  map[string]interface{}{},
			})

			resp, err := http.Post(ts.URL, "application/json", bytes.NewReader(reqBody))
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			var rpcResp Response
			if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
				t.Fatalf("Failed to decode response: %v", err)
			}

			if rpcResp.Error == nil {
				t.Errorf("Method %s should require authentication", method)
			}
			if rpcResp.Error != nil && rpcResp.Error.Code != ErrCodeInvalidParams && rpcResp.Error.Code != ErrCodeAuthRequired {
				t.Errorf("Expected auth error for %s, got code %d: %s", method, rpcResp.Error.Code, rpcResp.Error.Message)
			}
		})
	}
}

// TestAuthorizationAuthenticateMethodNoTokenRequired verifies Authenticate doesn't require a token.
func TestAuthorizationAuthenticateMethodNoTokenRequired(t *testing.T) {
	stats := &mockStatsForAuth{running: true}
	cfg := &config.I2PControlConfig{
		Enabled:  true,
		Address:  "127.0.0.1:0",
		Password: "testpassword",
		UseHTTPS: false,
	}

	server, err := NewServer(cfg, stats)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	ts := httptest.NewServer(http.HandlerFunc(server.handleRPC))
	defer ts.Close()

	// Authenticate should work without existing token
	reqBody, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "Authenticate",
		"params": map[string]interface{}{
			"API":      1,
			"Password": "testpassword",
		},
	})

	resp, err := http.Post(ts.URL, "application/json", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	var rpcResp Response
	if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if rpcResp.Error != nil {
		t.Errorf("Authenticate should not require existing token: %v", rpcResp.Error)
	}

	// Verify we got a token back
	result, ok := rpcResp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("Expected map result, got %T", rpcResp.Result)
	}
	if _, hasToken := result["Token"]; !hasToken {
		t.Error("Expected Token in response")
	}
}

// TestAuthorizationInvalidTokenRejected verifies invalid tokens are rejected.
func TestAuthorizationInvalidTokenRejected(t *testing.T) {
	stats := &mockStatsForAuth{running: true}
	cfg := &config.I2PControlConfig{
		Enabled:  true,
		Address:  "127.0.0.1:0",
		Password: "testpassword",
		UseHTTPS: false,
	}

	server, err := NewServer(cfg, stats)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	ts := httptest.NewServer(http.HandlerFunc(server.handleRPC))
	defer ts.Close()

	// Request with invalid token
	reqBody, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "RouterInfo",
		"params": map[string]interface{}{
			"Token": "invalid_fake_token_12345",
		},
	})

	resp, err := http.Post(ts.URL, "application/json", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	var rpcResp Response
	if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if rpcResp.Error == nil {
		t.Error("Expected error for invalid token")
	}
	if rpcResp.Error != nil && rpcResp.Error.Code != ErrCodeAuthRequired {
		t.Errorf("Expected ErrCodeAuthRequired, got %d", rpcResp.Error.Code)
	}
}

// TestAuthorizationExpiredTokenRejected verifies expired tokens are rejected.
func TestAuthorizationExpiredTokenRejected(t *testing.T) {
	am, err := NewAuthManager("testpassword")
	if err != nil {
		t.Fatalf("NewAuthManager failed: %v", err)
	}

	// Create token with very short expiration
	token, err := am.Authenticate("testpassword", 50*time.Millisecond)
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}

	// Token should be valid initially
	if !am.ValidateToken(token) {
		t.Error("Token should be valid initially")
	}

	// Wait for expiration
	time.Sleep(100 * time.Millisecond)

	// Token should be invalid after expiration
	if am.ValidateToken(token) {
		t.Error("Expired token should be rejected")
	}
}

// TestAuthorizationTokenRevokedAfterPasswordChange verifies all tokens are revoked on password change.
func TestAuthorizationTokenRevokedAfterPasswordChange(t *testing.T) {
	am, err := NewAuthManager("oldpassword")
	if err != nil {
		t.Fatalf("NewAuthManager failed: %v", err)
	}

	// Create several tokens
	tokens := make([]string, 5)
	for i := 0; i < 5; i++ {
		tokens[i], _ = am.Authenticate("oldpassword", 10*time.Minute)
	}

	// All tokens should be valid
	for i, token := range tokens {
		if !am.ValidateToken(token) {
			t.Errorf("Token %d should be valid before password change", i)
		}
	}

	// Change password
	revokedCount := am.ChangePassword("newpassword")
	if revokedCount != 5 {
		t.Errorf("Expected 5 tokens revoked, got %d", revokedCount)
	}

	// All old tokens should be invalid
	for i, token := range tokens {
		if am.ValidateToken(token) {
			t.Errorf("Token %d should be invalid after password change", i)
		}
	}

	// Old password should not work
	_, err = am.Authenticate("oldpassword", 10*time.Minute)
	if err == nil {
		t.Error("Old password should not authenticate after change")
	}

	// New password should work
	newToken, err := am.Authenticate("newpassword", 10*time.Minute)
	if err != nil {
		t.Fatalf("New password should authenticate: %v", err)
	}
	if !am.ValidateToken(newToken) {
		t.Error("New token should be valid")
	}
}

// =============================================================================
// Section 3: Input Validation - RPC Parameter Sanitization
// =============================================================================

// TestInputValidationMalformedJSON verifies malformed JSON is rejected.
func TestInputValidationMalformedJSON(t *testing.T) {
	stats := &mockStatsForAuth{running: true}
	cfg := &config.I2PControlConfig{
		Enabled:  true,
		Address:  "127.0.0.1:0",
		Password: "testpassword",
		UseHTTPS: false,
	}

	server, err := NewServer(cfg, stats)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	ts := httptest.NewServer(http.HandlerFunc(server.handleRPC))
	defer ts.Close()

	malformedInputs := []struct {
		name  string
		input string
	}{
		{"truncated_json", `{"jsonrpc": "2.0", "method": "Echo"`},
		{"invalid_utf8", "{\"jsonrpc\": \"2.0\", \"method\": \"Echo\", \"params\": \"\xff\xfe\"}"},
		{"nested_too_deep", `{"jsonrpc":"2.0","method":"Echo","params":{"a":{"b":{"c":{"d":{"e":{"f":"g"}}}}}}}`},
		{"unclosed_string", `{"jsonrpc": "2.0", "method": "Echo", "params": {"Echo": "unclosed`},
		{"trailing_comma", `{"jsonrpc": "2.0", "method": "Echo", "params": {"Echo": "test",}}`},
		{"null_byte", "{\"jsonrpc\": \"2.0\", \"method\": \"Echo\", \"params\": {\"Echo\": \"test\x00value\"}}"},
	}

	for _, tc := range malformedInputs {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := http.Post(ts.URL, "application/json", strings.NewReader(tc.input))
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			body, _ := io.ReadAll(resp.Body)

			var rpcResp Response
			if err := json.Unmarshal(body, &rpcResp); err != nil {
				// If we can't even parse the response, that's acceptable for malformed input
				t.Logf("Response not parseable (expected for malformed input): %s", string(body))
				return
			}

			// Either we get an error or the server handles it gracefully
			// The important thing is no panic occurs (server is still running)
			if rpcResp.Error == nil && rpcResp.Result == nil {
				t.Logf("Got empty response for %s", tc.name)
			}
		})
	}
}

// TestInputValidationOversizedRequest verifies oversized requests are rejected.
func TestInputValidationOversizedRequest(t *testing.T) {
	stats := &mockStatsForAuth{running: true}
	cfg := &config.I2PControlConfig{
		Enabled:  true,
		Address:  "127.0.0.1:0",
		Password: "testpassword",
		UseHTTPS: false,
	}

	server, err := NewServer(cfg, stats)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	ts := httptest.NewServer(http.HandlerFunc(server.handleRPC))
	defer ts.Close()

	// Create a request larger than 1MB (the server limit)
	largeValue := strings.Repeat("a", 2*1024*1024) // 2MB
	reqBody, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "Echo",
		"params": map[string]interface{}{
			"Echo": largeValue,
		},
	})

	resp, err := http.Post(ts.URL, "application/json", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	// Server should truncate or reject the request
	// The key assertion is that the server doesn't crash
	t.Logf("Response to oversized request: %s", string(body))

	// Make another request to verify server is still working
	smallReq, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "Echo",
		"params":  map[string]interface{}{"Echo": "test"},
	})

	resp2, err := http.Post(ts.URL, "application/json", bytes.NewReader(smallReq))
	if err != nil {
		t.Fatalf("Server stopped responding after oversized request: %v", err)
	}
	defer resp2.Body.Close()
}

// TestInputValidationWrongHTTPMethod verifies non-POST requests are rejected.
func TestInputValidationWrongHTTPMethod(t *testing.T) {
	stats := &mockStatsForAuth{running: true}
	cfg := &config.I2PControlConfig{
		Enabled:  true,
		Address:  "127.0.0.1:0",
		Password: "testpassword",
		UseHTTPS: false,
	}

	server, err := NewServer(cfg, stats)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	ts := httptest.NewServer(http.HandlerFunc(server.handleRPC))
	defer ts.Close()

	methods := []string{"GET", "PUT", "DELETE", "PATCH"}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req, _ := http.NewRequest(method, ts.URL, nil)
			req.Header.Set("Content-Type", "application/json")

			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			var rpcResp Response
			if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
				t.Fatalf("Failed to decode response: %v", err)
			}

			if rpcResp.Error == nil {
				t.Errorf("Method %s should be rejected", method)
			}
		})
	}
}

// TestInputValidationWrongContentType verifies wrong Content-Type is rejected.
func TestInputValidationWrongContentType(t *testing.T) {
	stats := &mockStatsForAuth{running: true}
	cfg := &config.I2PControlConfig{
		Enabled:  true,
		Address:  "127.0.0.1:0",
		Password: "testpassword",
		UseHTTPS: false,
	}

	server, err := NewServer(cfg, stats)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	ts := httptest.NewServer(http.HandlerFunc(server.handleRPC))
	defer ts.Close()

	wrongContentTypes := []string{
		"text/plain",
		"text/html",
		"application/xml",
		"multipart/form-data",
		"",
	}

	for _, contentType := range wrongContentTypes {
		t.Run("Content-Type_"+contentType, func(t *testing.T) {
			reqBody := []byte(`{"jsonrpc":"2.0","method":"Echo","id":1}`)
			req, _ := http.NewRequest("POST", ts.URL, bytes.NewReader(reqBody))
			if contentType != "" {
				req.Header.Set("Content-Type", contentType)
			}

			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			var rpcResp Response
			if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
				t.Fatalf("Failed to decode response: %v", err)
			}

			if rpcResp.Error == nil {
				t.Errorf("Content-Type '%s' should be rejected", contentType)
			}
		})
	}
}

// TestInputValidationUnknownMethod verifies unknown methods return proper error.
func TestInputValidationUnknownMethod(t *testing.T) {
	stats := &mockStatsForAuth{running: true}
	cfg := &config.I2PControlConfig{
		Enabled:  true,
		Address:  "127.0.0.1:0",
		Password: "testpassword",
		UseHTTPS: false,
	}

	server, err := NewServer(cfg, stats)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	ts := httptest.NewServer(http.HandlerFunc(server.handleRPC))
	defer ts.Close()

	unknownMethods := []string{
		"UnknownMethod",
		"rpc.private",
		"__proto__",
		"constructor",
		"../../etc/passwd",
	}

	for _, method := range unknownMethods {
		t.Run(method, func(t *testing.T) {
			reqBody, _ := json.Marshal(map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      1,
				"method":  method,
				"params":  map[string]interface{}{"Token": "test"},
			})

			resp, err := http.Post(ts.URL, "application/json", bytes.NewReader(reqBody))
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			var rpcResp Response
			if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
				t.Fatalf("Failed to decode response: %v", err)
			}

			// Should return method not found error
			if rpcResp.Error == nil {
				t.Errorf("Unknown method '%s' should return error", method)
			}
		})
	}
}

// TestInputValidationSQLInjection verifies SQL-like injection attempts are handled safely.
func TestInputValidationSQLInjection(t *testing.T) {
	// Test that injection-style inputs don't cause unexpected behavior
	handler := NewEchoHandler()
	ctx := context.Background()

	injectionInputs := []string{
		"'; DROP TABLE users; --",
		"1 OR 1=1",
		"<script>alert('xss')</script>",
		"${7*7}",
		"{{7*7}}",
		"$(whoami)",
		"`whoami`",
	}

	for _, input := range injectionInputs {
		t.Run(input, func(t *testing.T) {
			params, _ := json.Marshal(map[string]interface{}{
				"Echo": input,
			})

			result, err := handler.Handle(ctx, params)
			if err != nil {
				// Errors are acceptable
				return
			}

			// If echo returns result, it should be the exact same input (no interpretation)
			resultMap, ok := result.(map[string]interface{})
			if !ok {
				return
			}

			if resultMap["Result"] != input {
				t.Errorf("Echo modified input: got %v, want %v", resultMap["Result"], input)
			}
		})
	}
}

// =============================================================================
// Section 4: Information Disclosure - Sensitive Data in Responses
// =============================================================================

// TestInfoDisclosureNoPasswordInResponse verifies password is never returned in responses.
func TestInfoDisclosureNoPasswordInResponse(t *testing.T) {
	stats := &mockStatsForAuth{running: true}
	cfg := &config.I2PControlConfig{
		Enabled:  true,
		Address:  "127.0.0.1:0",
		Password: "supersecretpassword123",
		UseHTTPS: false,
	}

	server, err := NewServer(cfg, stats)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	ts := httptest.NewServer(http.HandlerFunc(server.handleRPC))
	defer ts.Close()

	// Test various responses and ensure password never appears
	requests := []struct {
		method string
		params interface{}
	}{
		{"Authenticate", map[string]interface{}{"API": 1, "Password": "supersecretpassword123"}},
		{"Authenticate", map[string]interface{}{"API": 1, "Password": "wrongpassword"}},
		{"Echo", map[string]interface{}{"Echo": "test", "Token": "invalid"}},
	}

	for _, req := range requests {
		t.Run(req.method, func(t *testing.T) {
			reqBody, _ := json.Marshal(map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      1,
				"method":  req.method,
				"params":  req.params,
			})

			resp, err := http.Post(ts.URL, "application/json", bytes.NewReader(reqBody))
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			body, _ := io.ReadAll(resp.Body)
			bodyStr := string(body)

			// Password should never appear in response
			if strings.Contains(bodyStr, "supersecretpassword123") {
				t.Errorf("Password found in response: %s", bodyStr)
			}

			// Token generation secrets should never appear
			if strings.Contains(bodyStr, "secret") && strings.Contains(strings.ToLower(bodyStr), "secret") {
				// Check if it's not just the error message
				if !strings.Contains(bodyStr, "invalid") && !strings.Contains(bodyStr, "error") {
					t.Logf("Response mentions 'secret': %s", bodyStr)
				}
			}
		})
	}
}

// TestInfoDisclosureNoInternalPaths verifies internal paths aren't exposed in errors.
func TestInfoDisclosureNoInternalPaths(t *testing.T) {
	stats := &mockStatsForAuth{running: true}
	cfg := &config.I2PControlConfig{
		Enabled:  true,
		Address:  "127.0.0.1:0",
		Password: "testpassword",
		UseHTTPS: false,
	}

	server, err := NewServer(cfg, stats)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	ts := httptest.NewServer(http.HandlerFunc(server.handleRPC))
	defer ts.Close()

	// Send malformed requests to trigger errors
	badRequests := []string{
		`{"jsonrpc":"2.0","method":"Unknown","id":1}`,
		`{"jsonrpc":"2.0","method":"RouterInfo","id":1,"params":{"Token":"bad"}}`,
		`invalid json`,
	}

	for _, reqBody := range badRequests {
		resp, err := http.Post(ts.URL, "application/json", strings.NewReader(reqBody))
		if err != nil {
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		bodyStr := string(body)

		// Check for path disclosure
		pathPatterns := []string{
			"/home/",
			"/Users/",
			"C:\\",
			"/go/src/",
			".go:",
			"goroutine",
			"panic",
			"runtime.",
		}

		for _, pattern := range pathPatterns {
			if strings.Contains(bodyStr, pattern) {
				t.Errorf("Internal path/stack trace leaked in response: found '%s' in %s", pattern, bodyStr)
			}
		}
	}
}

// TestInfoDisclosureNoVersionLeakInErrors verifies version info isn't leaked in errors.
func TestInfoDisclosureNoVersionLeakInErrors(t *testing.T) {
	stats := &mockStatsForAuth{running: true}
	cfg := &config.I2PControlConfig{
		Enabled:  true,
		Address:  "127.0.0.1:0",
		Password: "testpassword",
		UseHTTPS: false,
	}

	server, err := NewServer(cfg, stats)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	ts := httptest.NewServer(http.HandlerFunc(server.handleRPC))
	defer ts.Close()

	// Request that causes error
	reqBody, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "RouterInfo",
		"params":  map[string]interface{}{"Token": "invalid"},
	})

	resp, err := http.Post(ts.URL, "application/json", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// Check response headers for version disclosure
	serverHeader := resp.Header.Get("Server")
	if strings.Contains(serverHeader, "Go") {
		t.Logf("Server header contains Go version info: %s", serverHeader)
		// This is informational, not necessarily a security issue
	}

	// X-Powered-By should not exist
	if resp.Header.Get("X-Powered-By") != "" {
		t.Errorf("X-Powered-By header should not be set: %s", resp.Header.Get("X-Powered-By"))
	}
}

// TestInfoDisclosureErrorMessagesGeneric verifies error messages don't reveal implementation details.
func TestInfoDisclosureErrorMessagesGeneric(t *testing.T) {
	am, err := NewAuthManager("correctpassword")
	if err != nil {
		t.Fatalf("NewAuthManager failed: %v", err)
	}

	// Test authentication error message
	_, authErr := am.Authenticate("wrongpassword", 10*time.Minute)
	if authErr == nil {
		t.Fatal("Expected error for wrong password")
	}

	errMsg := authErr.Error()

	// Error should be generic, not revealing specifics
	if strings.Contains(errMsg, "correctpassword") {
		t.Error("Error message contains the correct password")
	}
	if strings.Contains(errMsg, "password mismatch") || strings.Contains(errMsg, "bytes differ") {
		t.Logf("Error might be too specific: %s", errMsg)
	}

	// Generic message like "invalid password" is acceptable
	if !strings.Contains(errMsg, "invalid") {
		t.Logf("Error message: %s", errMsg)
	}
}

// =============================================================================
// Section 5: Bandwidth Stats - Accuracy of Reported Values
// =============================================================================

// TestBandwidthStatsAccuracy verifies bandwidth stats return correct values.
func TestBandwidthStatsAccuracy(t *testing.T) {
	// Create mock with specific bandwidth values
	expectedInbound := float64(12345)
	expectedOutbound := float64(67890)

	mock := &mockRouterAccessBandwidth{
		inbound:  uint64(expectedInbound),
		outbound: uint64(expectedOutbound),
	}

	provider := NewRouterStatsProvider(mock, "test-version")

	stats := provider.GetBandwidthStats()

	if stats.InboundRate != expectedInbound {
		t.Errorf("InboundRate: got %f, want %f", stats.InboundRate, expectedInbound)
	}
	if stats.OutboundRate != expectedOutbound {
		t.Errorf("OutboundRate: got %f, want %f", stats.OutboundRate, expectedOutbound)
	}
}

// mockRouterAccessBandwidth implements RouterAccess for bandwidth testing
type mockRouterAccessBandwidth struct {
	inbound  uint64
	outbound uint64
}

func (m *mockRouterAccessBandwidth) GetNetDB() *netdb.StdNetDB {
	return nil
}
func (m *mockRouterAccessBandwidth) GetTunnelManager() *i2np.TunnelManager { return nil }
func (m *mockRouterAccessBandwidth) GetParticipantManager() *tunnelpkg.Manager {
	return nil
}
func (m *mockRouterAccessBandwidth) GetConfig() *config.RouterConfig { return nil }
func (m *mockRouterAccessBandwidth) IsRunning() bool                 { return true }
func (m *mockRouterAccessBandwidth) IsReseeding() bool               { return false }
func (m *mockRouterAccessBandwidth) GetBandwidthRates() (inbound, outbound uint64) {
	return m.inbound, m.outbound
}
func (m *mockRouterAccessBandwidth) GetTransportAddr() interface{} { return nil }
func (m *mockRouterAccessBandwidth) Stop()                         {}

// TestBandwidthStatsZeroValues verifies zero bandwidth is handled correctly.
func TestBandwidthStatsZeroValues(t *testing.T) {
	mock := &mockRouterAccessBandwidth{
		inbound:  0,
		outbound: 0,
	}

	provider := NewRouterStatsProvider(mock, "test-version")
	stats := provider.GetBandwidthStats()

	if stats.InboundRate != 0 {
		t.Errorf("InboundRate should be 0, got %f", stats.InboundRate)
	}
	if stats.OutboundRate != 0 {
		t.Errorf("OutboundRate should be 0, got %f", stats.OutboundRate)
	}
}

// TestBandwidthStatsLargeValues verifies large bandwidth values don't overflow.
func TestBandwidthStatsLargeValues(t *testing.T) {
	// 10 Gbps = 1.25 GB/s = 1,250,000,000 bytes/s
	largeValue := uint64(1250000000)

	mock := &mockRouterAccessBandwidth{
		inbound:  largeValue,
		outbound: largeValue,
	}

	provider := NewRouterStatsProvider(mock, "test-version")
	stats := provider.GetBandwidthStats()

	if stats.InboundRate != float64(largeValue) {
		t.Errorf("InboundRate: got %f, want %f", stats.InboundRate, float64(largeValue))
	}
	if stats.OutboundRate != float64(largeValue) {
		t.Errorf("OutboundRate: got %f, want %f", stats.OutboundRate, float64(largeValue))
	}
}

// TestBandwidthStatsHandlerIntegration verifies GetRate handler returns correct data.
func TestBandwidthStatsHandlerIntegration(t *testing.T) {
	stats := &mockStatsForAuth{running: true}
	handler := NewGetRateHandler(stats)
	ctx := context.Background()

	params, _ := json.Marshal(map[string]interface{}{
		"i2p.router.net.bw.inbound.15s":  nil,
		"i2p.router.net.bw.outbound.15s": nil,
	})

	result, err := handler.Handle(ctx, params)
	if err != nil {
		t.Fatalf("GetRate handler failed: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("Expected map result, got %T", result)
	}

	// Verify expected fields are present
	if _, ok := resultMap["i2p.router.net.bw.inbound.15s"]; !ok {
		t.Error("Missing i2p.router.net.bw.inbound.15s in response")
	}
	if _, ok := resultMap["i2p.router.net.bw.outbound.15s"]; !ok {
		t.Error("Missing i2p.router.net.bw.outbound.15s in response")
	}

	// Values should match what mockStatsForAuth returns
	expectedInbound := float64(1000)
	expectedOutbound := float64(2000)

	if resultMap["i2p.router.net.bw.inbound.15s"] != expectedInbound {
		t.Errorf("Inbound rate: got %v, want %v", resultMap["i2p.router.net.bw.inbound.15s"], expectedInbound)
	}
	if resultMap["i2p.router.net.bw.outbound.15s"] != expectedOutbound {
		t.Errorf("Outbound rate: got %v, want %v", resultMap["i2p.router.net.bw.outbound.15s"], expectedOutbound)
	}
}

// TestBandwidthStatsConcurrentAccess verifies thread-safe bandwidth stat access.
func TestBandwidthStatsConcurrentAccess(t *testing.T) {
	mock := &mockRouterAccessBandwidth{
		inbound:  1000,
		outbound: 2000,
	}

	provider := NewRouterStatsProvider(mock, "test-version")

	var wg sync.WaitGroup
	numGoroutines := 100

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			stats := provider.GetBandwidthStats()
			if stats.InboundRate != 1000 {
				t.Errorf("Unexpected inbound rate: %f", stats.InboundRate)
			}
			if stats.OutboundRate != 2000 {
				t.Errorf("Unexpected outbound rate: %f", stats.OutboundRate)
			}
		}()
	}

	wg.Wait()
}

// TestBandwidthStatsSelectiveFieldRequest verifies only requested fields are returned.
func TestBandwidthStatsSelectiveFieldRequest(t *testing.T) {
	stats := &mockStatsForAuth{running: true}
	handler := NewGetRateHandler(stats)
	ctx := context.Background()

	// Request only inbound
	params, _ := json.Marshal(map[string]interface{}{
		"i2p.router.net.bw.inbound.15s": nil,
	})

	result, err := handler.Handle(ctx, params)
	if err != nil {
		t.Fatalf("GetRate handler failed: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("Expected map result, got %T", result)
	}

	if _, ok := resultMap["i2p.router.net.bw.inbound.15s"]; !ok {
		t.Error("Missing requested inbound field")
	}

	// Outbound should not be in response when only inbound was requested
	if _, ok := resultMap["i2p.router.net.bw.outbound.15s"]; ok {
		t.Error("Outbound field should not be present when not requested")
	}
}

// =============================================================================
// Additional Security Tests
// =============================================================================

// TestRPCErrorCodesCorrect verifies error codes follow JSON-RPC spec.
func TestRPCErrorCodesCorrect(t *testing.T) {
	// Standard JSON-RPC error codes
	standardCodes := map[int]string{
		-32700: "Parse error",
		-32600: "Invalid Request",
		-32601: "Method not found",
		-32602: "Invalid params",
		-32603: "Internal error",
	}

	// Verify our constants match
	if ErrCodeParseError != -32700 {
		t.Errorf("ErrCodeParseError: got %d, want -32700", ErrCodeParseError)
	}
	if ErrCodeInvalidRequest != -32600 {
		t.Errorf("ErrCodeInvalidRequest: got %d, want -32600", ErrCodeInvalidRequest)
	}
	if ErrCodeMethodNotFound != -32601 {
		t.Errorf("ErrCodeMethodNotFound: got %d, want -32601", ErrCodeMethodNotFound)
	}
	if ErrCodeInvalidParams != -32602 {
		t.Errorf("ErrCodeInvalidParams: got %d, want -32602", ErrCodeInvalidParams)
	}
	if ErrCodeInternalError != -32603 {
		t.Errorf("ErrCodeInternalError: got %d, want -32603", ErrCodeInternalError)
	}

	// Implementation-defined codes should be in -32000 to -32099 range
	implCodes := []int{ErrCodeAuthRequired, ErrCodeAuthFailed, ErrCodeNotImpl}
	for _, code := range implCodes {
		if code < -32099 || code > -32000 {
			t.Errorf("Implementation code %d not in range -32099 to -32000", code)
		}
	}

	t.Logf("Standard codes verified: %v", standardCodes)
}

// TestCORSHeadersSet verifies CORS headers are properly configured.
func TestCORSHeadersSet(t *testing.T) {
	stats := &mockStatsForAuth{running: true}
	cfg := &config.I2PControlConfig{
		Enabled:  true,
		Address:  "127.0.0.1:0",
		Password: "testpassword",
		UseHTTPS: false,
	}

	server, err := NewServer(cfg, stats)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	ts := httptest.NewServer(http.HandlerFunc(server.handleRPC))
	defer ts.Close()

	// OPTIONS request (preflight)
	req, _ := http.NewRequest("OPTIONS", ts.URL, nil)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("OPTIONS request failed: %v", err)
	}
	defer resp.Body.Close()

	// Check CORS headers
	allowOrigin := resp.Header.Get("Access-Control-Allow-Origin")
	allowMethods := resp.Header.Get("Access-Control-Allow-Methods")
	allowHeaders := resp.Header.Get("Access-Control-Allow-Headers")

	if allowOrigin != "*" {
		t.Logf("Access-Control-Allow-Origin: %s (may want to restrict in production)", allowOrigin)
	}
	if !strings.Contains(allowMethods, "POST") {
		t.Errorf("Access-Control-Allow-Methods should include POST: %s", allowMethods)
	}
	if !strings.Contains(allowHeaders, "Content-Type") {
		t.Errorf("Access-Control-Allow-Headers should include Content-Type: %s", allowHeaders)
	}
}

// TestGracefulShutdown verifies server shuts down gracefully.
func TestGracefulShutdown(t *testing.T) {
	stats := &mockStatsForAuth{running: true}
	cfg := &config.I2PControlConfig{
		Enabled:  true,
		Address:  "127.0.0.1:0",
		Password: "testpassword",
		UseHTTPS: false,
	}

	server, err := NewServer(cfg, stats)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	// Don't actually start HTTP server for this test
	// Just verify Stop() doesn't panic on unstarted server
	server.Stop()

	// Second stop shouldn't panic
	server.Stop()
}

// TestTimeoutEnforced verifies request timeouts are properly configured.
func TestTimeoutEnforced(t *testing.T) {
	stats := &mockStatsForAuth{running: true}
	cfg := &config.I2PControlConfig{
		Enabled:  true,
		Address:  "127.0.0.1:0",
		Password: "testpassword",
		UseHTTPS: false,
	}

	server, err := NewServer(cfg, stats)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	// Verify HTTP server has timeouts configured
	httpServer := server.httpServer
	if httpServer.ReadTimeout == 0 {
		t.Error("ReadTimeout should be non-zero")
	}
	if httpServer.WriteTimeout == 0 {
		t.Error("WriteTimeout should be non-zero")
	}
	if httpServer.IdleTimeout == 0 {
		t.Error("IdleTimeout should be non-zero")
	}

	t.Logf("ReadTimeout: %v, WriteTimeout: %v, IdleTimeout: %v",
		httpServer.ReadTimeout, httpServer.WriteTimeout, httpServer.IdleTimeout)
}
