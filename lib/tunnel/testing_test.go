package tunnel

import (
	"fmt"
	"sync"
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
)

// TestNewTunnelTester verifies tester creation
func TestNewTunnelTester(t *testing.T) {
	pool := createTestPool(t)
	defer pool.Stop()

	tester := NewTunnelTester(pool)
	if tester == nil {
		t.Fatal("NewTunnelTester returned nil")
	}

	if tester.pool != pool {
		t.Error("Tester pool not set correctly")
	}

	if tester.timeout != 5*time.Second {
		t.Errorf("Expected default timeout of 5s, got %v", tester.timeout)
	}
}

// TestSetTimeout verifies timeout configuration
func TestSetTimeout(t *testing.T) {
	pool := createTestPool(t)
	defer pool.Stop()

	tester := NewTunnelTester(pool)

	customTimeout := 10 * time.Second
	tester.SetTimeout(customTimeout)

	if tester.timeout != customTimeout {
		t.Errorf("Expected timeout %v, got %v", customTimeout, tester.timeout)
	}
}

// TestTestTunnel_TunnelNotFound verifies error handling for missing tunnels
func TestTestTunnel_TunnelNotFound(t *testing.T) {
	pool := createTestPool(t)
	defer pool.Stop()

	tester := NewTunnelTester(pool)

	result := tester.TestTunnel(99999)

	if result.Success {
		t.Error("Expected test to fail for nonexistent tunnel")
	}

	if result.Error == nil {
		t.Error("Expected error for nonexistent tunnel")
	}

	if result.TunnelID != 99999 {
		t.Errorf("Expected tunnel ID 99999, got %d", result.TunnelID)
	}
}

// TestTestTunnel_NotReady verifies error handling for non-ready tunnels
func TestTestTunnel_NotReady(t *testing.T) {
	pool := createTestPool(t)
	defer pool.Stop()

	// Add a tunnel in building state
	pool.mutex.Lock()
	pool.tunnels[12345] = &TunnelState{
		ID:        12345,
		State:     TunnelBuilding,
		CreatedAt: time.Now(),
	}
	pool.mutex.Unlock()

	tester := NewTunnelTester(pool)
	result := tester.TestTunnel(12345)

	if result.Success {
		t.Error("Expected test to fail for non-ready tunnel")
	}

	if result.Error == nil {
		t.Error("Expected error for non-ready tunnel")
	}
}

// TestTestTunnel_Success verifies successful tunnel testing
func TestTestTunnel_Success(t *testing.T) {
	pool := createTestPool(t)
	defer pool.Stop()

	// Add a ready tunnel
	tunnelID := TunnelID(54321)
	pool.mutex.Lock()
	pool.tunnels[tunnelID] = &TunnelState{
		ID:        tunnelID,
		State:     TunnelReady,
		CreatedAt: time.Now(),
		Hops:      []common.Hash{{1}, {2}, {3}},
	}
	pool.mutex.Unlock()

	tester := NewTunnelTester(pool)
	tester.SetTimeout(2 * time.Second)

	result := tester.TestTunnel(tunnelID)

	if !result.Success {
		t.Errorf("Expected test to succeed, got error: %v", result.Error)
	}

	if result.Latency == 0 {
		t.Error("Expected non-zero latency")
	}

	if result.Latency > 2*time.Second {
		t.Errorf("Latency too high: %v", result.Latency)
	}

	if result.TunnelID != tunnelID {
		t.Errorf("Expected tunnel ID %d, got %d", tunnelID, result.TunnelID)
	}
}

// TestTestTunnel_NearExpiration verifies detection of near-expiry tunnels
func TestTestTunnel_NearExpiration(t *testing.T) {
	pool := createTestPool(t)
	defer pool.Stop()

	// Add a tunnel that's near expiration
	tunnelID := TunnelID(11111)
	pool.mutex.Lock()
	pool.tunnels[tunnelID] = &TunnelState{
		ID:        tunnelID,
		State:     TunnelReady,
		CreatedAt: time.Now().Add(-9*time.Minute - 30*time.Second), // 30s before 10min expiry
		Hops:      []common.Hash{{1}, {2}, {3}},
	}
	pool.mutex.Unlock()

	tester := NewTunnelTester(pool)
	result := tester.TestTunnel(tunnelID)

	// Should fail because tunnel is near expiration
	if result.Success {
		t.Error("Expected test to fail for near-expiry tunnel")
	}

	if result.Error == nil {
		t.Error("Expected error for near-expiry tunnel")
	}
}

// TestTestAllTunnels verifies testing multiple tunnels
func TestTestAllTunnels(t *testing.T) {
	pool := createTestPool(t)
	defer pool.Stop()

	// Add multiple ready tunnels
	pool.mutex.Lock()
	for i := TunnelID(1); i <= 3; i++ {
		pool.tunnels[i] = &TunnelState{
			ID:        i,
			State:     TunnelReady,
			CreatedAt: time.Now(),
			Hops:      []common.Hash{{1}, {2}, {3}},
		}
	}
	// Add one non-ready tunnel (should not be tested)
	pool.tunnels[4] = &TunnelState{
		ID:        4,
		State:     TunnelBuilding,
		CreatedAt: time.Now(),
	}
	pool.mutex.Unlock()

	tester := NewTunnelTester(pool)
	results := tester.TestAllTunnels()

	// Should test only the 3 ready tunnels
	if len(results) != 3 {
		t.Errorf("Expected 3 test results, got %d", len(results))
	}

	// Verify all results
	for _, result := range results {
		if result.TunnelID == 4 {
			t.Error("Should not test non-ready tunnel")
		}

		if !result.Success {
			t.Errorf("Expected tunnel %d test to succeed, got error: %v",
				result.TunnelID, result.Error)
		}
	}
}

// TestHealthCheck verifies health check functionality
func TestHealthCheck(t *testing.T) {
	pool := createTestPool(t)
	defer pool.Stop()

	// Add mix of tunnels
	pool.mutex.Lock()
	// 2 healthy tunnels
	for i := TunnelID(1); i <= 2; i++ {
		pool.tunnels[i] = &TunnelState{
			ID:        i,
			State:     TunnelReady,
			CreatedAt: time.Now(),
			Hops:      []common.Hash{{1}, {2}, {3}},
		}
	}
	// 1 near-expiry tunnel (will fail test)
	pool.tunnels[3] = &TunnelState{
		ID:        3,
		State:     TunnelReady,
		CreatedAt: time.Now().Add(-9*time.Minute - 30*time.Second),
		Hops:      []common.Hash{{1}, {2}, {3}},
	}
	// 1 building tunnel (not tested)
	pool.tunnels[4] = &TunnelState{
		ID:        4,
		State:     TunnelBuilding,
		CreatedAt: time.Now(),
	}
	pool.mutex.Unlock()

	tester := NewTunnelTester(pool)
	health := tester.HealthCheck()

	if health.TotalTunnels != 4 {
		t.Errorf("Expected 4 total tunnels, got %d", health.TotalTunnels)
	}

	if health.ReadyTunnels != 3 {
		t.Errorf("Expected 3 ready tunnels, got %d", health.ReadyTunnels)
	}

	if health.TestedTunnels != 3 {
		t.Errorf("Expected 3 tested tunnels, got %d", health.TestedTunnels)
	}

	if health.HealthyTunnels != 2 {
		t.Errorf("Expected 2 healthy tunnels, got %d", health.HealthyTunnels)
	}

	if health.UnhealthyTunnels != 1 {
		t.Errorf("Expected 1 unhealthy tunnel, got %d", health.UnhealthyTunnels)
	}

	if health.AverageLatency == 0 {
		t.Error("Expected non-zero average latency")
	}

	if len(health.Results) != 3 {
		t.Errorf("Expected 3 test results, got %d", len(health.Results))
	}
}

// TestReplacementRecommendation verifies replacement logic
func TestReplacementRecommendation(t *testing.T) {
	pool := createTestPool(t)
	defer pool.Stop()

	tester := NewTunnelTester(pool)

	// Create test results with various conditions
	results := []TunnelTestResult{
		{
			TunnelID: 1,
			Success:  true,
			Latency:  100 * time.Millisecond, // Good
		},
		{
			TunnelID: 2,
			Success:  false, // Failed test
			Error:    fmt.Errorf("test failed"),
		},
		{
			TunnelID: 3,
			Success:  true,
			Latency:  3 * time.Second, // High latency
		},
		{
			TunnelID: 4,
			Success:  true,
			Latency:  500 * time.Millisecond, // Good
		},
	}

	recommendations := tester.ReplacementRecommendation(results)

	// Should recommend replacing tunnels 2 (failed) and 3 (high latency)
	if len(recommendations) != 2 {
		t.Errorf("Expected 2 replacement recommendations, got %d", len(recommendations))
	}

	// Verify specific tunnels recommended
	recommendedMap := make(map[TunnelID]bool)
	for _, id := range recommendations {
		recommendedMap[id] = true
	}

	if !recommendedMap[2] {
		t.Error("Expected tunnel 2 (failed) to be recommended for replacement")
	}

	if !recommendedMap[3] {
		t.Error("Expected tunnel 3 (high latency) to be recommended for replacement")
	}

	if recommendedMap[1] || recommendedMap[4] {
		t.Error("Healthy tunnels should not be recommended for replacement")
	}
}

// TestTestTunnel_Timeout verifies timeout handling
func TestTestTunnel_Timeout(t *testing.T) {
	pool := createTestPool(t)
	defer pool.Stop()

	// Add a ready tunnel
	tunnelID := TunnelID(77777)
	pool.mutex.Lock()
	pool.tunnels[tunnelID] = &TunnelState{
		ID:        tunnelID,
		State:     TunnelReady,
		CreatedAt: time.Now(),
		Hops:      []common.Hash{{1}, {2}, {3}},
	}
	pool.mutex.Unlock()

	// Configure sender that never responds
	sender := newMockMessageSender()
	tester := NewTunnelTester(pool)
	tester.SetMessageSender(sender)
	tester.SetTimeout(500 * time.Millisecond) // Short timeout

	start := time.Now()
	result := tester.TestTunnel(tunnelID)
	elapsed := time.Since(start)

	// Should fail due to timeout
	if result.Success {
		t.Error("Expected test to fail due to timeout")
	}

	if result.Error == nil {
		t.Error("Expected timeout error")
	}

	// Verify timeout happened in expected time range
	if elapsed < 400*time.Millisecond {
		t.Errorf("Timeout happened too quickly: %v", elapsed)
	}

	if elapsed > 2*time.Second {
		t.Errorf("Timeout took too long: %v", elapsed)
	}
}

// createTestPool creates a minimal pool for testing
func createTestPool(t *testing.T) *Pool {
	t.Helper()

	pool := &Pool{
		tunnels: make(map[TunnelID]*TunnelState),
		config:  DefaultPoolConfig(),
	}

	// Don't start maintenance for these tests
	return pool
}

// mockMessageSender implements TunnelMessageSender for testing
type mockMessageSender struct {
	sentMessages map[TunnelID][]uint32
	shouldFail   bool
	mu           sync.Mutex
}

func newMockMessageSender() *mockMessageSender {
	return &mockMessageSender{
		sentMessages: make(map[TunnelID][]uint32),
	}
}

func (m *mockMessageSender) SendTestMessage(tunnelID TunnelID, messageID uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.shouldFail {
		return fmt.Errorf("mock send failure")
	}

	m.sentMessages[tunnelID] = append(m.sentMessages[tunnelID], messageID)
	return nil
}

func (m *mockMessageSender) getLastMessageID(tunnelID TunnelID) (uint32, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	messages := m.sentMessages[tunnelID]
	if len(messages) == 0 {
		return 0, false
	}
	return messages[len(messages)-1], true
}

// TestSetMessageSender verifies message sender configuration
func TestSetMessageSender(t *testing.T) {
	pool := createTestPool(t)
	defer pool.Stop()

	tester := NewTunnelTester(pool)

	if tester.sender != nil {
		t.Error("Expected no sender initially")
	}

	sender := newMockMessageSender()
	tester.SetMessageSender(sender)

	if tester.sender != sender {
		t.Error("Sender not set correctly")
	}
}

// TestRealEchoTest_Success verifies real echo test with response
func TestRealEchoTest_Success(t *testing.T) {
	pool := createTestPool(t)
	defer pool.Stop()

	// Add a ready tunnel
	tunnelID := TunnelID(12345)
	pool.mutex.Lock()
	pool.tunnels[tunnelID] = &TunnelState{
		ID:        tunnelID,
		State:     TunnelReady,
		CreatedAt: time.Now(),
		Hops:      []common.Hash{{1}, {2}, {3}},
	}
	pool.mutex.Unlock()

	sender := newMockMessageSender()
	tester := NewTunnelTester(pool)
	tester.SetMessageSender(sender)
	tester.SetTimeout(2 * time.Second)

	// Run test in goroutine since it will block
	resultCh := make(chan TunnelTestResult, 1)
	go func() {
		resultCh <- tester.TestTunnel(tunnelID)
	}()

	// Wait a bit for the message to be sent
	time.Sleep(50 * time.Millisecond)

	// Get the message ID and simulate response
	messageID, ok := sender.getLastMessageID(tunnelID)
	if !ok {
		t.Fatal("No message was sent")
	}

	// Simulate response
	handled := tester.HandleTestResponse(messageID)
	if !handled {
		t.Error("Response was not handled")
	}

	// Get result
	select {
	case result := <-resultCh:
		if !result.Success {
			t.Errorf("Expected test to succeed, got error: %v", result.Error)
		}
		if result.Latency == 0 {
			t.Error("Expected non-zero latency")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Test timed out waiting for result")
	}
}

// TestRealEchoTest_Timeout verifies timeout when no response
func TestRealEchoTest_Timeout(t *testing.T) {
	pool := createTestPool(t)
	defer pool.Stop()

	// Add a ready tunnel
	tunnelID := TunnelID(54321)
	pool.mutex.Lock()
	pool.tunnels[tunnelID] = &TunnelState{
		ID:        tunnelID,
		State:     TunnelReady,
		CreatedAt: time.Now(),
		Hops:      []common.Hash{{1}, {2}, {3}},
	}
	pool.mutex.Unlock()

	sender := newMockMessageSender()
	tester := NewTunnelTester(pool)
	tester.SetMessageSender(sender)
	tester.SetTimeout(100 * time.Millisecond) // Short timeout for test

	result := tester.TestTunnel(tunnelID)

	if result.Success {
		t.Error("Expected test to fail due to timeout")
	}

	if result.Error == nil {
		t.Error("Expected timeout error")
	}
}

// TestRealEchoTest_SendFailure verifies handling of send failures
func TestRealEchoTest_SendFailure(t *testing.T) {
	pool := createTestPool(t)
	defer pool.Stop()

	// Add a ready tunnel
	tunnelID := TunnelID(99999)
	pool.mutex.Lock()
	pool.tunnels[tunnelID] = &TunnelState{
		ID:        tunnelID,
		State:     TunnelReady,
		CreatedAt: time.Now(),
		Hops:      []common.Hash{{1}, {2}, {3}},
	}
	pool.mutex.Unlock()

	sender := newMockMessageSender()
	sender.shouldFail = true

	tester := NewTunnelTester(pool)
	tester.SetMessageSender(sender)

	result := tester.TestTunnel(tunnelID)

	if result.Success {
		t.Error("Expected test to fail due to send failure")
	}

	if result.Error == nil {
		t.Error("Expected error for send failure")
	}
}

// TestHandleTestResponse_UnknownMessage verifies handling of unknown responses
func TestHandleTestResponse_UnknownMessage(t *testing.T) {
	pool := createTestPool(t)
	defer pool.Stop()

	tester := NewTunnelTester(pool)

	// Handle response for unknown message ID
	handled := tester.HandleTestResponse(12345)
	if handled {
		t.Error("Should not handle unknown message ID")
	}
}

// TestGenerateTestMessageID verifies unique ID generation
func TestGenerateTestMessageID(t *testing.T) {
	pool := createTestPool(t)
	defer pool.Stop()

	tester := NewTunnelTester(pool)

	ids := make(map[uint32]bool)
	for i := 0; i < 100; i++ {
		id, err := tester.generateTestMessageID()
		if err != nil {
			t.Fatalf("Failed to generate message ID: %v", err)
		}

		if ids[id] {
			t.Errorf("Duplicate message ID generated: %d", id)
		}
		ids[id] = true
	}
}

// TestPendingTestsCleanup verifies pending tests are cleaned up after completion
func TestPendingTestsCleanup(t *testing.T) {
	pool := createTestPool(t)
	defer pool.Stop()

	// Add a ready tunnel
	tunnelID := TunnelID(11111)
	pool.mutex.Lock()
	pool.tunnels[tunnelID] = &TunnelState{
		ID:        tunnelID,
		State:     TunnelReady,
		CreatedAt: time.Now(),
		Hops:      []common.Hash{{1}, {2}, {3}},
	}
	pool.mutex.Unlock()

	sender := newMockMessageSender()
	tester := NewTunnelTester(pool)
	tester.SetMessageSender(sender)
	tester.SetTimeout(1 * time.Second)

	// Run test that will timeout
	_ = tester.TestTunnel(tunnelID)

	// Check that pending test was cleaned up
	tester.mu.Lock()
	pendingCount := len(tester.pendingTests)
	tester.mu.Unlock()

	if pendingCount != 0 {
		t.Errorf("Expected 0 pending tests after completion, got %d", pendingCount)
	}
}

// TestFallbackToAgeBasedTest verifies fallback when no sender configured
func TestFallbackToAgeBasedTest(t *testing.T) {
	pool := createTestPool(t)
	defer pool.Stop()

	// Add a ready tunnel
	tunnelID := TunnelID(22222)
	pool.mutex.Lock()
	pool.tunnels[tunnelID] = &TunnelState{
		ID:        tunnelID,
		State:     TunnelReady,
		CreatedAt: time.Now(),
		Hops:      []common.Hash{{1}, {2}, {3}},
	}
	pool.mutex.Unlock()

	// Create tester WITHOUT setting message sender
	tester := NewTunnelTester(pool)

	result := tester.TestTunnel(tunnelID)

	// Should succeed using age-based fallback
	if !result.Success {
		t.Errorf("Expected fallback test to succeed, got error: %v", result.Error)
	}

	if result.Latency == 0 {
		t.Error("Expected non-zero latency even for fallback")
	}
}
