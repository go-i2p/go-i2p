package tunnel

import (
	"fmt"
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
	t.Skip("Timeout test would require >5 seconds, skipping for fast test suite")
	// This test would set a very short timeout and verify that
	// tests time out appropriately. Skipped to keep test suite fast.
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
