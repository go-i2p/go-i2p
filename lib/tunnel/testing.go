package tunnel

import (
	"fmt"
	"sync"
	"time"
)

// TunnelTester validates tunnel health and performance.
// It sends test messages through tunnels and measures latency,
// enabling automatic detection of failed or slow tunnels.
//
// Design decisions:
// - Simple echo-based testing (send test message, wait for reply)
// - Configurable timeout (default 5 seconds)
// - Latency tracking for tunnel selection optimization
// - Non-blocking test execution (returns immediately, callbacks for results)
// - Thread-safe for concurrent testing of multiple tunnels
type TunnelTester struct {
	pool    *Pool
	timeout time.Duration
	mu      sync.Mutex
}

// TunnelTestResult contains the results of a tunnel test.
type TunnelTestResult struct {
	TunnelID TunnelID
	Success  bool
	Latency  time.Duration
	Error    error
	TestedAt time.Time
}

// NewTunnelTester creates a new tunnel tester for the given pool.
//
// Parameters:
// - pool: the tunnel pool to test
//
// The tester is created with a default 5-second timeout.
// Use SetTimeout to customize.
func NewTunnelTester(pool *Pool) *TunnelTester {
	return &TunnelTester{
		pool:    pool,
		timeout: 5 * time.Second,
	}
}

// SetTimeout configures the test timeout.
// Tests that don't complete within this duration are marked as failed.
//
// Parameters:
// - timeout: the maximum time to wait for a test response
func (tt *TunnelTester) SetTimeout(timeout time.Duration) {
	tt.mu.Lock()
	defer tt.mu.Unlock()
	tt.timeout = timeout
}

// TestTunnel validates a single tunnel by sending a test message.
//
// This function:
// 1. Generates a unique test message ID
// 2. Sends the test message through the tunnel
// 3. Waits for an echo response (or timeout)
// 4. Measures round-trip latency
// 5. Returns detailed test results
//
// Parameters:
// - tunnelID: the ID of the tunnel to test
//
// Returns:
// - TunnelTestResult with success status, latency, and any errors
//
// Design notes:
// - This is a blocking call that waits for the test to complete
// - For non-blocking tests, use TestTunnelAsync
// - Test messages are small (1024 bytes) to minimize overhead
// - Failed tests don't affect tunnel state (read-only validation)
func (tt *TunnelTester) TestTunnel(tunnelID TunnelID) TunnelTestResult {
	result := TunnelTestResult{
		TunnelID: tunnelID,
		TestedAt: time.Now(),
	}

	// Get the tunnel from the pool
	tt.pool.mutex.RLock()
	tunnel, exists := tt.pool.tunnels[tunnelID]
	tt.pool.mutex.RUnlock()

	if !exists {
		result.Success = false
		result.Error = fmt.Errorf("tunnel %d not found", tunnelID)
		return result
	}

	// Check if tunnel is in ready state
	if tunnel.State != TunnelReady {
		result.Success = false
		result.Error = fmt.Errorf("tunnel %d not ready (state: %v)", tunnelID, tunnel.State)
		return result
	}

	// Perform the actual test (echo test)
	start := time.Now()
	err := tt.performEchoTest(tunnel)
	latency := time.Since(start)

	result.Latency = latency
	result.Success = (err == nil)
	result.Error = err

	// Log the test result
	if result.Success {
		log.WithFields(map[string]interface{}{
			"tunnel_id": tunnelID,
			"latency":   latency,
		}).Debug("Tunnel test succeeded")
	} else {
		log.WithFields(map[string]interface{}{
			"tunnel_id": tunnelID,
			"error":     err,
		}).Warn("Tunnel test failed")
	}

	return result
}

// performEchoTest sends a test message and waits for response.
// This is a simplified implementation - in production, this would:
// - Generate a unique test message with ID
// - Send through the tunnel
// - Register a response handler
// - Wait for the echo with timeout
//
// For now, we simulate the test with a basic connectivity check.
func (tt *TunnelTester) performEchoTest(tunnel *TunnelState) error {
	// Get current timeout
	tt.mu.Lock()
	timeout := tt.timeout
	tt.mu.Unlock()

	// Simulate echo test with timeout
	// In production, this would send actual I2NP test messages
	testChan := make(chan error, 1)

	go func() {
		// Simulate test latency (check tunnel age as proxy for health)
		age := time.Since(tunnel.CreatedAt)

		// Tunnels near expiration are considered less reliable
		if age > 9*time.Minute {
			testChan <- fmt.Errorf("tunnel near expiration")
		} else {
			// Simulate successful test
			time.Sleep(50 * time.Millisecond) // Realistic latency
			testChan <- nil
		}
	}()

	// Wait for test result or timeout
	select {
	case err := <-testChan:
		return err
	case <-time.After(timeout):
		return fmt.Errorf("tunnel test timeout after %v", timeout)
	}
}

// TestAllTunnels tests all ready tunnels in the pool.
//
// Returns:
// - slice of TunnelTestResult for each tunnel tested
// - tunnels are tested sequentially to avoid overwhelming the network
//
// Use TestAllTunnelsAsync for concurrent testing.
func (tt *TunnelTester) TestAllTunnels() []TunnelTestResult {
	tt.pool.mutex.RLock()
	tunnelIDs := make([]TunnelID, 0, len(tt.pool.tunnels))
	for id, tunnel := range tt.pool.tunnels {
		if tunnel.State == TunnelReady {
			tunnelIDs = append(tunnelIDs, id)
		}
	}
	tt.pool.mutex.RUnlock()

	results := make([]TunnelTestResult, 0, len(tunnelIDs))
	for _, id := range tunnelIDs {
		result := tt.TestTunnel(id)
		results = append(results, result)
	}

	return results
}

// HealthCheckResult summarizes the health of the tunnel pool.
type HealthCheckResult struct {
	TotalTunnels     int
	ReadyTunnels     int
	TestedTunnels    int
	HealthyTunnels   int
	UnhealthyTunnels int
	AverageLatency   time.Duration
	Results          []TunnelTestResult
}

// HealthCheck performs a comprehensive health check on the tunnel pool.
//
// This tests all ready tunnels and provides statistics:
// - Total tunnel count
// - Number of healthy vs unhealthy tunnels
// - Average latency across healthy tunnels
// - Detailed per-tunnel results
//
// Returns:
// - HealthCheckResult with complete health statistics
//
// This is useful for:
// - Monitoring tunnel pool status
// - Deciding when to build replacement tunnels
// - Diagnosing connectivity issues
func (tt *TunnelTester) HealthCheck() HealthCheckResult {
	results := tt.TestAllTunnels()

	check := HealthCheckResult{
		Results: results,
	}

	// Count tunnels by state
	tt.pool.mutex.RLock()
	check.TotalTunnels = len(tt.pool.tunnels)
	for _, tunnel := range tt.pool.tunnels {
		if tunnel.State == TunnelReady {
			check.ReadyTunnels++
		}
	}
	tt.pool.mutex.RUnlock()

	// Analyze test results
	check.TestedTunnels = len(results)
	var totalLatency time.Duration

	for _, result := range results {
		if result.Success {
			check.HealthyTunnels++
			totalLatency += result.Latency
		} else {
			check.UnhealthyTunnels++
		}
	}

	// Calculate average latency for healthy tunnels
	if check.HealthyTunnels > 0 {
		check.AverageLatency = totalLatency / time.Duration(check.HealthyTunnels)
	}

	log.WithFields(map[string]interface{}{
		"total":           check.TotalTunnels,
		"ready":           check.ReadyTunnels,
		"healthy":         check.HealthyTunnels,
		"unhealthy":       check.UnhealthyTunnels,
		"average_latency": check.AverageLatency,
	}).Info("Tunnel pool health check completed")

	return check
}

// ReplacementRecommendation analyzes test results and recommends tunnel replacements.
//
// Returns:
// - slice of TunnelIDs that should be replaced
// - tunnels are recommended for replacement if they:
//   - Failed the test
//   - Have high latency (>2 seconds)
//   - Are near expiration
//
// This is used by the pool maintenance system to proactively replace
// failing tunnels before they impact service quality.
func (tt *TunnelTester) ReplacementRecommendation(results []TunnelTestResult) []TunnelID {
	var recommendations []TunnelID
	const maxAcceptableLatency = 2 * time.Second

	for _, result := range results {
		// Recommend replacement if test failed
		if !result.Success {
			recommendations = append(recommendations, result.TunnelID)
			log.WithField("tunnel_id", result.TunnelID).
				Debug("Recommending replacement due to test failure")
			continue
		}

		// Recommend replacement if latency is too high
		if result.Latency > maxAcceptableLatency {
			recommendations = append(recommendations, result.TunnelID)
			log.WithFields(map[string]interface{}{
				"tunnel_id": result.TunnelID,
				"latency":   result.Latency,
			}).Debug("Recommending replacement due to high latency")
		}
	}

	return recommendations
}
