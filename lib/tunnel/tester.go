package tunnel

import (
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"github.com/go-i2p/crypto/rand"
)

// TunnelMessageSender defines the interface for sending test messages through tunnels.
// This abstraction allows the TunnelTester to remain decoupled from the transport layer.
// The router or a higher-level component provides the actual implementation.
type TunnelMessageSender interface {
	// SendTestMessage sends a DeliveryStatus test message through the specified tunnel.
	// Parameters:
	//   - tunnelID: the tunnel to test
	//   - messageID: unique identifier for the test message (used for response correlation)
	// Returns error if the message could not be sent.
	SendTestMessage(tunnelID TunnelID, messageID uint32) error
}

// pendingTest tracks an in-progress tunnel test
type pendingTest struct {
	tunnelID  TunnelID
	startTime time.Time
	done      chan error
}

// TunnelTester validates tunnel health and performance.
// It sends test messages through tunnels and measures latency,
// enabling automatic detection of failed or slow tunnels.
//
// Design decisions:
// - Uses DeliveryStatus messages for echo-based testing
// - Correlates responses using unique message IDs
// - Configurable timeout (default 5 seconds)
// - Latency tracking for tunnel selection optimization
// - Thread-safe for concurrent testing of multiple tunnels
type TunnelTester struct {
	pool         *Pool
	sender       TunnelMessageSender
	timeout      time.Duration
	mu           sync.Mutex
	pendingTests map[uint32]*pendingTest // messageID -> pendingTest
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
// Use SetMessageSender to enable real I2NP-based testing.
func NewTunnelTester(pool *Pool) *TunnelTester {
	return &TunnelTester{
		pool:         pool,
		timeout:      5 * time.Second,
		pendingTests: make(map[uint32]*pendingTest),
	}
}

// SetMessageSender configures the message sender for real tunnel testing.
// Without a sender configured, tests will use age-based health estimation.
//
// Parameters:
// - sender: implementation of TunnelMessageSender (typically provided by router)
func (tt *TunnelTester) SetMessageSender(sender TunnelMessageSender) {
	tt.mu.Lock()
	defer tt.mu.Unlock()
	tt.sender = sender
	log.WithField("at", "TunnelTester.SetMessageSender").Debug("Message sender configured for real tunnel testing")
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

	// Check if we have a message sender for real testing
	if tt.sender != nil {
		return tt.performRealEchoTest(tunnel, timeout)
	}

	// Fallback: age-based health estimation when no sender is configured
	return tt.performAgeBasedTest(tunnel, timeout)
}

// generateTestMessageID creates a cryptographically random 32-bit message ID
// for correlating test requests with responses.
func (tt *TunnelTester) generateTestMessageID() (uint32, error) {
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, fmt.Errorf("failed to generate random message ID: %w", err)
	}
	return binary.BigEndian.Uint32(buf[:]), nil
}

// performRealEchoTest sends an actual DeliveryStatus message through the tunnel
// and waits for a response to measure real round-trip latency.
func (tt *TunnelTester) performRealEchoTest(tunnel *TunnelState, timeout time.Duration) error {
	// Generate unique message ID for this test
	messageID, err := tt.generateTestMessageID()
	if err != nil {
		return err
	}

	// Create pending test entry
	pending := &pendingTest{
		tunnelID:  tunnel.ID,
		startTime: time.Now(),
		done:      make(chan error, 1),
	}

	// Register the pending test
	tt.mu.Lock()
	tt.pendingTests[messageID] = pending
	tt.mu.Unlock()

	// Ensure cleanup
	defer func() {
		tt.mu.Lock()
		delete(tt.pendingTests, messageID)
		tt.mu.Unlock()
	}()

	// Send the test message
	if err := tt.sender.SendTestMessage(tunnel.ID, messageID); err != nil {
		log.WithFields(map[string]interface{}{
			"at":         "TunnelTester.performRealEchoTest",
			"tunnel_id":  tunnel.ID,
			"message_id": messageID,
			"error":      err,
		}).Warn("Failed to send test message")
		return fmt.Errorf("failed to send test message: %w", err)
	}

	log.WithFields(map[string]interface{}{
		"at":         "TunnelTester.performRealEchoTest",
		"tunnel_id":  tunnel.ID,
		"message_id": messageID,
	}).Debug("Test message sent, waiting for response")

	// Wait for response or timeout
	select {
	case err := <-pending.done:
		return err
	case <-time.After(timeout):
		log.WithFields(map[string]interface{}{
			"at":         "TunnelTester.performRealEchoTest",
			"tunnel_id":  tunnel.ID,
			"message_id": messageID,
			"timeout":    timeout,
		}).Warn("Tunnel test timeout")
		return fmt.Errorf("tunnel test timeout after %v", timeout)
	}
}

// HandleTestResponse processes a DeliveryStatus response for a pending test.
// This should be called by the message router when a DeliveryStatus message
// is received that matches a pending test message ID.
//
// Parameters:
// - messageID: the message ID from the DeliveryStatus response
//
// Returns true if the message was for a pending test, false otherwise.
func (tt *TunnelTester) HandleTestResponse(messageID uint32) bool {
	tt.mu.Lock()
	pending, exists := tt.pendingTests[messageID]
	tt.mu.Unlock()

	if !exists {
		return false
	}

	// Signal successful completion
	select {
	case pending.done <- nil:
		log.WithFields(map[string]interface{}{
			"at":         "TunnelTester.HandleTestResponse",
			"tunnel_id":  pending.tunnelID,
			"message_id": messageID,
			"latency":    time.Since(pending.startTime),
		}).Debug("Test response received")
	default:
		// Channel already closed or full
	}

	return true
}

// performAgeBasedTest uses tunnel age as a proxy for health when no message sender
// is configured. This is a fallback for situations where real testing isn't available.
func (tt *TunnelTester) performAgeBasedTest(tunnel *TunnelState, timeout time.Duration) error {
	testChan := make(chan error, 1)

	go func() {
		age := time.Since(tunnel.CreatedAt)

		// Tunnels near expiration (within 1 minute of 10-minute lifetime) are less reliable
		if age > 9*time.Minute {
			testChan <- fmt.Errorf("tunnel near expiration (age: %v)", age)
		} else {
			// Minimal delay to simulate test overhead
			time.Sleep(10 * time.Millisecond)
			testChan <- nil
		}
	}()

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

// TestAllTunnelsAsync tests all ready tunnels in the pool concurrently.
// This avoids the O(n * timeout) latency of sequential testing.
// The results are collected and returned in no particular order.
func (tt *TunnelTester) TestAllTunnelsAsync() []TunnelTestResult {
	tt.pool.mutex.RLock()
	tunnelIDs := make([]TunnelID, 0, len(tt.pool.tunnels))
	for id, tunnel := range tt.pool.tunnels {
		if tunnel.State == TunnelReady {
			tunnelIDs = append(tunnelIDs, id)
		}
	}
	tt.pool.mutex.RUnlock()

	if len(tunnelIDs) == 0 {
		return nil
	}

	resultCh := make(chan TunnelTestResult, len(tunnelIDs))
	var wg sync.WaitGroup
	for _, id := range tunnelIDs {
		wg.Add(1)
		go func(tid TunnelID) {
			defer wg.Done()
			resultCh <- tt.TestTunnel(tid)
		}(id)
	}
	wg.Wait()
	close(resultCh)

	results := make([]TunnelTestResult, 0, len(tunnelIDs))
	for r := range resultCh {
		results = append(results, r)
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

	tt.countTunnelsByState(&check)
	tt.analyzeTestResults(&check, results)

	log.WithFields(map[string]interface{}{
		"total":           check.TotalTunnels,
		"ready":           check.ReadyTunnels,
		"healthy":         check.HealthyTunnels,
		"unhealthy":       check.UnhealthyTunnels,
		"average_latency": check.AverageLatency,
	}).Info("Tunnel pool health check completed")

	return check
}

// countTunnelsByState counts tunnels by their state in the pool.
func (tt *TunnelTester) countTunnelsByState(check *HealthCheckResult) {
	tt.pool.mutex.RLock()
	check.TotalTunnels = len(tt.pool.tunnels)
	for _, tunnel := range tt.pool.tunnels {
		if tunnel.State == TunnelReady {
			check.ReadyTunnels++
		}
	}
	tt.pool.mutex.RUnlock()
}

// analyzeTestResults analyzes test results to determine tunnel health statistics.
func (tt *TunnelTester) analyzeTestResults(check *HealthCheckResult, results []TunnelTestResult) {
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

	if check.HealthyTunnels > 0 {
		check.AverageLatency = totalLatency / time.Duration(check.HealthyTunnels)
	}
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
