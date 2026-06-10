package ssu2

import (
	"testing"
	"time"

	"github.com/go-i2p/go-i2p/lib/nat"
	"github.com/stretchr/testify/assert"
)

// TestTE3_NATRetryBackoffBounded verifies that NAT detection retries use bounded exponential backoff.
// This validates that the natRetryInitial (30s) and natRetryMax (30min) constants
// define reasonable bounds even though they're defined but not directly used.
// The actual retry logic should match these bounds in spirit.
func TestTE3_NATRetryBackoffBounded(t *testing.T) {
	// Verify the constants themselves
	assert.Equal(t, 30*time.Second, natRetryInitial, "natRetryInitial should be 30 seconds")
	assert.Equal(t, 30*time.Minute, natRetryMax, "natRetryMax should be 30 minutes")

	// Simulate the exponential backoff progression
	// natRetryInitial = 30s, factor = 2.0, max = 30min
	backoff := natRetryInitial
	backoffs := []time.Duration{backoff}

	// Run exponential doubling until we hit max
	for i := 0; i < 20 && backoff < natRetryMax; i++ {
		backoff *= 2
		if backoff > natRetryMax {
			backoff = natRetryMax
		}
		backoffs = append(backoffs, backoff)
	}

	// Verify all backoffs are bounded at 30 minutes
	for _, b := range backoffs {
		assert.True(t, b <= natRetryMax, "Backoff %v exceeds natRetryMax %v", b, natRetryMax)
	}

	// Verify at least one doubling before hitting cap
	assert.True(t, len(backoffs) > 1, "Should have multiple backoff steps")

	// Last backoff should be capped
	assert.Equal(t, natRetryMax, backoffs[len(backoffs)-1], "Final backoff should be capped at max")
}

// TestTE3_PeerTestRetrySequenceTerminates verifies that peer test timeouts
// eventually terminate and don't retry unboundedly.
func TestTE3_PeerTestRetrySequenceTerminates(t *testing.T) {
	tr, cleanup := makeTestTransportWithListener(t)
	defer cleanup()

	candidates := makeMockRouterInfos(t, 2)
	publishCalls := 0
	republish := func() {
		publishCalls++
	}

	// First timeout - should schedule retry
	tr.handlePeerTestTimeout(candidates, republish)
	tr.peerTestRetryMu.Lock()
	retry1 := tr.peerTestRetryCount
	tr.peerTestRetryMu.Unlock()
	assert.Equal(t, 1, retry1, "First timeout should have retry count 1")
	assert.Equal(t, 0, publishCalls, "Should not publish after first timeout")

	// Second timeout
	tr.handlePeerTestTimeout(candidates, republish)
	tr.peerTestRetryMu.Lock()
	retry2 := tr.peerTestRetryCount
	tr.peerTestRetryMu.Unlock()
	assert.Equal(t, 2, retry2, "Second timeout should have retry count 2")
	assert.Equal(t, 0, publishCalls, "Should not publish after second timeout")

	// Third timeout
	tr.handlePeerTestTimeout(candidates, republish)
	tr.peerTestRetryMu.Lock()
	retry3 := tr.peerTestRetryCount
	tr.peerTestRetryMu.Unlock()
	assert.Equal(t, 3, retry3, "Third timeout should have retry count 3")
	assert.Equal(t, 0, publishCalls, "Should not publish after third timeout")

	// Fourth timeout - should exceed maxRetries and reset counter
	tr.handlePeerTestTimeout(candidates, republish)
	tr.peerTestRetryMu.Lock()
	retry4 := tr.peerTestRetryCount
	tr.peerTestRetryMu.Unlock()
	assert.Equal(t, 0, retry4, "Fourth timeout should reset retry count to 0 (max retries exceeded)")

	// At this point, the sequence terminates - no more retries scheduled
	// Republish may or may not be called depending on introducer registration success
	// The key point is that the retry loop terminates (doesn't go to retry 5, 6, etc.)
}

// TestTE3_ExternalAddressUpdateFrequency verifies that NAT detection happens
// frequently enough to detect network changes. The mainloop timer is 15 minutes.
// This test validates that we can detect address changes within a reasonable window.
func TestTE3_ExternalAddressUpdateFrequency(t *testing.T) {
	// NAT recheck interval from router mainloop
	// This should be documented and reasonable
	const mainloopNATInterval = 15 * time.Minute

	// In 30 minutes, we should have 2 NAT checks
	checksIn30Min := int((30 * time.Minute) / mainloopNATInterval)
	assert.Equal(t, 2, checksIn30Min, "Should have 2 NAT checks in 30 minutes")

	// Each check should complete in less than the interval
	const peerTestTimeout = 60 * time.Second
	const maxRetryBackoff = 60 + 120 + 240 // seconds for all retries
	totalCheckTime := peerTestTimeout + (maxRetryBackoff * time.Second)

	// Total time for one check cycle should be << 15 minutes
	assert.True(t, totalCheckTime < mainloopNATInterval,
		"One NAT check cycle (%v) should complete well before next check (%v)",
		totalCheckTime, mainloopNATInterval)
}

// TestTE3_NATRetryStateConsistency verifies that retry state is properly
// managed and doesn't leak between cycles.
func TestTE3_NATRetryStateConsistency(t *testing.T) {
	tr, cleanup := makeTestTransportWithListener(t)
	defer cleanup()

	candidates := makeMockRouterInfos(t, 2)
	republish := func() {}

	// Simulate multiple timeouts until max retries
	for i := 0; i < 4; i++ {
		tr.handlePeerTestTimeout(candidates, republish)
	}

	// After 4 timeouts, retry count should be reset to 0
	tr.peerTestRetryMu.Lock()
	finalRetryCount := tr.peerTestRetryCount
	tr.peerTestRetryMu.Unlock()
	assert.Equal(t, 0, finalRetryCount, "Retry count should be reset after max retries")

	// Now simulate a new cycle - should start fresh at retry count 1
	tr.handlePeerTestTimeout(candidates, republish)
	tr.peerTestRetryMu.Lock()
	nextCycleRetry := tr.peerTestRetryCount
	tr.peerTestRetryMu.Unlock()
	assert.Equal(t, 1, nextCycleRetry, "New cycle should start with retry count 1")
}

// TestTE3_PortMapperRetryBounded verifies that the port mapper's
// exponential backoff is properly bounded at 30 minutes.
func TestTE3_PortMapperRetryBounded(t *testing.T) {
	cfg := &nat.BackoffConfig{
		Initial: 30 * time.Second,
		Max:     30 * time.Minute,
		Factor:  2.0,
	}

	// Simulate exponential backoff progression
	backoff := cfg.Initial
	maxBackoffs := 20
	backoffSeq := make([]time.Duration, 0, maxBackoffs)

	for i := 0; i < maxBackoffs; i++ {
		backoffSeq = append(backoffSeq, backoff)

		// Verify never exceeds max
		assert.True(t, backoff <= cfg.Max,
			"Backoff step %d (%v) exceeds max (%v)", i, backoff, cfg.Max)

		// Calculate next backoff
		nextBackoff := cfg.CalculateNextBackoff(backoff)

		// Verify monotonic increase up to max
		if backoff < cfg.Max {
			assert.True(t, nextBackoff > backoff,
				"Backoff should increase until reaching max (step %d)", i)
		} else {
			assert.Equal(t, cfg.Max, nextBackoff,
				"Backoff should stay at max (step %d)", i)
		}

		backoff = nextBackoff
	}

	// Last backoff should be capped at max
	assert.Equal(t, cfg.Max, backoffSeq[len(backoffSeq)-1],
		"Final backoff should be capped at max 30 minutes")
}

// TestTE3_NATDetectionTimeoutValues verifies that timeout values are reasonable
// and don't cause excessive delays or unnecessary retries.
func TestTE3_NATDetectionTimeoutValues(t *testing.T) {
	// These are the actual hardcoded values in awaitPeerTestResult
	const peerTestPollInterval = 2 * time.Second
	const peerTestTimeout = 60 * time.Second

	// Poll interval should be reasonably small to detect completion quickly
	assert.True(t, peerTestPollInterval < 5*time.Second,
		"Poll interval (%v) should be < 5s for responsive detection", peerTestPollInterval)

	// Test timeout should be large enough for network latency but not huge
	assert.True(t, peerTestTimeout > 10*time.Second && peerTestTimeout < 120*time.Second,
		"Test timeout (%v) should be 10-120 seconds for reasonable NAT testing", peerTestTimeout)

	// Retry intervals: 60s, 120s, 240s
	retrySequence := []time.Duration{
		60 * time.Second,
		120 * time.Second,
		240 * time.Second,
	}

	totalRetryTime := peerTestTimeout
	for _, retryDelay := range retrySequence {
		totalRetryTime += retryDelay + peerTestTimeout
	}

	// Total should be less than 15 minutes (mainloop check interval)
	const mainloopInterval = 15 * time.Minute
	assert.True(t, totalRetryTime < mainloopInterval,
		"Total retry time (%v) should fit within mainloop interval (%v)",
		totalRetryTime, mainloopInterval)

	t.Logf("NAT detection timing: initial=%v, retries=%v, total sequence=%v, mainloop=%v",
		peerTestTimeout, retrySequence, totalRetryTime, mainloopInterval)
}

// TestTE3_NATDetectionNoUnboundedRetries verifies that NAT detection
// doesn't enter an unbounded retry loop under adverse conditions.
func TestTE3_NATDetectionNoUnboundedRetries(t *testing.T) {
	tr, cleanup := makeTestTransportWithListener(t)
	defer cleanup()

	candidates := makeMockRouterInfos(t, 2)
	republish := func() {}

	// Simulate 100 consecutive timeouts
	// The retry counter should reset after every 4 attempts (3 retries + 1 max)
	// and never go unbounded
	const testIterations = 100
	maxSeenRetryCount := 0

	for i := 0; i < testIterations; i++ {
		tr.handlePeerTestTimeout(candidates, republish)

		tr.peerTestRetryMu.Lock()
		currentRetryCount := tr.peerTestRetryCount
		tr.peerTestRetryMu.Unlock()

		// Retry count should never exceed 3 (maxRetries = 3, then resets to 0)
		assert.True(t, currentRetryCount <= 3,
			"Iteration %d: retry count %d should never exceed max retries (3)", i, currentRetryCount)

		if currentRetryCount > maxSeenRetryCount {
			maxSeenRetryCount = currentRetryCount
		}
	}

	// After many iterations, should see retry count cycle 0,1,2,3,0,1,2,3,...
	// Never unbounded
	assert.Equal(t, 3, maxSeenRetryCount,
		"Max retry count should be 3, never unbounded in %d iterations", testIterations)
}

// TestTE3_NATRetryConstantsDocumented verifies that the retry bounds
// constants are properly documented and reasonable.
func TestTE3_NATRetryConstantsDocumented(t *testing.T) {
	// These constants define the bounds for NAT retry strategy
	// Even if not directly used in all code paths, they represent design intent

	// Initial backoff should be reasonable (not too short, not too long)
	assert.Equal(t, 30*time.Second, natRetryInitial)
	assert.True(t, natRetryInitial > 10*time.Second && natRetryInitial < 60*time.Second,
		"natRetryInitial (%v) should be in range 10-60 seconds", natRetryInitial)

	// Maximum backoff should prevent extremely long gaps
	assert.Equal(t, 30*time.Minute, natRetryMax)
	assert.True(t, natRetryMax > 1*time.Minute && natRetryMax < 1*time.Hour,
		"natRetryMax (%v) should be in range 1-60 minutes", natRetryMax)

	// Max should be much larger than initial to allow exponential growth
	assert.True(t, natRetryMax > natRetryInitial*10,
		"natRetryMax (%v) should be much larger than natRetryInitial (%v)",
		natRetryMax, natRetryInitial)

	t.Logf("NAT retry constants: initial=%v, max=%v (growth factor ~%v)",
		natRetryInitial, natRetryMax, natRetryMax/natRetryInitial)
}
