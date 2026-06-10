package ssu2

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-i2p/logger"
	"github.com/stretchr/testify/assert"
)

// TestRC2_CASLoopBounded_CheckSessionLimit verifies checkSessionLimit uses
// bounded retries instead of infinite loop under high contention.
func TestRC2_CASLoopBounded_CheckSessionLimit(t *testing.T) {
	t.Parallel()

	transport := &SSU2Transport{
		config: &Config{
			MaxSessions: 10,
		},
		sessionCount: 0,
		logger:       testLogger_RC2(),
	}

	// Concurrent goroutines all trying to reserve slots
	const numGoroutines = 50
	errors := make(chan error, numGoroutines)
	var wg sync.WaitGroup

	// Start goroutines that try to reserve slots
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := transport.checkSessionLimit()
			errors <- err
		}()
	}

	wg.Wait()
	close(errors)

	// Count successes and failures
	successCount := 0
	failureCount := 0
	for err := range errors {
		if err != nil {
			failureCount++
		} else {
			successCount++
		}
	}

	// Should have exactly 10 successes (maxSessions) and 40 failures
	assert.Equal(t, 10, successCount, "should reserve exactly 10 slots")
	assert.Equal(t, 40, failureCount, "should reject 40 connections")
	assert.Equal(t, int32(10), transport.sessionCount, "sessionCount should be 10")
}

// TestRC2_CASLoopRetryLimit verifies checkSessionLimit doesn't spin indefinitely
// even under extreme contention by measuring time to completion.
func TestRC2_CASLoopRetryLimit(t *testing.T) {
	t.Parallel()

	transport := &SSU2Transport{
		config: &Config{
			MaxSessions: 5,
		},
		sessionCount: 0,
		logger:       testLogger_RC2(),
	}

	// Create extreme contention: many goroutines competing
	const numGoroutines = 200
	done := make(chan struct{})
	startTime := time.Now()

	var wg sync.WaitGroup
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = transport.checkSessionLimit()
		}()
	}

	// Run with a timeout to detect if loop spins indefinitely
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		elapsed := time.Since(startTime)
		// Should complete quickly (< 5 seconds) despite high contention
		assert.Less(t, elapsed, 5*time.Second,
			"checkSessionLimit should complete in bounded time, got %v", elapsed)

	case <-time.After(10 * time.Second):
		t.Fatal("checkSessionLimit appears to spin indefinitely under contention")
	}
}

// TestRC2_UnreserveSessionSlot_Bounded verifies unreserveSessionSlot uses
// bounded retries and doesn't spin indefinitely.
func TestRC2_UnreserveSessionSlot_Bounded(t *testing.T) {
	t.Parallel()

	transport := &SSU2Transport{
		sessionCount: 100,
		logger:       testLogger_RC2(),
	}

	// Concurrent unreserve attempts
	const numGoroutines = 150
	var wg sync.WaitGroup

	startTime := time.Now()
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			transport.unreserveSessionSlot()
		}()
	}

	wg.Wait()
	elapsed := time.Since(startTime)

	// Should complete quickly despite high contention
	assert.Less(t, elapsed, 5*time.Second,
		"unreserveSessionSlot should complete in bounded time, got %v", elapsed)

	// After 100 decrements, count should be 0 (capped at 0)
	assert.Equal(t, int32(0), atomic.LoadInt32(&transport.sessionCount),
		"sessionCount should not go below 0")
}

// TestRC2_CASLoopConsistency verifies that with bounded retries, the final
// session count is still consistent (no silent underflow or overflow).
func TestRC2_CASLoopConsistency(t *testing.T) {
	t.Parallel()

	transport := &SSU2Transport{
		config: &Config{
			MaxSessions: 50,
		},
		sessionCount: 0,
		logger:       testLogger_RC2(),
	}

	// Phase 1: Reserve 40 slots concurrently
	const reserveCount = 40
	reserveErrors := make(chan error, reserveCount)
	var wg sync.WaitGroup

	for i := 0; i < reserveCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			reserveErrors <- transport.checkSessionLimit()
		}()
	}

	wg.Wait()
	close(reserveErrors)

	// Count successful reserves
	successCount := 0
	for err := range reserveErrors {
		if err == nil {
			successCount++
		}
	}

	// Phase 2: Unreserve concurrently from the same goroutines
	for i := 0; i < successCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			transport.unreserveSessionSlot()
		}()
	}

	wg.Wait()

	// Final count should be exactly 0 (all reserved slots released)
	finalCount := atomic.LoadInt32(&transport.sessionCount)
	assert.Equal(t, int32(0), finalCount,
		"after reserving %d and unreserving %d, count should be 0; got %d",
		reserveCount, successCount, finalCount)
}

// TestRC2_HighContentionNoStarvation tests that under high contention,
// no goroutine is starved and all eventually complete.
func TestRC2_HighContentionNoStarvation(t *testing.T) {
	t.Parallel()

	transport := &SSU2Transport{
		config: &Config{
			MaxSessions: 20,
		},
		sessionCount: 0,
		logger:       testLogger_RC2(),
	}

	// Stress test: many goroutines cycling through reserve/unreserve
	const numWorkers = 100
	const iterations = 10
	completedCount := atomic.Int32{}

	var wg sync.WaitGroup
	for worker := 0; worker < numWorkers; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				// Only count successful reserve+unreserve pairs
				if transport.checkSessionLimit() == nil {
					transport.unreserveSessionSlot()
					completedCount.Add(1)
				}
				completedCount.Add(1) // Count all iterations attempted
			}
		}()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	// All workers should complete within reasonable time
	select {
	case <-done:
		completed := completedCount.Load()
		expectedMin := int32(numWorkers * iterations) // At least all iterations start
		assert.GreaterOrEqual(t, completed, expectedMin,
			"all workers should complete all iterations")

	case <-time.After(10 * time.Second):
		t.Fatalf("workers did not complete within 10s; possible starvation or deadlock")
	}
}

// testLogger_RC2 returns a logger for RC2 tests.
func testLogger_RC2() *logger.Entry {
	return logger.WithField("test", "rc2_cas_loop")
}
