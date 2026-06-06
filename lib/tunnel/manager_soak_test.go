package tunnel

import (
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSoak_ParticipantChurnNoResourceLeak verifies that repeated tunnel
// build/expire cycles do not leak goroutines or accumulate participants in
// the manager's map. This is a bounded soak test simulating week-long uptime
// under constant transit traffic.
//
// This test addresses audit finding M4: "No soak/stability test for week-long
// uptime resource growth on transit/build churn."
//
// Test strategy:
//  1. Measure baseline goroutine count and participant count (should be 0)
//  2. Execute 10,000 add/expire cycles:
//     a. Add batch of participants
//     b. Mark some as expired (simulate lifetime expiry)
//     c. Mark some as idle (simulate inactive tunnels)
//     d. Trigger cleanup
//     e. Verify removal
//  3. Wait for final cleanup pass
//  4. Assert goroutine count returns to baseline (±tolerance for runtime jitter)
//  5. Assert participant table is empty
//
// Validation criteria (per audit requirement):
// - Goroutine count returns to baseline after all cycles complete
// - Participant table size returns to zero (no accumulation)
// - Test completes without hanging or panicking under -race detector
//
// This test runs 10k cycles representing ~7 days of 10-minute tunnel lifetimes:
//
//	7 days * 24 hours * 6 cycles/hour = 1,008 cycles
//	10,000 cycles ≈ 10x margin for detecting slow leaks
func TestSoak_ParticipantChurnNoResourceLeak(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping soak test in short mode")
	}

	const (
		totalCycles       = 10000 // Simulate ~10x week-long uptime
		batchSize         = 10    // Participants per cycle
		expiredRatio      = 0.3   // 30% expire naturally
		idleRatio         = 0.2   // 20% become idle
		goroutineJitter   = 5     // Allow ±5 goroutines for runtime noise
		cleanupWaitPeriod = 2 * time.Second
	)

	// Phase 0: Measure baseline
	runtime.GC() // Force GC to stabilize baseline
	time.Sleep(50 * time.Millisecond)
	baselineGoroutines := runtime.NumGoroutine()

	// Phase 1: Create manager (spawns cleanup goroutine)
	m := NewManager()
	defer m.Stop()

	// Allow cleanup goroutine to start
	time.Sleep(10 * time.Millisecond)
	startGoroutines := runtime.NumGoroutine()
	expectedGoroutineDelta := startGoroutines - baselineGoroutines
	require.GreaterOrEqual(t, expectedGoroutineDelta, 1,
		"manager should spawn at least 1 cleanup goroutine (actual delta: %d)", expectedGoroutineDelta)
	require.LessOrEqual(t, expectedGoroutineDelta, 3,
		"manager should not spawn more than 3 background goroutines (actual delta: %d)", expectedGoroutineDelta)

	// Phase 2: Execute churn cycles
	for cycle := 0; cycle < totalCycles; cycle++ {
		// Add batch of participants
		participants := make([]*Participant, batchSize)
		for i := 0; i < batchSize; i++ {
			tunnelID := TunnelID((cycle * batchSize) + i + 1)
			p, err := NewParticipant(tunnelID, &mockTunnelEncryptor{})
			require.NoError(t, err)
			participants[i] = p
			err = m.AddParticipant(p)
			require.NoError(t, err)
		}

		// Simulate natural expiry for some participants
		expiredCount := int(float64(batchSize) * expiredRatio)
		for i := 0; i < expiredCount; i++ {
			p := participants[i]
			// Set creation time 11 minutes ago (past 10-minute lifetime)
			p.createdAt = time.Now().Add(-11 * time.Minute)
		}

		// Simulate idle tunnels (inactive for >2 minutes)
		idleStart := expiredCount
		idleEnd := idleStart + int(float64(batchSize)*idleRatio)
		for i := idleStart; i < idleEnd && i < batchSize; i++ {
			p := participants[i]
			p.lastActivity.Store(time.Now().Add(-3 * time.Minute).UnixNano())
		}

		// Trigger cleanup (normally runs every 60s, we trigger manually for speed)
		m.cleanupExpiredParticipants()

		// Verify expired and idle participants were removed
		removedCount := expiredCount + (idleEnd - idleStart)
		expectedRemaining := batchSize - removedCount
		actualRemaining := m.ParticipantCount()
		assert.Equal(t, expectedRemaining, actualRemaining,
			"cycle %d: expected %d remaining after cleanup, got %d",
			cycle, expectedRemaining, actualRemaining)

		// Remove remaining active participants to simulate tunnel completion
		for _, p := range participants {
			m.RemoveParticipant(p.TunnelID())
		}

		// Verify map is empty after full cycle
		assert.Equal(t, 0, m.ParticipantCount(),
			"cycle %d: participant map should be empty after removal", cycle)

		// Periodic GC to prevent memory accumulation from skewing goroutine count
		if cycle%1000 == 999 {
			runtime.GC()
		}

		// Progress indicator for long-running test
		if cycle%2000 == 1999 {
			t.Logf("completed %d/%d cycles", cycle+1, totalCycles)
		}
	}

	// Phase 3: Wait for final cleanup pass and verify no resource leaks
	time.Sleep(cleanupWaitPeriod)
	runtime.GC()
	time.Sleep(50 * time.Millisecond)

	finalGoroutines := runtime.NumGoroutine()
	finalParticipants := m.ParticipantCount()

	// Assertion 1: Participant table is empty (no accumulation)
	assert.Equal(t, 0, finalParticipants,
		"participant table must be empty after all cycles complete")

	// Assertion 2: Goroutine count returns to baseline (within jitter tolerance)
	goroutineDelta := finalGoroutines - startGoroutines
	assert.InDelta(t, 0, goroutineDelta, float64(goroutineJitter),
		"goroutine count should return to baseline ±%d (start=%d, final=%d, delta=%d)",
		goroutineJitter, startGoroutines, finalGoroutines, goroutineDelta)

	t.Logf("Soak test passed: %d cycles completed, participants=%d, goroutines=%d→%d (delta=%d)",
		totalCycles, finalParticipants, startGoroutines, finalGoroutines, goroutineDelta)
}

// TestSoak_ConcurrentChurnNoRace verifies that concurrent add/remove operations
// under heavy load do not produce race conditions. This complements the main
// soak test by stressing the mutex paths with parallel access.
func TestSoak_ConcurrentChurnNoRace(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping concurrent soak test in short mode")
	}

	const (
		numWorkers     = 20
		opsPerWorker   = 500
		shortLifetime  = 10 * time.Millisecond
		cleanupTrigger = 100 // Trigger cleanup every N ops
	)

	m := NewManager()
	defer m.Stop()

	done := make(chan bool, numWorkers)

	// Launch workers that concurrently add/remove participants
	for worker := 0; worker < numWorkers; worker++ {
		go func(id int) {
			for op := 0; op < opsPerWorker; op++ {
				tunnelID := TunnelID((id * opsPerWorker) + op + 1)

				// Add participant
				p, err := NewParticipant(tunnelID, &mockTunnelEncryptor{})
				if err != nil {
					t.Errorf("worker %d: failed to create participant: %v", id, err)
					continue
				}
				p.SetLifetime(shortLifetime)

				if err := m.AddParticipant(p); err != nil {
					t.Errorf("worker %d: failed to add participant %d: %v", id, tunnelID, err)
				}

				// Short delay to let some participants expire
				time.Sleep(shortLifetime + 5*time.Millisecond)

				// Trigger cleanup periodically
				if op%cleanupTrigger == 0 {
					m.cleanupExpiredParticipants()
				}

				// Attempt removal (may already be cleaned up)
				m.RemoveParticipant(tunnelID)
			}
			done <- true
		}(worker)
	}

	// Wait for all workers
	for i := 0; i < numWorkers; i++ {
		<-done
	}

	// Final cleanup
	m.cleanupExpiredParticipants()
	time.Sleep(100 * time.Millisecond)

	// Verify no participants remain
	finalCount := m.ParticipantCount()
	assert.Equal(t, 0, finalCount,
		"no participants should remain after concurrent churn completes")

	t.Logf("Concurrent soak test passed: %d workers × %d ops = %d total operations",
		numWorkers, opsPerWorker, numWorkers*opsPerWorker)
}
