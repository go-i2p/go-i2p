package ssu2

import (
	"testing"
	"time"

	ssu2noise "github.com/go-i2p/go-noise/ssu2"
	"github.com/stretchr/testify/assert"
)

// TestRD2_ExternalCacheTTLExpiration validates that getExternal respects natResultTTL
func TestRD2_ExternalCacheTTLExpiration(t *testing.T) {
	addr := "1.2.3.4:5678"
	ns := &natState{}

	// Record observations and get confirmation
	ns.recordObservation(addr, 1)
	ns.recordObservation(addr, 2)
	ns.recordObservation(addr, 3)

	// Set the confirmed address
	ns.set(ssu2noise.NATCone, addr)

	// Immediately, getExternal should return the address
	result := ns.getExternal()
	assert.Equal(t, addr, result)

	// Simulate cache expiration by manipulating updated timestamp
	ns.mu.Lock()
	ns.updated = time.Now().Add(-natResultTTL - time.Second)
	ns.mu.Unlock()

	// Now getExternal should return empty string (expired)
	result = ns.getExternal()
	assert.Equal(t, "", result)
}

// TestRD2_ObservationWindowPruning validates observations are pruned after peerTestObservationWindow
func TestRD2_ObservationWindowPruning(t *testing.T) {
	addr1 := "1.2.3.4:5678"
	addr2 := "5.6.7.8:5678"
	ns := &natState{}

	// Record first set of observations
	ns.recordObservation(addr1, 1)
	ns.recordObservation(addr1, 2)
	ns.recordObservation(addr1, 3)

	// Check observations are recorded
	ns.mu.Lock()
	observationCount := len(ns.observations)
	ns.mu.Unlock()
	assert.Equal(t, 3, observationCount)

	// Backdate existing observations past the window
	ns.mu.Lock()
	for i := range ns.observations {
		ns.observations[i].at = time.Now().Add(-peerTestObservationWindow - time.Second)
	}
	ns.mu.Unlock()

	// Record a new observation - this should prune the old ones
	ns.recordObservation(addr2, 4)

	// Check only the new observation remains
	ns.mu.Lock()
	observationCount = len(ns.observations)
	ns.mu.Unlock()
	assert.Equal(t, 1, observationCount)
}

// TestRD2_CompletedNoncesMemoryLeak documents the memory leak in completedNonces
// This test verifies that completedNonces grows unbounded and is never pruned
func TestRD2_CompletedNoncesMemoryLeak(t *testing.T) {
	addr := "1.2.3.4:5678"
	ns := &natState{}

	// Record many observations with different nonces
	const maxNonces = 1000
	for nonce := uint32(0); nonce < maxNonces; nonce++ {
		ns.recordObservation(addr, nonce)
	}

	// Check completedNonces map size
	ns.mu.Lock()
	noncesCount := len(ns.completedNonces)
	ns.mu.Unlock()

	// All nonces should be in the map (memory leak - no cleanup)
	assert.Equal(t, maxNonces, noncesCount)
	t.Logf("ISSUE: completedNonces map has %d entries with NO cleanup - memory leak in long-running router", noncesCount)
}

// TestRD2_CompletedNoncesNeverPruned verifies that nonces persist even after their observations are pruned
func TestRD2_CompletedNoncesNeverPruned(t *testing.T) {
	addr := "1.2.3.4:5678"
	ns := &natState{}

	// Record observations with old nonces
	for nonce := uint32(1); nonce <= 10; nonce++ {
		ns.recordObservation(addr, nonce)
	}

	ns.mu.Lock()
	noncesCountBefore := len(ns.completedNonces)
	ns.mu.Unlock()

	// Backdate observations so they'll be pruned
	ns.mu.Lock()
	for i := range ns.observations {
		ns.observations[i].at = time.Now().Add(-peerTestObservationWindow - time.Second)
	}
	ns.mu.Unlock()

	// Record new observation - this prunes old observations
	ns.recordObservation(addr, 11)

	ns.mu.Lock()
	noncesCountAfter := len(ns.completedNonces)
	ns.mu.Unlock()

	// Observations should be pruned but nonces persist
	assert.Equal(t, noncesCountBefore, 10)
	assert.Equal(t, noncesCountAfter, 11)
	t.Logf("ISSUE: Even though observations pruned, completedNonces keeps growing: %d → %d", noncesCountBefore, noncesCountAfter)
}

// TestRD2_NetworkRebindingScenario simulates address change detection
func TestRD2_NetworkRebindingScenario(t *testing.T) {
	addr1 := "1.2.3.4:5678"
	addr2 := "10.0.0.1:9876"
	ns := &natState{}

	// Phase 1: Record observations for address 1
	ns.recordObservation(addr1, 1)
	ns.recordObservation(addr1, 2)
	confirmed1 := ns.recordObservation(addr1, 3)
	assert.Equal(t, addr1, confirmed1)

	// Cache the result
	ns.set(ssu2noise.NATCone, addr1)
	assert.Equal(t, addr1, ns.getExternal())

	// Phase 2: Network rebinds - start recording new address
	// First, need to get past the observation window for old observations
	ns.mu.Lock()
	for i := range ns.observations {
		ns.observations[i].at = time.Now().Add(-peerTestObservationWindow - time.Second)
	}
	ns.mu.Unlock()

	// Now record new observations for addr2 - old ones will be pruned
	ns.recordObservation(addr2, 4)
	ns.recordObservation(addr2, 5)
	confirmed2 := ns.recordObservation(addr2, 6)
	assert.Equal(t, addr2, confirmed2)

	// Update cache with new address
	ns.set(ssu2noise.NATCone, addr2)
	assert.Equal(t, addr2, ns.getExternal())

	// Phase 3: Cache should eventually expire
	ns.mu.Lock()
	ns.updated = time.Now().Add(-natResultTTL - time.Second)
	ns.mu.Unlock()
	assert.Equal(t, "", ns.getExternal())
}

// TestRD2_StaleObservationDoesNotPollutCache validates that pruned observations
// don't influence the cached result after their window expires
func TestRD2_StaleObservationDoesNotPollutCache(t *testing.T) {
	addr1 := "1.2.3.4:5678"
	addr2 := "10.0.0.1:9876"
	ns := &natState{}

	// Record 3 observations for addr1 and confirm them
	ns.recordObservation(addr1, 1)
	ns.recordObservation(addr1, 2)
	confirmed1 := ns.recordObservation(addr1, 3)
	assert.Equal(t, addr1, confirmed1)

	// Cache it
	ns.set(ssu2noise.NATCone, addr1)

	// Backdate those observations past the window
	ns.mu.Lock()
	for i := range ns.observations {
		ns.observations[i].at = time.Now().Add(-peerTestObservationWindow - time.Second)
	}
	ns.mu.Unlock()

	// Record new observations for addr2
	ns.recordObservation(addr2, 4)
	ns.recordObservation(addr2, 5)
	confirmed2 := ns.recordObservation(addr2, 6)

	// addr2 should be confirmed (not influenced by pruned addr1 observations)
	assert.Equal(t, addr2, confirmed2)

	// Verify only new observations remain
	ns.mu.Lock()
	obsCounts := make(map[string]int)
	for _, obs := range ns.observations {
		obsCounts[obs.addr]++
	}
	ns.mu.Unlock()

	// Should only have observations for addr2 (old addr1 obs were pruned)
	assert.Equal(t, 3, obsCounts[addr2])
	assert.Equal(t, 0, obsCounts[addr1])
}

// TestRD2_DuplicateNonceRejection validates that same nonce only counted once (RD-1 fix)
func TestRD2_DuplicateNonceRejection(t *testing.T) {
	addr := "1.2.3.4:5678"
	ns := &natState{}

	// Try to record multiple observations with same nonce
	ns.recordObservation(addr, 1) // First recording succeeds
	ns.recordObservation(addr, 1) // Attempt duplicate - should be rejected

	// Same nonce should only appear once in completedNonces
	ns.mu.Lock()
	noncesCount := len(ns.completedNonces)
	ns.mu.Unlock()
	assert.Equal(t, 1, noncesCount)

	// Only one observation should be recorded for the duplicate nonce
	ns.mu.Lock()
	obsCount := len(ns.observations)
	ns.mu.Unlock()
	assert.Equal(t, 1, obsCount)
}

// TestRD2_CacheInvalidationAfterExpiry simulates cache expiring and requiring fresh observations
func TestRD2_CacheInvalidationAfterExpiry(t *testing.T) {
	addr1 := "1.2.3.4:5678"
	addr2 := "5.6.7.8:5678"
	ns := &natState{}

	// Record and cache address 1
	ns.recordObservation(addr1, 1)
	ns.recordObservation(addr1, 2)
	ns.recordObservation(addr1, 3)
	ns.set(ssu2noise.NATCone, addr1)

	// Cache is valid
	assert.Equal(t, addr1, ns.getExternal())

	// Expire the cache
	ns.mu.Lock()
	ns.updated = time.Now().Add(-natResultTTL - time.Second)
	// Also age the observations so they get pruned when we record new ones
	for i := range ns.observations {
		ns.observations[i].at = time.Now().Add(-peerTestObservationWindow - time.Second)
	}
	ns.mu.Unlock()

	// Cache now returns empty
	assert.Equal(t, "", ns.getExternal())

	// Record new observations - old ones will be pruned due to age
	ns.recordObservation(addr2, 4)
	ns.recordObservation(addr2, 5)

	// Cache should still be empty
	assert.Equal(t, "", ns.getExternal())

	// Third observation meets threshold
	result := ns.recordObservation(addr2, 6)
	assert.Equal(t, addr2, result)

	// Update cache with new result
	ns.set(ssu2noise.NATCone, addr2)
	assert.Equal(t, addr2, ns.getExternal())
}

// TestRD2_ObservationsTTLWithoutCacheTTL verifies observations can expire while cache remains valid
func TestRD2_ObservationsTTLWithoutCacheTTL(t *testing.T) {
	addr := "1.2.3.4:5678"
	ns := &natState{}

	// Record observations to get confirmation
	ns.recordObservation(addr, 1)
	ns.recordObservation(addr, 2)
	ns.recordObservation(addr, 3)

	// Cache the result
	ns.set(ssu2noise.NATCone, addr)

	// Backdate observations past their window but keep cache TTL recent
	ns.mu.Lock()
	for i := range ns.observations {
		ns.observations[i].at = time.Now().Add(-peerTestObservationWindow - time.Second)
	}
	// Keep updated time recent (within cache TTL)
	ns.updated = time.Now().Add(-5 * time.Minute)
	ns.mu.Unlock()

	// Observations are stale but still in memory
	ns.mu.Lock()
	obsCount := len(ns.observations)
	ns.mu.Unlock()
	assert.Greater(t, obsCount, 0)

	// Record new observation - old ones should be pruned
	ns.recordObservation(addr, 4)

	ns.mu.Lock()
	obsCount = len(ns.observations)
	ns.mu.Unlock()
	assert.Equal(t, 1, obsCount)

	// Cache should still be valid (within TTL)
	assert.Equal(t, addr, ns.getExternal())
}

// TestRD2_MultipleAddressCyclesGrowCompletedNonces simulates long-running router with address changes
func TestRD2_MultipleAddressCyclesGrowCompletedNonces(t *testing.T) {
	addresses := []string{
		"1.2.3.4:5678",
		"10.0.0.1:9876",
		"172.16.0.1:1234",
		"192.168.1.1:5555",
	}

	ns := &natState{}
	nonceCounter := uint32(1)

	for _, addr := range addresses {
		// Age previous observations past the window
		ns.mu.Lock()
		for i := range ns.observations {
			ns.observations[i].at = time.Now().Add(-peerTestObservationWindow - time.Second)
		}
		ns.mu.Unlock()

		// Record observations for new address - old ones will be pruned
		ns.recordObservation(addr, nonceCounter)
		nonceCounter++
		ns.recordObservation(addr, nonceCounter)
		nonceCounter++
		confirmed := ns.recordObservation(addr, nonceCounter)
		nonceCounter++

		assert.Equal(t, addr, confirmed)

		// Cache it
		ns.set(ssu2noise.NATCone, addr)
		assert.Equal(t, addr, ns.getExternal())
	}

	// Verify completedNonces grows (memory leak - no pruning)
	ns.mu.Lock()
	noncesCount := len(ns.completedNonces)
	ns.mu.Unlock()

	// After 4 address cycles with 3 observations each = 12 nonces
	assert.Equal(t, 12, noncesCount)
	t.Logf("After %d address cycles, completedNonces: %d entries (MEMORY LEAK - should be pruned)", len(addresses), noncesCount)
}

// TestRD2_TTLWindow Validating the expected TTL windows are reasonable
func TestRD2_TTLWindowsReasonable(t *testing.T) {
	// peerTestObservationWindow = 10 minutes (line 27)
	assert.Equal(t, 10*time.Minute, peerTestObservationWindow)

	// natResultTTL = 30 minutes (line 20)
	assert.Equal(t, 30*time.Minute, natResultTTL)

	// peerTestConfirmThreshold = 3 (line 33)
	assert.Equal(t, 3, peerTestConfirmThreshold)

	t.Logf("TTL Windows: observationWindow=%v, resultTTL=%v, threshold=%d",
		peerTestObservationWindow, natResultTTL, peerTestConfirmThreshold)
}

// TestRD2_CompletedNoncesPruningFixed_WithAging verifies nonce pruning by aging nonce timestamps
func TestRD2_CompletedNoncesPruningFixed_WithAging(t *testing.T) {
	addr := "1.2.3.4:5678"
	ns := &natState{}

	// Record observations with recent nonces
	for nonce := uint32(1); nonce <= 10; nonce++ {
		ns.recordObservation(addr, nonce)
	}

	ns.mu.Lock()
	noncesCountBefore := len(ns.completedNonces)
	ns.mu.Unlock()
	assert.Equal(t, 10, noncesCountBefore)

	// Age nonces past the window by manipulating their timestamps
	ns.mu.Lock()
	cutoffTime := time.Now().Add(-peerTestObservationWindow - time.Second)
	for nonce := range ns.completedNonces {
		ns.completedNonces[nonce] = cutoffTime
	}
	ns.mu.Unlock()

	// Record new observation - this should trigger pruning of old nonces
	ns.recordObservation(addr, 11)

	ns.mu.Lock()
	noncesCountAfter := len(ns.completedNonces)
	ns.mu.Unlock()

	// Old nonces (1-10) should be pruned, only nonce 11 remains
	assert.Equal(t, 1, noncesCountAfter)
	t.Logf("FIX VALIDATED: Old nonces pruned: %d → %d (10 nonces removed)", noncesCountBefore, noncesCountAfter)
}
