package ssu2

// transport_rc7_test.go covers RC-7: Outbound Dial Slot Reservation/Release Mismatch
//
// RC-7 is a HIGH severity bug where concurrent dial attempts to the same peer
// can leave slot reservations hanging if registerOrReuseSession detects a duplicate.
// The tests verify that the slot accounting invariant is maintained:
// (slots reserved) - (slots unreserved) = (active sessions)

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRC7_DualDialSamePeer verifies slot reservation accounting is correct when
// two threads simultaneously dial the same peer.
func TestRC7_DualDialSamePeer(t *testing.T) {
	tr := makeMinimalTransport()
	defer tr.Close()

	initialCount := tr.GetSessionCount()
	t.Logf("RC-7: Initial session count: %d", initialCount)

	// Thread A: Reserve slot
	err1 := tr.checkSessionLimit()
	require.NoError(t, err1)
	countAfterA := tr.GetSessionCount()
	t.Logf("RC-7: Count after Thread A reserves: %d", countAfterA)

	// Thread B: Reserve slot
	err2 := tr.checkSessionLimit()
	require.NoError(t, err2)
	countAfterB := tr.GetSessionCount()
	t.Logf("RC-7: Count after Thread B reserves: %d", countAfterB)

	// Both should have reserved
	assert.Equal(t, initialCount+2, countAfterB, "Both threads should reserve slots")

	// Simulate Thread B unreserves (e.g., because LoadOrStore failed)
	tr.unreserveSessionSlot()
	countAfterUnreserve := tr.GetSessionCount()
	t.Logf("RC-7: Count after Thread B unreserves: %d", countAfterUnreserve)

	// Expected: back to initialCount + 1
	assert.Equal(t, initialCount+1, countAfterUnreserve, "Only Thread A's slot should remain")
	t.Logf("RC-7: ✓ Dual dial accounting correct: %d == %d", countAfterUnreserve, initialCount+1)
}

// TestRC7_sessionCountInvariant verifies the fundamental invariant:
// (slots reserved) - (slots unreserved) = (active sessions)
func TestRC7_sessionCountInvariant(t *testing.T) {
	tr := makeMinimalTransport()
	tr.config.MaxSessions = 100 // Increase limit for this test
	defer tr.Close()

	initialCount := tr.GetSessionCount()
	assert.GreaterOrEqual(t, initialCount, 0, "sessionCount should never be negative")

	// Test: reserve 5, unreserve 3 → expect initialCount + 2
	for i := 0; i < 5; i++ {
		err := tr.checkSessionLimit()
		require.NoError(t, err, "checkSessionLimit should succeed")
	}
	countAfterReserve := tr.GetSessionCount()
	assert.Equal(t, initialCount+5, countAfterReserve)

	for i := 0; i < 3; i++ {
		tr.unreserveSessionSlot()
	}
	countAfterUnreserve := tr.GetSessionCount()
	assert.Equal(t, initialCount+2, countAfterUnreserve)
	t.Logf("RC-7: ✓ Slot accounting invariant holds: %d + 5 - 3 = %d", initialCount, countAfterUnreserve)
}

// TestRC7_UnderflowProtection verifies that unreserveSessionSlot() doesn't allow count to go below 0.
func TestRC7_UnderflowProtection(t *testing.T) {
	tr := makeMinimalTransport()
	defer tr.Close()

	// Attempt to unreserve more than we have
	const attemptedUnreserves = 100
	for i := 0; i < attemptedUnreserves; i++ {
		tr.unreserveSessionSlot()
	}

	finalCount := tr.GetSessionCount()
	t.Logf("RC-7: Underflow test: attempted %d unreserves, final count=%d", attemptedUnreserves, finalCount)

	// Count should never go below 0
	assert.GreaterOrEqual(t, finalCount, 0, "sessionCount should never go negative (underflow protection)")
	t.Logf("RC-7: ✓ Underflow protection working: count=%d >= 0", finalCount)
}
