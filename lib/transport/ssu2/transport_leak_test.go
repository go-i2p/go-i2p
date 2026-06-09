package ssu2

import (
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestL1_SetIdentity_NoGoroutineLeak verifies that calling SetIdentity multiple
// times does not leak NAT goroutines or managers (L-1 fix item 5).
// Each SetIdentity call should stop the old NAT goroutines before starting new ones.
func TestL1_SetIdentity_NoGoroutineLeak(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow goroutine leak test in short mode")
	}

	// Create a minimal transport with a real listener.
	ks, cfg := makeValidIdentity(t)
	ri, err := ks.ConstructRouterInfo(nil)
	require.NoError(t, err)

	transport, err := NewSSU2Transport(*ri, cfg, ks)
	require.NoError(t, err, "Failed to create SSU2 transport")
	defer transport.Close()

	// Force garbage collection and wait for goroutines to stabilize.
	runtime.GC()
	time.Sleep(200 * time.Millisecond)
	baselineGoroutines := runtime.NumGoroutine()
	t.Logf("Baseline goroutine count: %d", baselineGoroutines)

	// Call SetIdentity N times with the same identity.
	// The important part is that the NAT managers are stopped and restarted.
	const N = 5
	for i := 0; i < N; i++ {
		err := transport.SetIdentity(*ri)
		require.NoError(t, err, "SetIdentity failed on iteration %d", i)

		// Give goroutines time to stop.
		time.Sleep(100 * time.Millisecond)
	}

	// Force garbage collection to clean up any lingering goroutines.
	runtime.GC()
	time.Sleep(200 * time.Millisecond)
	finalGoroutines := runtime.NumGoroutine()
	t.Logf("Final goroutine count after %d SetIdentity calls: %d", N, finalGoroutines)

	// The goroutine count should be close to the baseline.
	// We allow a generous delta to account for timing, GC variance, and test framework goroutines.
	const maxDelta = 5
	delta := finalGoroutines - baselineGoroutines
	if delta < 0 {
		delta = -delta
	}
	assert.LessOrEqual(t, delta, maxDelta,
		"Goroutine leak detected: baseline %d, final %d, delta %d (max allowed %d)",
		baselineGoroutines, finalGoroutines, delta, maxDelta)

	// If the delta is > 0, log a warning for visibility.
	if delta > 0 {
		t.Logf("NOTE: Goroutine count delta is %d (within tolerance of %d)", delta, maxDelta)
	}
}

// TestL1_SetIdentity_ManagersReplaced verifies that calling SetIdentity stops
// old managers and creates new ones (L-1 fix items 1, 3, 4).
func TestL1_SetIdentity_ManagersReplaced(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping manager replacement test in short mode")
	}

	ks, cfg := makeValidIdentity(t)
	ri, err := ks.ConstructRouterInfo(nil)
	require.NoError(t, err)

	transport, err := NewSSU2Transport(*ri, cfg, ks)
	require.NoError(t, err)
	defer transport.Close()

	// Capture initial manager pointers.
	oldRelayManager := transport.relayManager
	oldPeerTestManager := transport.peerTestManager
	oldHolePunchCoord := transport.holePunchCoord
	oldIntroducerRegistry := transport.introducerRegistry
	oldKeyRotationManager := transport.keyRotationManager

	// Call SetIdentity.
	err = transport.SetIdentity(*ri)
	require.NoError(t, err)

	// Verify that managers have been replaced (new pointers).
	assert.NotSame(t, oldRelayManager, transport.relayManager, "relayManager not replaced")
	assert.NotSame(t, oldPeerTestManager, transport.peerTestManager, "peerTestManager not replaced")
	assert.NotSame(t, oldHolePunchCoord, transport.holePunchCoord, "holePunchCoord not replaced")
	assert.NotSame(t, oldIntroducerRegistry, transport.introducerRegistry, "introducerRegistry not replaced")
	// keyRotationManager is also replaced after SetIdentity calls initKeyManagement.
	assert.NotSame(t, oldKeyRotationManager, transport.keyRotationManager, "keyRotationManager not replaced")

	// Verify that the transport is still functional after SetIdentity.
	require.NotNil(t, transport.relayManager)
	require.NotNil(t, transport.peerTestManager)
	require.NotNil(t, transport.holePunchCoord)
	require.NotNil(t, transport.introducerRegistry)
	require.NotNil(t, transport.keyRotationManager)
}
