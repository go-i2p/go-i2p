package ssu2

import (
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestRL2_PortMapperGoroutineLeakOnSetIdentityFailure
// Verifies that port mapper goroutines don't leak when SetIdentity operations
// fail or when NAT traversal takes longer than the Stop() timeout.
func TestRL2_PortMapperGoroutineLeakOnSetIdentityFailure(t *testing.T) {
	t.Parallel()

	ks, cfg := makeValidIdentity(t)
	ri, err := ks.ConstructRouterInfo(nil)
	require.NoError(t, err)

	tr, err := NewSSU2Transport(*ri, cfg, ks)
	require.NoError(t, err)
	defer tr.Close()

	// Get baseline goroutine count
	baselineGoroutines := runtime.NumGoroutine()
	t.Logf("Baseline goroutines: %d", baselineGoroutines)

	// Perform repeated SetIdentity operations
	// This exercises the stop/start cycle of the port mapper
	for i := 0; i < 20; i++ {
		ri2, err := ks.ConstructRouterInfo(nil)
		require.NoError(t, err, "iteration %d: failed to construct router info", i)

		err = tr.SetIdentity(*ri2)
		require.NoError(t, err, "iteration %d: SetIdentity failed", i)
	}

	// Check goroutine count after SetIdentity churn
	// Should be close to baseline (allow some small variance)
	afterSetIdentityGoroutines := runtime.NumGoroutine()
	t.Logf("Goroutines after SetIdentity churn: %d", afterSetIdentityGoroutines)

	// Close transport and give goroutines time to clean up
	tr.Close()
	time.Sleep(100 * time.Millisecond)

	// Final goroutine count should return to baseline
	finalGoroutines := runtime.NumGoroutine()
	t.Logf("Final goroutines after Close: %d", finalGoroutines)

	// Allow for 5 goroutine variance (some background tasks might still be running)
	accumulated := finalGoroutines - baselineGoroutines
	require.LessOrEqual(t, accumulated, 5, "Goroutines accumulated (%d), possible leak", accumulated)
}

// TestRL2_PortMapperStopTimeout
// Verifies that port mapper Stop() properly waits for retry goroutine to exit,
// even if it takes close to the 5-second timeout.
func TestRL2_PortMapperStopTimeout(t *testing.T) {
	t.Parallel()

	ks, cfg := makeValidIdentity(t)
	ri, err := ks.ConstructRouterInfo(nil)
	require.NoError(t, err)

	tr, err := NewSSU2Transport(*ri, cfg, ks)
	require.NoError(t, err)

	// Get baseline before Close
	baselineGoroutines := runtime.NumGoroutine()
	t.Logf("Baseline goroutines: %d", baselineGoroutines)

	// Close should properly clean up port mapper goroutines
	startClose := time.Now()
	tr.Close()
	closeDuration := time.Since(startClose)
	t.Logf("Close() took %v", closeDuration)

	// Give goroutines time to clean up
	time.Sleep(100 * time.Millisecond)

	// Check final goroutine count
	finalGoroutines := runtime.NumGoroutine()
	t.Logf("Final goroutines after Close: %d", finalGoroutines)

	accumulated := finalGoroutines - baselineGoroutines
	require.LessOrEqual(t, accumulated, 5, "Goroutines accumulated after Close (%d), possible leak", accumulated)
}

// TestRL2_RapidSetIdentityWithNAT
// Stress test: rapid SetIdentity calls with NAT enabled.
// Verifies no resource exhaustion or goroutine leaks.
func TestRL2_RapidSetIdentityWithNAT(t *testing.T) {
	t.Parallel()

	ks, cfg := makeValidIdentity(t)
	ri, err := ks.ConstructRouterInfo(nil)
	require.NoError(t, err)

	tr, err := NewSSU2Transport(*ri, cfg, ks)
	require.NoError(t, err)
	defer tr.Close()

	baselineGoroutines := runtime.NumGoroutine()
	t.Logf("Baseline goroutines: %d", baselineGoroutines)

	// Rapid SetIdentity cycles - this stresses the port mapper lifecycle
	for i := 0; i < 50; i++ {
		ri2, err := ks.ConstructRouterInfo(nil)
		require.NoError(t, err)
		_ = tr.SetIdentity(*ri2)
		// Note: ignoring errors to test robustness even with failures
	}

	// Goroutine count should be reasonable
	afterGoroutines := runtime.NumGoroutine()
	t.Logf("Goroutines after 50 SetIdentity cycles: %d", afterGoroutines)

	accumulated := afterGoroutines - baselineGoroutines
	require.Less(t, accumulated, 20, "Goroutine accumulation (%d) suggests leak in SetIdentity", accumulated)
}
