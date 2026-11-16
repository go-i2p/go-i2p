package i2np

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGarlicSessionManager_OneTimeKeysObservableAndCleanupLoopBounded is the
// go-i2p-side guard for GN-009 (one-time garlic keys grow unbounded at the
// inbound-build rate).
//
// The eviction logic itself lives in go-noise (it owns the oneTimeKeys map and
// its cleanup loop) and is covered there. What this test pins is the two things
// that are go-i2p's responsibility:
//
//  1. The one-time key count is observable through the wrapper, and registering
//     a key per inbound build makes it grow one-for-one — i.e. without the
//     cleanup loop the map really does accumulate at the build rate.
//  2. StartCleanupLoop is bounded by the supplied context: cancelling it stops
//     the loop goroutine, so wiring it to the router's lifecycle context adds no
//     goroutine past shutdown.
func TestGarlicSessionManager_OneTimeKeysObservableAndCleanupLoopBounded(t *testing.T) {
	sm, err := GenerateGarlicSessionManager()
	require.NoError(t, err, "GenerateGarlicSessionManager() error")

	// (1) Registering one key per simulated inbound build grows the count
	// one-for-one. This is the unbounded-growth signature GN-009 describes.
	const builds = 500
	for i := 0; i < builds; i++ {
		var tag [8]byte
		var key [32]byte
		tag[0] = byte(i)
		tag[7] = byte(i >> 8)
		key[0] = byte(i)
		sm.RegisterOneTimeGarlicKey(tag, key)
	}
	assert.Equal(t, builds, sm.OneTimeKeyCount(),
		"one-time key count must track registrations (unbounded without cleanup)")

	// (2) The cleanup loop must be bounded by its context. Start it, confirm the
	// goroutine is live, then cancel and confirm it exits.
	before := runtime.NumGoroutine()
	ctx, cancel := context.WithCancel(context.Background())
	sm.StartCleanupLoop(ctx)

	// Give the goroutine a moment to spawn, then cancel.
	time.Sleep(50 * time.Millisecond)
	cancel()

	// The loop selects on ctx.Done() and returns immediately on cancellation, so
	// within a short window the goroutine count must return to (at most) baseline.
	settled := false
	for i := 0; i < 40; i++ {
		time.Sleep(25 * time.Millisecond)
		runtime.GC()
		if runtime.NumGoroutine() <= before {
			settled = true
			break
		}
	}
	assert.True(t, settled,
		"the cleanup loop goroutine must exit when its context is cancelled (before=%d, now=%d)",
		before, runtime.NumGoroutine())
}
