package transport

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestReleaseSession_ConcurrentNoNegative verifies that concurrent ReleaseSession
// calls cannot drive the counter negative due to TOCTOU race.
func TestReleaseSession_ConcurrentNoNegative(t *testing.T) {
	tmux := &TransportMuxer{}

	// Set initial count to 5
	atomic.StoreInt32(&tmux.activeSessionCount, 5)

	// Release 10 times concurrently (more than the 5 we have)
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tmux.ReleaseSession()
		}()
	}
	wg.Wait()

	// Counter should never go below 0
	finalCount := atomic.LoadInt32(&tmux.activeSessionCount)
	assert.GreaterOrEqual(t, finalCount, int32(0),
		"activeSessionCount should never go negative")
	assert.Equal(t, int32(0), finalCount,
		"activeSessionCount should be exactly 0 after releasing all sessions")
}

// TestReleaseSession_SingleDecrement verifies normal single-threaded decrement.
func TestReleaseSession_SingleDecrement(t *testing.T) {
	tmux := &TransportMuxer{}
	atomic.StoreInt32(&tmux.activeSessionCount, 3)

	tmux.ReleaseSession()
	assert.Equal(t, int32(2), atomic.LoadInt32(&tmux.activeSessionCount))

	tmux.ReleaseSession()
	assert.Equal(t, int32(1), atomic.LoadInt32(&tmux.activeSessionCount))

	tmux.ReleaseSession()
	assert.Equal(t, int32(0), atomic.LoadInt32(&tmux.activeSessionCount))

	// Extra release should clamp at 0
	tmux.ReleaseSession()
	assert.Equal(t, int32(0), atomic.LoadInt32(&tmux.activeSessionCount))
}
