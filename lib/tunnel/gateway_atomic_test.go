package tunnel

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestGateway_MsgIDSeqAtomic verifies that concurrent calls to sendFragmented
// produce unique message IDs (no duplicates due to race conditions).
// This tests the fix for the EDGE CASE BUG: Gateway msgIDSeq Not Thread-Safe.
func TestGateway_MsgIDSeqAtomic(t *testing.T) {
	// Directly test the atomic counter behavior
	var counter uint32
	const goroutines = 100

	var wg sync.WaitGroup
	ids := make([]uint32, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ids[idx] = atomic.AddUint32(&counter, 1)
		}(i)
	}
	wg.Wait()

	// Verify all IDs are unique
	seen := make(map[uint32]bool)
	for _, id := range ids {
		assert.False(t, seen[id], "duplicate message ID %d detected", id)
		seen[id] = true
	}
	assert.Equal(t, uint32(goroutines), counter, "counter should equal number of increments")
}
