package ssu2

import (
	"sync"
	"sync/atomic"
	"testing"

	ssu2noise "github.com/go-i2p/go-noise/ssu2"
	"github.com/stretchr/testify/assert"
)

// SA-1: Test that shouldInitiatePeerTest correctly caps at startupPeerTestMax
// under concurrent load, preventing the check-then-decrement race.
func TestShouldInitiatePeerTest_ConcurrentCap(t *testing.T) {
	const startupPeerTestMax = 5 // T-2/RD-1: raised from 3 to 5
	const concurrentAttempts = 50

	// Use a non-nil pointer of the real PeerTestManager type.
	// We don't need to initialize it fully; shouldInitiatePeerTest only checks != nil.
	transport := &SSU2Transport{
		peerTestManager: &ssu2noise.PeerTestManager{},
	}

	// Launch concurrentAttempts goroutines, all calling shouldInitiatePeerTest
	// concurrently. Only startupPeerTestMax should succeed.
	var wg sync.WaitGroup
	successCount := int32(0)

	for i := 0; i < concurrentAttempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if transport.shouldInitiatePeerTest() {
				atomic.AddInt32(&successCount, 1)
			}
		}()
	}

	wg.Wait()

	// Assert exactly startupPeerTestMax (3) succeeded
	assert.Equal(t, int32(startupPeerTestMax), successCount,
		"Expected exactly %d peer tests to be allowed, got %d", startupPeerTestMax, successCount)

	// Assert counter reflects the correct count
	finalCount := atomic.LoadInt32(&transport.startupPeerTestCount)
	assert.Equal(t, int32(startupPeerTestMax), finalCount,
		"Expected startupPeerTestCount to be %d, got %d", startupPeerTestMax, finalCount)
}

// SA-1: Test that shouldInitiatePeerTest respects the cap when called sequentially.
func TestShouldInitiatePeerTest_SequentialCap(t *testing.T) {
	const startupPeerTestMax = 5 // T-2/RD-1: raised from 3 to 5

	transport := &SSU2Transport{
		peerTestManager: &ssu2noise.PeerTestManager{},
	}

	// First 5 calls should succeed (T-2/RD-1: raised from 3 to 5)
	for i := 1; i <= startupPeerTestMax; i++ {
		result := transport.shouldInitiatePeerTest()
		assert.True(t, result, "Expected attempt %d to succeed", i)
	}

	// 6th call should fail (T-2/RD-1: raised from 4th to 6th)
	result := transport.shouldInitiatePeerTest()
	assert.False(t, result, "Expected %dth attempt to fail (cap reached)", startupPeerTestMax+1)

	// Counter should be exactly 5 (T-2/RD-1: raised from 3 to 5)
	finalCount := atomic.LoadInt32(&transport.startupPeerTestCount)
	assert.Equal(t, int32(startupPeerTestMax), finalCount)
}

// SA-1: Test that shouldInitiatePeerTest returns false when peerTestManager is nil.
func TestShouldInitiatePeerTest_NilManager(t *testing.T) {
	transport := &SSU2Transport{
		peerTestManager: nil, // peer tests disabled
	}

	result := transport.shouldInitiatePeerTest()
	assert.False(t, result, "Expected false when peerTestManager is nil")

	// Counter should not have been incremented
	count := atomic.LoadInt32(&transport.startupPeerTestCount)
	assert.Equal(t, int32(0), count, "Expected counter to remain 0 when manager is nil")
}
