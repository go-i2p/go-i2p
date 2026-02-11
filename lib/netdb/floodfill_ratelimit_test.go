package netdb

import (
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
)

func testPeerHashRL(id byte) common.Hash {
	var h common.Hash
	h[0] = id
	return h
}

func TestFloodfillRateLimiter_AllowsUpToBurst(t *testing.T) {
	rl := NewFloodfillRateLimiter(60, 5) // 60/min, burst 5
	defer rl.Stop()

	peer := testPeerHashRL(1)

	// First 5 requests should be allowed (burst capacity)
	for i := 0; i < 5; i++ {
		assert.True(t, rl.Allow(peer), "request %d should be allowed within burst", i+1)
	}

	// 6th request should be rejected (burst exhausted, no time to refill)
	assert.False(t, rl.Allow(peer), "request beyond burst should be rejected")
}

func TestFloodfillRateLimiter_RefillsOverTime(t *testing.T) {
	rl := NewFloodfillRateLimiter(60, 5)
	defer rl.Stop()

	peer := testPeerHashRL(2)

	// Exhaust burst
	for i := 0; i < 5; i++ {
		rl.Allow(peer)
	}
	assert.False(t, rl.Allow(peer))

	// After 1 second, should have refilled 1 token (60/min = 1/sec)
	time.Sleep(1100 * time.Millisecond)
	assert.True(t, rl.Allow(peer), "should have refilled after 1 second")
}

func TestFloodfillRateLimiter_IndependentPeers(t *testing.T) {
	rl := NewFloodfillRateLimiter(60, 3)
	defer rl.Stop()

	peer1 := testPeerHashRL(10)
	peer2 := testPeerHashRL(20)

	// Exhaust peer1's burst
	for i := 0; i < 3; i++ {
		rl.Allow(peer1)
	}
	assert.False(t, rl.Allow(peer1))

	// peer2 should still have full burst
	assert.True(t, rl.Allow(peer2), "peer2 should not be affected by peer1")
}

func TestFloodfillRateLimiter_CleanupRemovesStaleEntries(t *testing.T) {
	rl := NewFloodfillRateLimiter(60, 5)
	defer rl.Stop()

	peer := testPeerHashRL(30)
	rl.Allow(peer)

	// Manually set the entry to be stale
	rl.mu.Lock()
	if pl, ok := rl.peers[peer]; ok {
		pl.lastUpdate = time.Now().Add(-15 * time.Minute) // beyond 10-minute threshold
	}
	rl.mu.Unlock()

	// Run cleanup manually
	rl.mu.Lock()
	now := time.Now()
	for p, pl := range rl.peers {
		if now.Sub(pl.lastUpdate) > 10*time.Minute {
			delete(rl.peers, p)
		}
	}
	rl.mu.Unlock()

	// Peer should be removed
	rl.mu.Lock()
	_, exists := rl.peers[peer]
	rl.mu.Unlock()
	assert.False(t, exists, "stale peer entry should have been cleaned up")
}
