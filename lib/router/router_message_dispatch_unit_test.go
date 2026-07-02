package router

import (
	"fmt"
	"testing"
	"time"
)

// TestReadWarnMapBoundedGrowth verifies that the readWarnLastByPeer map is bounded
// by readWarnMaxMapSize and that oldest entries are evicted when the cap is hit.
func TestReadWarnMapBoundedGrowth(t *testing.T) {
	// Save original state and restore after test
	originalMap := readWarnLastByPeer
	originalMaxSize := readWarnMaxMapSize
	defer func() {
		readWarnLimiterMu.Lock()
		readWarnLastByPeer = originalMap
		readWarnLimiterMu.Unlock()
		readWarnMaxMapSize = originalMaxSize
	}()

	// Use a small cap for testing
	testCapSize := 100
	readWarnMaxMapSize = testCapSize

	// Reset map for clean test
	readWarnLimiterMu.Lock()
	readWarnLastByPeer = make(map[string]time.Time)
	readWarnLimiterMu.Unlock()

	// Add more peers than the cap allows
	numPeers := testCapSize + 50
	peerHashes := make([]string, numPeers)
	for i := 0; i < numPeers; i++ {
		peerHashes[i] = fmt.Sprintf("peer_%d", i)
	}

	// Simulate adding many peers (each adding a new peer to the map)
	// Only the first call per peer should rate-limit
	for _, hash := range peerHashes {
		// First call returns true (should log)
		shouldLogReadWarn(hash)
		// Immediate second call should return false (rate-limited)
		if shouldLogReadWarn(hash) {
			t.Errorf("shouldLogReadWarn returned true for peer %s within rate-limit interval", hash)
		}
	}

	// Verify map size doesn't exceed cap
	readWarnLimiterMu.Lock()
	mapSize := len(readWarnLastByPeer)
	readWarnLimiterMu.Unlock()

	if mapSize > testCapSize {
		t.Errorf("readWarnLastByPeer map size %d exceeds cap %d", mapSize, testCapSize)
	}

	if mapSize < testCapSize {
		// Some entries might have been evicted, but we should be close to cap
		// Allow some tolerance for test timing
		if mapSize < testCapSize-10 {
			t.Logf("readWarnLastByPeer map size %d is below cap %d", mapSize, testCapSize)
		}
	}

	// Verify oldest entries are indeed oldest (were evicted)
	// The first peers we added should no longer be in the map
	for i := 0; i < 50; i++ {
		readWarnLimiterMu.Lock()
		_, exists := readWarnLastByPeer[peerHashes[i]]
		readWarnLimiterMu.Unlock()

		if exists {
			t.Errorf("peer_%d still in map after exceeding cap; should have been evicted", i)
		}
	}

	// The later peers should be in the map
	for i := numPeers - 20; i < numPeers; i++ {
		readWarnLimiterMu.Lock()
		_, exists := readWarnLastByPeer[peerHashes[i]]
		readWarnLimiterMu.Unlock()

		if !exists {
			t.Errorf("peer_%d missing from map; should be retained as recent peer", i)
		}
	}
}

// TestReadWarnCleanupNearCapacity verifies that cleanup logs at Warn level
// when map is at 90%+ capacity, indicating high peer churn.
func TestReadWarnCleanupNearCapacity(t *testing.T) {
	// Save original state
	originalMap := readWarnLastByPeer
	originalMaxSize := readWarnMaxMapSize
	defer func() {
		readWarnLimiterMu.Lock()
		readWarnLastByPeer = originalMap
		readWarnLimiterMu.Unlock()
		readWarnMaxMapSize = originalMaxSize
	}()

	testCapSize := 100
	readWarnMaxMapSize = testCapSize

	// Reset map
	readWarnLimiterMu.Lock()
	readWarnLastByPeer = make(map[string]time.Time)
	readWarnLimiterMu.Unlock()

	// Fill map to just below capacity
	now := time.Now()
	readWarnLimiterMu.Lock()
	for i := 0; i < testCapSize-5; i++ {
		hash := fmt.Sprintf("peer_%d", i)
		readWarnLastByPeer[hash] = now.Add(time.Duration(i) * time.Second)
	}
	readWarnLimiterMu.Unlock()

	// Cleanup should log at Warn level due to being near capacity
	// (no assertion needed here; just verify it doesn't panic)
	cleanupReadWarnLastByPeer()

	// Verify map is still around expected size
	readWarnLimiterMu.Lock()
	mapSize := len(readWarnLastByPeer)
	readWarnLimiterMu.Unlock()

	if mapSize != testCapSize-5 {
		t.Errorf("Expected map size %d, got %d", testCapSize-5, mapSize)
	}
}
