package netdb

import (
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper to create test hash with specific suffix
func testPeerHash(suffix byte) common.Hash {
	var hash common.Hash
	for i := range hash {
		hash[i] = suffix
	}
	return hash
}

// TestGetActivePeerCount tests counting peers with recent successful connections
func TestGetActivePeerCount(t *testing.T) {
	tempDir := t.TempDir()
	db := NewStdNetDB(tempDir)
	require.NoError(t, db.Create())
	defer db.Stop()

	// Initially should be 0
	assert.Equal(t, 0, db.GetActivePeerCount())

	// Create test hashes
	hash1 := testPeerHash(1)
	hash2 := testPeerHash(2)
	hash3 := testPeerHash(3)

	// Add hashes to RouterInfos map so they're counted
	db.riMutex.Lock()
	db.RouterInfos[hash1] = Entry{}
	db.RouterInfos[hash2] = Entry{}
	db.RouterInfos[hash3] = Entry{}
	db.riMutex.Unlock()

	// Record peer 1 as active (recent success)
	db.PeerTracker.RecordSuccess(hash1, 100)

	// Record peer 2 as inactive - manually modify the internal stats
	// We need to access the internal map directly since RecordSuccess would set LastSuccess to now
	db.PeerTracker.mu.Lock()
	db.PeerTracker.stats[hash2] = &PeerStats{
		Hash:              hash2,
		SuccessCount:      1,
		LastSuccess:       time.Now().Add(-2 * time.Hour), // 2 hours ago
		TotalAttempts:     1,
		AvgResponseTimeMs: 100,
	}
	db.PeerTracker.mu.Unlock()

	// Peer 3 has no connection attempts

	// Should count only peer 1 as active (within last hour)
	activePeers := db.GetActivePeerCount()
	assert.Equal(t, 1, activePeers, "Expected 1 active peer with recent success")
}

// TestGetFastPeerCount tests counting peers with low latency
func TestGetFastPeerCount(t *testing.T) {
	tempDir := t.TempDir()
	db := NewStdNetDB(tempDir)
	require.NoError(t, db.Create())
	defer db.Stop()

	// Initially should be 0
	assert.Equal(t, 0, db.GetFastPeerCount())

	// Create test hashes
	hash1 := testPeerHash(10)
	hash2 := testPeerHash(20)
	hash3 := testPeerHash(30)

	// Add hashes to RouterInfos map
	db.riMutex.Lock()
	db.RouterInfos[hash1] = Entry{}
	db.RouterInfos[hash2] = Entry{}
	db.RouterInfos[hash3] = Entry{}
	db.riMutex.Unlock()

	// Record peer 1 as fast (< 500ms, enough attempts)
	for i := 0; i < 5; i++ {
		db.PeerTracker.RecordSuccess(hash1, 200) // 200ms response time
	}

	// Record peer 2 as slow (> 500ms)
	for i := 0; i < 5; i++ {
		db.PeerTracker.RecordSuccess(hash2, 800) // 800ms response time
	}

	// Record peer 3 with too few attempts (only 2, needs 3)
	db.PeerTracker.RecordSuccess(hash3, 100)
	db.PeerTracker.RecordSuccess(hash3, 100)

	// Should count only peer 1 as fast
	fastPeers := db.GetFastPeerCount()
	assert.Equal(t, 1, fastPeers, "Expected 1 fast peer with low latency")
}

// TestGetHighCapacityPeerCount tests counting reliable high-performance peers
func TestGetHighCapacityPeerCount(t *testing.T) {
	tempDir := t.TempDir()
	db := NewStdNetDB(tempDir)
	require.NoError(t, db.Create())
	defer db.Stop()

	// Initially should be 0
	assert.Equal(t, 0, db.GetHighCapacityPeerCount())

	// Create test hashes
	hash1 := testPeerHash(40)
	hash2 := testPeerHash(50)
	hash3 := testPeerHash(60)
	hash4 := testPeerHash(70)

	// Add hashes to RouterInfos map
	db.riMutex.Lock()
	db.RouterInfos[hash1] = Entry{}
	db.RouterInfos[hash2] = Entry{}
	db.RouterInfos[hash3] = Entry{}
	db.RouterInfos[hash4] = Entry{}
	db.riMutex.Unlock()

	// Record peer 1 as high capacity (high success rate, low latency, enough attempts)
	for i := 0; i < 10; i++ {
		db.PeerTracker.RecordSuccess(hash1, 300) // 300ms response time
	}

	// Record peer 2 with low success rate (< 80%)
	for i := 0; i < 10; i++ {
		if i < 6 {
			db.PeerTracker.RecordSuccess(hash2, 300)
		} else {
			db.PeerTracker.RecordFailure(hash2, "timeout")
		}
	}

	// Record peer 3 as slow (> 1000ms average)
	for i := 0; i < 10; i++ {
		db.PeerTracker.RecordSuccess(hash3, 1500) // 1500ms response time
	}

	// Record peer 4 as stale (consecutive failures)
	for i := 0; i < 5; i++ {
		if i < 2 {
			db.PeerTracker.RecordSuccess(hash4, 300)
		} else {
			db.PeerTracker.RecordFailure(hash4, "timeout")
		}
	}

	// Should count only peer 1 as high capacity
	highCapPeers := db.GetHighCapacityPeerCount()
	assert.Equal(t, 1, highCapPeers, "Expected 1 high-capacity peer")
}

// TestPeerClassificationWithNoPeerTracker tests behavior when PeerTracker is nil
func TestPeerClassificationWithNoPeerTracker(t *testing.T) {
	tempDir := t.TempDir()
	db := NewStdNetDB(tempDir)
	db.PeerTracker = nil // Simulate missing peer tracker

	// All methods should return 0 without crashing
	assert.Equal(t, 0, db.GetActivePeerCount())
	assert.Equal(t, 0, db.GetFastPeerCount())
	assert.Equal(t, 0, db.GetHighCapacityPeerCount())
}

// TestPeerClassificationWithEmptyDatabase tests behavior with no peers
func TestPeerClassificationWithEmptyDatabase(t *testing.T) {
	tempDir := t.TempDir()
	db := NewStdNetDB(tempDir)
	require.NoError(t, db.Create())
	defer db.Stop()

	// All methods should return 0 for empty database
	assert.Equal(t, 0, db.GetActivePeerCount())
	assert.Equal(t, 0, db.GetFastPeerCount())
	assert.Equal(t, 0, db.GetHighCapacityPeerCount())
}

// TestMultiplePeerClassifications tests peers can be classified in multiple categories
func TestMultiplePeerClassifications(t *testing.T) {
	tempDir := t.TempDir()
	db := NewStdNetDB(tempDir)
	require.NoError(t, db.Create())
	defer db.Stop()

	// Create a peer that should qualify for all categories
	hash := testPeerHash(100)

	// Add hash to RouterInfos map
	db.riMutex.Lock()
	db.RouterInfos[hash] = Entry{}
	db.riMutex.Unlock()

	// Record excellent performance
	for i := 0; i < 10; i++ {
		db.PeerTracker.RecordSuccess(hash, 200) // Fast response time
	}

	// Should be counted in all categories
	assert.Equal(t, 1, db.GetActivePeerCount(), "Should be active")
	assert.Equal(t, 1, db.GetFastPeerCount(), "Should be fast")
	assert.Equal(t, 1, db.GetHighCapacityPeerCount(), "Should be high capacity")
}
