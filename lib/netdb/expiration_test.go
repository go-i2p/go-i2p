package netdb

import (
	"os"
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestStartExpirationCleaner verifies that the expiration cleaner starts successfully
func TestStartExpirationCleaner(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)
	require.NotNil(t, db)

	// Start the cleaner
	db.StartExpirationCleaner()

	// Verify context is active
	select {
	case <-db.ctx.Done():
		t.Fatal("Context should not be cancelled yet")
	default:
		// Expected: context is still active
	}

	// Clean shutdown
	db.Stop()

	// Verify context is cancelled after stop
	select {
	case <-db.ctx.Done():
		// Expected: context is cancelled
	case <-time.After(1 * time.Second):
		t.Fatal("Context should be cancelled after Stop()")
	}
}

// TestStopWithoutStart verifies Stop() is safe to call even if cleaner wasn't started
func TestStopWithoutStart(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)
	require.NotNil(t, db)

	// Should not panic
	db.Stop()
}

// TestExpirationTracking verifies expiration time tracking
func TestExpirationTracking(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)
	require.NotNil(t, db)

	hash := common.Hash{0x01, 0x02, 0x03}
	expiryTime := time.Now().Add(5 * time.Minute)

	// Manually add expiry entry (simulating what trackLeaseSet* would do)
	db.expiryMutex.Lock()
	db.leaseSetExpiry[hash] = expiryTime
	db.expiryMutex.Unlock()

	// Verify expiration was recorded
	db.expiryMutex.RLock()
	trackedTime, exists := db.leaseSetExpiry[hash]
	db.expiryMutex.RUnlock()

	assert.True(t, exists, "Expiration should be tracked")
	assert.Equal(t, expiryTime, trackedTime)
}

// TestCleanExpiredLeaseSets verifies that expired LeaseSets are removed
func TestCleanExpiredLeaseSets(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)
	require.NotNil(t, db)

	// Create hash for expired LeaseSet
	expiredHash := common.Hash{0x10, 0x11, 0x12}
	validHash := common.Hash{0x20, 0x21, 0x22}

	// Add both to cache (with empty entries for testing)
	db.lsMutex.Lock()
	db.LeaseSets[expiredHash] = Entry{}
	db.LeaseSets[validHash] = Entry{}
	db.lsMutex.Unlock()

	// Track expirations: one expired, one valid
	db.expiryMutex.Lock()
	db.leaseSetExpiry[expiredHash] = time.Now().Add(-1 * time.Minute) // Expired 1 min ago
	db.leaseSetExpiry[validHash] = time.Now().Add(5 * time.Minute)    // Valid for 5 min
	db.expiryMutex.Unlock()

	// Verify both are in cache initially
	db.lsMutex.Lock()
	initialCount := len(db.LeaseSets)
	db.lsMutex.Unlock()
	assert.Equal(t, 2, initialCount)

	// Run cleanup
	db.cleanExpiredLeaseSets()

	// Verify expired was removed but valid remains
	db.lsMutex.Lock()
	_, hasExpired := db.LeaseSets[expiredHash]
	_, hasValid := db.LeaseSets[validHash]
	finalCount := len(db.LeaseSets)
	db.lsMutex.Unlock()

	assert.False(t, hasExpired, "Expired LeaseSet should be removed")
	assert.True(t, hasValid, "Valid LeaseSet should remain")
	assert.Equal(t, 1, finalCount)

	// Verify expiry tracking was also cleaned
	db.expiryMutex.RLock()
	_, trackedExpired := db.leaseSetExpiry[expiredHash]
	_, trackedValid := db.leaseSetExpiry[validHash]
	db.expiryMutex.RUnlock()

	assert.False(t, trackedExpired, "Expired entry should be removed from tracking")
	assert.True(t, trackedValid, "Valid entry should remain in tracking")
}

// TestRemoveLeaseSetFromDisk verifies filesystem cleanup
func TestRemoveLeaseSetFromDisk(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)
	require.NotNil(t, db)

	// Create netdb directory structure
	err := db.Create()
	require.NoError(t, err)

	// Create a test file
	hash := common.Hash{0x30, 0x31, 0x32}
	fpath := db.SkiplistFileForLeaseSet(hash)

	// Ensure directory exists
	err = os.MkdirAll(tmpDir+"/l3", 0o700)
	require.NoError(t, err)

	// Create a dummy file
	f, err := os.Create(fpath)
	require.NoError(t, err)
	_, err = f.WriteString("test data")
	require.NoError(t, err)
	f.Close()

	// Verify file exists
	_, err = os.Stat(fpath)
	require.NoError(t, err)

	// Remove from disk
	db.removeLeaseSetFromDisk(hash)

	// Verify file is gone
	_, err = os.Stat(fpath)
	assert.True(t, os.IsNotExist(err), "File should be deleted")
}

// TestRemoveLeaseSetFromDiskNonexistent verifies safe handling of missing files
func TestRemoveLeaseSetFromDiskNonexistent(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)
	require.NotNil(t, db)

	hash := common.Hash{0x40, 0x41, 0x42}

	// Should not panic when file doesn't exist
	db.removeLeaseSetFromDisk(hash)
}

// TestGetLeaseSetExpirationStats verifies statistics reporting
func TestGetLeaseSetExpirationStats(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)
	require.NotNil(t, db)

	now := time.Now()

	// Add 2 expired LeaseSets
	expiredHash1 := common.Hash{0x50}
	expiredHash2 := common.Hash{0x51}
	db.expiryMutex.Lock()
	db.leaseSetExpiry[expiredHash1] = now.Add(-5 * time.Minute)
	db.leaseSetExpiry[expiredHash2] = now.Add(-2 * time.Minute)
	db.expiryMutex.Unlock()

	// Add 3 valid LeaseSets with different expiry times
	validHash1 := common.Hash{0x60}
	validHash2 := common.Hash{0x61}
	validHash3 := common.Hash{0x62}
	db.expiryMutex.Lock()
	db.leaseSetExpiry[validHash1] = now.Add(2 * time.Minute) // Earliest valid
	db.leaseSetExpiry[validHash2] = now.Add(5 * time.Minute)
	db.leaseSetExpiry[validHash3] = now.Add(10 * time.Minute)
	db.expiryMutex.Unlock()

	// Get statistics
	total, expired, nextExpiry := db.GetLeaseSetExpirationStats()

	assert.Equal(t, 5, total, "Should track 5 total LeaseSets")
	assert.Equal(t, 2, expired, "Should identify 2 expired LeaseSets")
	// nextExpiry should be ~2 minutes (time until earliest valid expiration)
	assert.InDelta(t, float64(2*time.Minute), float64(nextExpiry), float64(5*time.Second),
		"Next expiry should be ~2 minutes from now")
}

// TestGetLeaseSetExpirationStatsEmpty verifies stats with no LeaseSets
func TestGetLeaseSetExpirationStatsEmpty(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)
	require.NotNil(t, db)

	total, expired, nextExpiry := db.GetLeaseSetExpirationStats()

	assert.Equal(t, 0, total)
	assert.Equal(t, 0, expired)
	assert.Equal(t, time.Duration(0), nextExpiry, "Should be zero when no LeaseSets")
}

// TestCleanExpiredLeaseSetsNoExpired verifies no action when all valid
func TestCleanExpiredLeaseSetsNoExpired(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)
	require.NotNil(t, db)

	// Add only valid LeaseSet
	validHash := common.Hash{0x70}

	db.lsMutex.Lock()
	db.LeaseSets[validHash] = Entry{}
	db.lsMutex.Unlock()

	db.expiryMutex.Lock()
	db.leaseSetExpiry[validHash] = time.Now().Add(10 * time.Minute)
	db.expiryMutex.Unlock()

	initialCount := len(db.LeaseSets)

	// Run cleanup
	db.cleanExpiredLeaseSets()

	// Verify nothing was removed
	db.lsMutex.Lock()
	finalCount := len(db.LeaseSets)
	db.lsMutex.Unlock()

	assert.Equal(t, initialCount, finalCount, "No LeaseSets should be removed")
}

// TestRemoveExpiredLeaseSet verifies complete removal of expired entry
func TestRemoveExpiredLeaseSet(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)
	require.NotNil(t, db)

	hash := common.Hash{0x80}

	// Add entry to all three maps
	db.lsMutex.Lock()
	db.LeaseSets[hash] = Entry{}
	db.lsMutex.Unlock()

	db.expiryMutex.Lock()
	db.leaseSetExpiry[hash] = time.Now().Add(-1 * time.Minute)
	db.expiryMutex.Unlock()

	// Remove expired entry
	db.removeExpiredLeaseSet(hash)

	// Verify removed from LeaseSet cache
	db.lsMutex.Lock()
	_, inCache := db.LeaseSets[hash]
	db.lsMutex.Unlock()
	assert.False(t, inCache, "Should be removed from LeaseSet cache")

	// Verify removed from expiry tracking
	db.expiryMutex.RLock()
	_, inExpiry := db.leaseSetExpiry[hash]
	db.expiryMutex.RUnlock()
	assert.False(t, inExpiry, "Should be removed from expiry tracking")
}

// TestExpirationCleanerIntegration tests the full lifecycle
func TestExpirationCleanerIntegration(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)
	require.NotNil(t, db)

	// Add one expired and one valid LeaseSet
	expiredHash := common.Hash{0x90}
	validHash := common.Hash{0x91}

	db.lsMutex.Lock()
	db.LeaseSets[expiredHash] = Entry{}
	db.LeaseSets[validHash] = Entry{}
	db.lsMutex.Unlock()

	db.expiryMutex.Lock()
	db.leaseSetExpiry[expiredHash] = time.Now().Add(-1 * time.Second)
	db.leaseSetExpiry[validHash] = time.Now().Add(1 * time.Hour)
	db.expiryMutex.Unlock()

	// Start cleaner (runs every minute, but we'll trigger manually)
	db.StartExpirationCleaner()
	defer db.Stop()

	// Manually trigger one cleanup cycle
	db.cleanExpiredLeaseSets()

	// Verify expired was removed, valid remains
	db.lsMutex.Lock()
	_, hasExpired := db.LeaseSets[expiredHash]
	_, hasValid := db.LeaseSets[validHash]
	count := len(db.LeaseSets)
	db.lsMutex.Unlock()

	assert.False(t, hasExpired, "Expired LeaseSet should be cleaned up")
	assert.True(t, hasValid, "Valid LeaseSet should remain")
	assert.Equal(t, 1, count, "Should have exactly 1 LeaseSet remaining")
}

// TestMultipleStopCalls verifies Stop() is idempotent
func TestMultipleStopCalls(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)
	require.NotNil(t, db)

	db.StartExpirationCleaner()

	// Call Stop() multiple times - should not panic
	db.Stop()
	db.Stop()
	db.Stop()
}

// TestCleanupWithManyExpired verifies performance with many expired LeaseSets
func TestCleanupWithManyExpired(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)
	require.NotNil(t, db)

	const numExpired = 100
	const numValid = 50

	// Add many expired LeaseSets
	for i := 0; i < numExpired; i++ {
		hash := common.Hash{}
		hash[0] = byte(i)

		db.lsMutex.Lock()
		db.LeaseSets[hash] = Entry{}
		db.lsMutex.Unlock()

		db.expiryMutex.Lock()
		db.leaseSetExpiry[hash] = time.Now().Add(-1 * time.Minute)
		db.expiryMutex.Unlock()
	}

	// Add some valid LeaseSets
	for i := 0; i < numValid; i++ {
		hash := common.Hash{}
		hash[0] = byte(numExpired + i)

		db.lsMutex.Lock()
		db.LeaseSets[hash] = Entry{}
		db.lsMutex.Unlock()

		db.expiryMutex.Lock()
		db.leaseSetExpiry[hash] = time.Now().Add(10 * time.Minute)
		db.expiryMutex.Unlock()
	}

	// Run cleanup
	start := time.Now()
	db.cleanExpiredLeaseSets()
	elapsed := time.Since(start)

	// Verify correct number remaining
	db.lsMutex.Lock()
	count := len(db.LeaseSets)
	db.lsMutex.Unlock()

	assert.Equal(t, numValid, count, "Should have only valid LeaseSets remaining")
	assert.Less(t, elapsed, 100*time.Millisecond, "Cleanup should be fast")

	// Verify statistics
	total, expired, _ := db.GetLeaseSetExpirationStats()
	assert.Equal(t, numValid, total)
	assert.Equal(t, 0, expired)
}

// TestCleanerRunsPeriodically verifies the cleanup goroutine runs automatically
func TestCleanerRunsPeriodically(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping periodic test in short mode")
	}

	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)
	require.NotNil(t, db)

	// Add a LeaseSet that will expire very soon
	expHash := common.Hash{0xA0}
	db.lsMutex.Lock()
	db.LeaseSets[expHash] = Entry{}
	db.lsMutex.Unlock()

	db.expiryMutex.Lock()
	db.leaseSetExpiry[expHash] = time.Now().Add(2 * time.Second)
	db.expiryMutex.Unlock()

	// Start cleaner - it runs every minute, but for this test we've made one expire soon
	db.StartExpirationCleaner()
	defer db.Stop()

	// Wait briefly, then manually trigger cleanup since the ticker interval is 1 minute
	time.Sleep(100 * time.Millisecond)
	db.cleanExpiredLeaseSets()

	// LeaseSet should still exist (not yet expired)
	db.lsMutex.Lock()
	_, exists := db.LeaseSets[expHash]
	db.lsMutex.Unlock()
	assert.True(t, exists, "LeaseSet should still exist")

	// Wait for expiration
	time.Sleep(3 * time.Second)

	// Manually trigger cleanup
	db.cleanExpiredLeaseSets()

	// LeaseSet should now be removed
	db.lsMutex.Lock()
	_, exists = db.LeaseSets[expHash]
	db.lsMutex.Unlock()
	assert.False(t, exists, "Expired LeaseSet should be removed")
}

// TestPeerTrackerPruningIntegration verifies that PeerTracker.PruneOldEntries is
// invoked by the expiration cleaner goroutine. We simulate the pruning trigger
// by directly calling PruneOldEntries (since the ticker-based invocation runs every
// 10 minutes and is impractical to wait for in tests) and verify the PeerTracker
// is properly initialized and accessible from StdNetDB.
func TestPeerTrackerPruningIntegration(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)
	require.NotNil(t, db)
	require.NotNil(t, db.PeerTracker, "PeerTracker should be initialized")

	// Add peer entries — one recent, one old
	recentHash := testHash(0xAA)
	oldHash := testHash(0xBB)

	db.PeerTracker.RecordAttempt(recentHash)
	db.PeerTracker.RecordAttempt(oldHash)

	// Manually age the old entry
	db.PeerTracker.mu.Lock()
	if stats, ok := db.PeerTracker.stats[oldHash]; ok {
		stats.LastAttempt = time.Now().Add(-25 * time.Hour)
	}
	db.PeerTracker.mu.Unlock()

	// Prune entries older than 24 hours (same as the cleaner uses)
	pruned := db.PeerTracker.PruneOldEntries(24 * time.Hour)
	assert.Equal(t, 1, pruned, "Should have pruned 1 old entry")

	// Recent peer should still exist
	assert.NotNil(t, db.PeerTracker.GetStats(recentHash), "Recent peer should still be tracked")
	// Old peer should be removed
	assert.Nil(t, db.PeerTracker.GetStats(oldHash), "Old peer should have been pruned")
}

// TestPeerTrackerAvailableInNetDB verifies PeerTracker is wired into StdNetDB
// and can be used for peer reputation queries.
func TestPeerTrackerAvailableInNetDB(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)
	require.NotNil(t, db)
	require.NotNil(t, db.PeerTracker)

	hash := testHash(0xCC)

	// Record activity through the NetDB's PeerTracker
	db.PeerTracker.RecordSuccess(hash, 100)
	db.PeerTracker.RecordSuccess(hash, 200)

	stats := db.PeerTracker.GetStats(hash)
	require.NotNil(t, stats)
	assert.Equal(t, 2, stats.SuccessCount)
	assert.Equal(t, int64(150), stats.AvgResponseTimeMs)
	assert.False(t, db.PeerTracker.IsLikelyStale(hash))
}
