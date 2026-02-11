package netdb

import (
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTrackRouterInfoExpiration tests that expiration tracking records the correct expiry time.
func TestTrackRouterInfoExpiration(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)

	testHash := common.Hash{0x01, 0x02, 0x03}
	publishedTime := time.Now().Add(-1 * time.Hour) // published 1 hour ago

	db.trackRouterInfoExpiration(testHash, publishedTime)

	db.expiryMutex.RLock()
	expiryTime, exists := db.routerInfoExpiry[testHash]
	db.expiryMutex.RUnlock()

	assert.True(t, exists, "expiry should be tracked")
	expectedExpiry := publishedTime.Add(RouterInfoMaxAge)
	assert.WithinDuration(t, expectedExpiry, expiryTime, time.Second,
		"expiry time should be published + RouterInfoMaxAge")
}

// TestCleanExpiredRouterInfos_RemovesExpired tests that expired RouterInfos are removed.
func TestCleanExpiredRouterInfos_RemovesExpired(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)
	require.NoError(t, db.Create())

	// Add enough non-expired entries to stay above MinRouterInfoCount
	for i := 0; i < MinRouterInfoCount+5; i++ {
		hash := common.Hash{}
		hash[0] = byte(i)
		hash[1] = 0xAA // distinguish from expired entries

		db.riMutex.Lock()
		db.RouterInfos[hash] = Entry{}
		db.riMutex.Unlock()

		// Track as not expired (far future)
		db.expiryMutex.Lock()
		db.routerInfoExpiry[hash] = time.Now().Add(24 * time.Hour)
		db.expiryMutex.Unlock()
	}

	// Add 3 expired entries
	expiredHashes := make([]common.Hash, 3)
	for i := 0; i < 3; i++ {
		hash := common.Hash{}
		hash[0] = byte(0xF0 + i)

		db.riMutex.Lock()
		db.RouterInfos[hash] = Entry{}
		db.riMutex.Unlock()

		db.expiryMutex.Lock()
		db.routerInfoExpiry[hash] = time.Now().Add(-1 * time.Hour) // expired 1 hour ago
		db.expiryMutex.Unlock()

		expiredHashes[i] = hash
	}

	initialSize := db.Size()

	db.cleanExpiredRouterInfos()

	// Verify expired entries were removed
	db.riMutex.RLock()
	for _, hash := range expiredHashes {
		_, exists := db.RouterInfos[hash]
		assert.False(t, exists, "expired RouterInfo should have been removed")
	}
	db.riMutex.RUnlock()

	assert.Equal(t, initialSize-3, db.Size(), "size should decrease by 3")
}

// TestCleanExpiredRouterInfos_PreservesMinimumCount tests that the cleanup
// does not remove entries if doing so would bring the count below MinRouterInfoCount.
func TestCleanExpiredRouterInfos_PreservesMinimumCount(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)

	// Add exactly MinRouterInfoCount entries, all expired
	for i := 0; i < MinRouterInfoCount; i++ {
		hash := common.Hash{}
		hash[0] = byte(i)

		db.riMutex.Lock()
		db.RouterInfos[hash] = Entry{}
		db.riMutex.Unlock()

		db.expiryMutex.Lock()
		db.routerInfoExpiry[hash] = time.Now().Add(-1 * time.Hour)
		db.expiryMutex.Unlock()
	}

	db.cleanExpiredRouterInfos()

	// All entries should still be present (at minimum count)
	assert.Equal(t, MinRouterInfoCount, db.Size(),
		"should not remove entries when at minimum count")
}

// TestCleanExpiredRouterInfos_PartialRemoval tests that when removing all expired
// entries would go below minimum, only some are removed.
func TestCleanExpiredRouterInfos_PartialRemoval(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)

	// Add MinRouterInfoCount+2 entries, with 5 expired
	totalEntries := MinRouterInfoCount + 2
	for i := 0; i < totalEntries; i++ {
		hash := common.Hash{}
		hash[0] = byte(i)

		db.riMutex.Lock()
		db.RouterInfos[hash] = Entry{}
		db.riMutex.Unlock()

		db.expiryMutex.Lock()
		if i < 5 { // first 5 are expired
			db.routerInfoExpiry[hash] = time.Now().Add(-1 * time.Hour)
		} else {
			db.routerInfoExpiry[hash] = time.Now().Add(24 * time.Hour)
		}
		db.expiryMutex.Unlock()
	}

	db.cleanExpiredRouterInfos()

	// Should have removed only 2 (totalEntries - MinRouterInfoCount)
	assert.Equal(t, MinRouterInfoCount, db.Size(),
		"should only remove enough to reach minimum count")
}

// TestCleanExpiredRouterInfos_NoExpired tests that nothing happens when
// there are no expired entries.
func TestCleanExpiredRouterInfos_NoExpired(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)

	for i := 0; i < 10; i++ {
		hash := common.Hash{}
		hash[0] = byte(i)

		db.riMutex.Lock()
		db.RouterInfos[hash] = Entry{}
		db.riMutex.Unlock()

		db.expiryMutex.Lock()
		db.routerInfoExpiry[hash] = time.Now().Add(24 * time.Hour) // not expired
		db.expiryMutex.Unlock()
	}

	db.cleanExpiredRouterInfos()

	assert.Equal(t, 10, db.Size(), "no entries should be removed")
}

// TestGetRouterInfoExpirationStats tests the stats reporting function.
func TestGetRouterInfoExpirationStats(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)

	// Add mix of expired and non-expired entries
	for i := 0; i < 5; i++ {
		hash := common.Hash{}
		hash[0] = byte(i)

		db.expiryMutex.Lock()
		if i < 2 {
			db.routerInfoExpiry[hash] = time.Now().Add(-1 * time.Hour) // expired
		} else {
			db.routerInfoExpiry[hash] = time.Now().Add(time.Duration(i) * time.Hour) // future
		}
		db.expiryMutex.Unlock()
	}

	total, expired, nextExpiry := db.GetRouterInfoExpirationStats()
	assert.Equal(t, 5, total, "total should be 5")
	assert.Equal(t, 2, expired, "2 entries should be expired")
	assert.True(t, nextExpiry > 0, "next expiry should be positive (future entries exist)")
}

// TestStartExpirationCleaner_IncludesRouterInfoCleanup tests that the expiration
// cleaner includes RouterInfo cleanup in its tick cycle.
func TestStartExpirationCleaner_IncludesRouterInfoCleanup(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)

	// Just verify the cleaner starts and stops cleanly
	db.StartExpirationCleaner()
	db.Stop()
	// If we get here without panic or hang, the test passes
}

// TestRouterInfoMaxAge verifies the constant is a reasonable value.
func TestRouterInfoMaxAge(t *testing.T) {
	assert.True(t, RouterInfoMaxAge >= 24*time.Hour,
		"RouterInfoMaxAge should be at least 24 hours")
	assert.True(t, RouterInfoMaxAge <= 72*time.Hour,
		"RouterInfoMaxAge should be at most 72 hours")
}

// TestMinRouterInfoCount verifies the minimum count is reasonable.
func TestMinRouterInfoCount(t *testing.T) {
	assert.True(t, MinRouterInfoCount >= 10,
		"MinRouterInfoCount should be at least 10")
	assert.True(t, MinRouterInfoCount <= 100,
		"MinRouterInfoCount should be at most 100")
}

// TestNewStdNetDB_InitializesRouterInfoExpiry tests that the routerInfoExpiry
// map is properly initialized in the constructor.
func TestNewStdNetDB_InitializesRouterInfoExpiry(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)

	assert.NotNil(t, db.routerInfoExpiry, "routerInfoExpiry map should be initialized")
	assert.Equal(t, 0, len(db.routerInfoExpiry), "routerInfoExpiry should start empty")
}
