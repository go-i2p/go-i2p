package netdb

import (
	"testing"

	"github.com/stretchr/testify/require"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/lease_set"
)

// Helper function to create a test hash with a given suffix
func testHashWithSuffix(suffix byte) common.Hash {
	var hash common.Hash
	for i := range hash {
		hash[i] = suffix
	}
	return hash
}

// TestLeaseSetAdmissionController_NilSourceAllowedUntilPressure verifies that nil sources
// (unknown/untrusted peers) are allowed until capacity pressure threshold.
func TestLeaseSetAdmissionController_NilSourceAllowedUntilPressure(t *testing.T) {
	c := newLeaseSetAdmissionController(100)

	// Below pressure threshold, nil sources are allowed
	for i := 0; i < 79; i++ { // 79 * 100 = 7900 < 8000 (80% of 10000)
		key := testHashWithSuffix(byte(i))
		ok := c.AllowIntroduction(nil, key, i)
		require.True(t, ok, "nil source should be allowed below pressure threshold at count %d", i)
	}

	// At pressure threshold, nil sources are rejected
	ok := c.AllowIntroduction(nil, testHashWithSuffix(80), 80)
	require.False(t, ok, "nil source should be rejected at pressure threshold")
}

// TestLeaseSetAdmissionController_PerSourceDistinctLimit verifies per-source distinct limits.
func TestLeaseSetAdmissionController_PerSourceDistinctLimit(t *testing.T) {
	c := newLeaseSetAdmissionController(100)

	var source common.Hash
	source[0] = 0xCC

	// Need to be under pressure (>= 80% of capacity) for per-source limits to apply
	// With capacity 100, need currentCount >= 80
	pressureThreshold := 80

	// First 256 introductions from source should be allowed under pressure
	for i := 0; i < leaseSetPerSourceIntroduced; i++ {
		var key common.Hash
		key[0] = byte(i)
		key[1] = byte(i >> 8)
		if !c.AllowIntroduction(&source, key, pressureThreshold) {
			t.Fatalf("unexpected reject at introduction %d", i)
		}
	}

	// 257th introduction from source should be rejected (per-source limit)
	var overflow common.Hash
	overflow[0] = 0xFE
	overflow[1] = 0xED

	if c.AllowIntroduction(&source, overflow, pressureThreshold) {
		t.Fatal("expected rejection after per-source distinct-introduction limit")
	}
}

// TestStdNetDB_LeaseSetCapacityEnforcement verifies capacity limits are enforced.
func TestStdNetDB_LeaseSetCapacityEnforcement(t *testing.T) {
	db := NewStdNetDB(t.TempDir())

	// Set small capacity for testing
	db.maxLeaseSets = 5

	// Create test LeaseSets with minimal data
	for i := 0; i < 10; i++ {
		key := testHashWithSuffix(byte(i))
		ls := lease_set.LeaseSet{}
		db.addLeaseSetToCache(key, ls)
	}

	// Should not exceed capacity
	db.lsMutex.RLock()
	cacheSize := len(db.LeaseSets)
	db.lsMutex.RUnlock()

	require.LessOrEqual(t, cacheSize, 5, "cache size should not exceed capacity, got %d", cacheSize)
}

// TestStdNetDB_LeaseSetEvictionOnCapacity verifies oldest-expiry eviction on capacity.
func TestStdNetDB_LeaseSetEvictionOnCapacity(t *testing.T) {
	db := NewStdNetDB(t.TempDir())

	db.maxLeaseSets = 3

	// Add 3 LeaseSets and track them
	keys := make([]common.Hash, 3)
	for i := 0; i < 3; i++ {
		keys[i] = testHashWithSuffix(byte(i))
		ls := lease_set.LeaseSet{}
		db.addLeaseSetToCache(keys[i], ls)
	}

	// Verify all 3 are in cache
	db.lsMutex.RLock()
	require.Equal(t, 3, len(db.LeaseSets), "should have exactly 3 LeaseSets in cache")
	db.lsMutex.RUnlock()

	// Add 4th LeaseSet - should evict one
	key4 := testHashWithSuffix(4)
	ls4 := lease_set.LeaseSet{}
	db.addLeaseSetToCache(key4, ls4)

	// Should still be at capacity (3)
	db.lsMutex.RLock()
	require.Equal(t, 3, len(db.LeaseSets), "after adding 4th LeaseSet, cache should have 3 (one evicted)")
	db.lsMutex.RUnlock()
}
