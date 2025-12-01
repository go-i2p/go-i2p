package netdb

import (
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/lease_set"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetAllLeaseSets_Empty tests GetAllLeaseSets on an empty database
func TestGetAllLeaseSets_Empty(t *testing.T) {
	db := NewStdNetDB(t.TempDir())
	require.NoError(t, db.Ensure())

	// Get all LeaseSets from empty database
	leaseSets := db.GetAllLeaseSets()

	// Should return empty slice, not nil
	assert.NotNil(t, leaseSets)
	assert.Empty(t, leaseSets)
}

// TestGetAllLeaseSets_WithEntries tests GetAllLeaseSets with in-memory entries
func TestGetAllLeaseSets_WithEntries(t *testing.T) {
	db := NewStdNetDB(t.TempDir())
	require.NoError(t, db.Ensure())

	// Manually add entries to the in-memory cache
	// Note: We're testing the GetAllLeaseSets method, not the full storage/retrieval flow
	hash1 := common.Hash{0x01, 0x02, 0x03}
	hash2 := common.Hash{0x04, 0x05, 0x06}
	hash3 := common.Hash{0x07, 0x08, 0x09}

	// Create placeholder LeaseSet entries
	ls1 := lease_set.LeaseSet{}
	ls2 := lease_set.LeaseSet{}
	ls3 := lease_set.LeaseSet{}

	db.lsMutex.Lock()
	db.LeaseSets[hash1] = Entry{LeaseSet: &ls1}
	db.LeaseSets[hash2] = Entry{LeaseSet: &ls2}
	db.LeaseSets[hash3] = Entry{LeaseSet: &ls3}
	db.lsMutex.Unlock()

	// Get all LeaseSets
	leaseSets := db.GetAllLeaseSets()

	// Should return exactly 3 LeaseSets
	assert.Len(t, leaseSets, 3)

	// Verify all hashes are present
	hashes := make(map[common.Hash]bool)
	for _, lsEntry := range leaseSets {
		hashes[lsEntry.Hash] = true
		assert.NotNil(t, lsEntry.Entry.LeaseSet)
	}

	assert.True(t, hashes[hash1])
	assert.True(t, hashes[hash2])
	assert.True(t, hashes[hash3])
}

// TestGetAllLeaseSets_Concurrent tests GetAllLeaseSets with concurrent access
func TestGetAllLeaseSets_Concurrent(t *testing.T) {
	db := NewStdNetDB(t.TempDir())
	require.NoError(t, db.Ensure())

	// Add an entry
	hash := common.Hash{0x01, 0x02, 0x03}
	ls := lease_set.LeaseSet{}

	db.lsMutex.Lock()
	db.LeaseSets[hash] = Entry{LeaseSet: &ls}
	db.lsMutex.Unlock()

	// Concurrent reads should not panic or race
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			defer func() {
				done <- true
			}()
			leaseSets := db.GetAllLeaseSets()
			assert.NotNil(t, leaseSets)
			assert.GreaterOrEqual(t, len(leaseSets), 1)
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}

// TestGetAllLeaseSets_CountMatch tests that GetAllLeaseSets count matches GetLeaseSetCount
func TestGetAllLeaseSets_CountMatch(t *testing.T) {
	db := NewStdNetDB(t.TempDir())
	require.NoError(t, db.Ensure())

	// Add multiple entries directly to cache
	for i := 0; i < 5; i++ {
		hash := common.Hash{byte(i), byte(i + 1), byte(i + 2)}
		ls := lease_set.LeaseSet{}

		db.lsMutex.Lock()
		db.LeaseSets[hash] = Entry{LeaseSet: &ls}
		db.lsMutex.Unlock()
	}

	// Count should match
	count := db.GetLeaseSetCount()
	leaseSets := db.GetAllLeaseSets()

	assert.Equal(t, count, len(leaseSets), "GetLeaseSetCount should match GetAllLeaseSets length")
	assert.Equal(t, 5, len(leaseSets))
}

// BenchmarkGetAllLeaseSets benchmarks the GetAllLeaseSets method
func BenchmarkGetAllLeaseSets(b *testing.B) {
	db := NewStdNetDB(b.TempDir())
	if err := db.Ensure(); err != nil {
		b.Fatal(err)
	}

	// Pre-populate with 100 LeaseSets
	db.lsMutex.Lock()
	for i := 0; i < 100; i++ {
		hash := common.Hash{byte(i), byte(i >> 8), byte(i >> 16)}
		ls := lease_set.LeaseSet{}
		db.LeaseSets[hash] = Entry{LeaseSet: &ls}
	}
	db.lsMutex.Unlock()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = db.GetAllLeaseSets()
	}
}
