package netdb

import (
	"sync"
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestStdNetDB_Size_EmptyDatabase tests Size() returns 0 for empty database
func TestStdNetDB_Size_EmptyDatabase(t *testing.T) {
	tempDir := t.TempDir()
	db := NewStdNetDB(tempDir)

	size := db.Size()
	assert.Equal(t, 0, size, "Empty database should have size 0")
}

// TestStdNetDB_Size_SingleEntry tests Size() returns 1 after adding one RouterInfo
func TestStdNetDB_Size_SingleEntry(t *testing.T) {
	tempDir := t.TempDir()
	db := NewStdNetDB(tempDir)

	// Add one RouterInfo to the in-memory map
	var testHash common.Hash
	testHash[0] = 0x01

	ri := router_info.RouterInfo{}
	db.riMutex.Lock()
	db.RouterInfos[testHash] = Entry{RouterInfo: &ri}
	db.riMutex.Unlock()

	size := db.Size()
	assert.Equal(t, 1, size, "Database with one entry should have size 1")
}

// TestStdNetDB_Size_MultipleEntries tests Size() with multiple RouterInfos
func TestStdNetDB_Size_MultipleEntries(t *testing.T) {
	tempDir := t.TempDir()
	db := NewStdNetDB(tempDir)

	// Add multiple RouterInfos
	expectedCount := 5
	for i := 0; i < expectedCount; i++ {
		var testHash common.Hash
		testHash[0] = byte(i)

		ri := router_info.RouterInfo{}
		db.riMutex.Lock()
		db.RouterInfos[testHash] = Entry{RouterInfo: &ri}
		db.riMutex.Unlock()
	}

	size := db.Size()
	assert.Equal(t, expectedCount, size, "Database should report correct count of entries")
}

// TestStdNetDB_Size_AfterRemoval tests Size() decreases after removing entries
func TestStdNetDB_Size_AfterRemoval(t *testing.T) {
	tempDir := t.TempDir()
	db := NewStdNetDB(tempDir)

	// Add multiple RouterInfos
	hashes := make([]common.Hash, 3)
	for i := 0; i < 3; i++ {
		hashes[i][0] = byte(i)
		ri := router_info.RouterInfo{}
		db.riMutex.Lock()
		db.RouterInfos[hashes[i]] = Entry{RouterInfo: &ri}
		db.riMutex.Unlock()
	}

	// Verify initial size
	assert.Equal(t, 3, db.Size(), "Should have 3 entries")

	// Remove one entry
	db.riMutex.Lock()
	delete(db.RouterInfos, hashes[0])
	db.riMutex.Unlock()

	// Verify size decreased
	assert.Equal(t, 2, db.Size(), "Should have 2 entries after removal")

	// Remove all entries
	db.riMutex.Lock()
	delete(db.RouterInfos, hashes[1])
	delete(db.RouterInfos, hashes[2])
	db.riMutex.Unlock()

	// Verify size is 0
	assert.Equal(t, 0, db.Size(), "Should have 0 entries after removing all")
}

// TestStdNetDB_Size_ConcurrentReads tests that Size() is safe for concurrent reads
func TestStdNetDB_Size_ConcurrentReads(t *testing.T) {
	tempDir := t.TempDir()
	db := NewStdNetDB(tempDir)

	// Add some entries
	for i := 0; i < 10; i++ {
		var testHash common.Hash
		testHash[0] = byte(i)
		ri := router_info.RouterInfo{}
		db.riMutex.Lock()
		db.RouterInfos[testHash] = Entry{RouterInfo: &ri}
		db.riMutex.Unlock()
	}

	// Perform multiple concurrent reads
	var wg sync.WaitGroup
	readers := 10
	results := make([]int, readers)

	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			results[index] = db.Size()
		}(i)
	}

	wg.Wait()

	// All readers should get the same value
	for i, result := range results {
		assert.Equal(t, 10, result, "Reader %d should get correct size", i)
	}
}

// TestStdNetDB_Size_ConcurrentReadWrite tests Size() during concurrent reads and writes
func TestStdNetDB_Size_ConcurrentReadWrite(t *testing.T) {
	tempDir := t.TempDir()
	db := NewStdNetDB(tempDir)

	var wg sync.WaitGroup
	writers := 5
	readers := 5

	// Start writers
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			var testHash common.Hash
			testHash[0] = byte(index)
			ri := router_info.RouterInfo{}
			db.riMutex.Lock()
			db.RouterInfos[testHash] = Entry{RouterInfo: &ri}
			db.riMutex.Unlock()
		}(i)
	}

	// Start readers
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Just ensure Size() doesn't panic or deadlock
			_ = db.Size()
		}()
	}

	wg.Wait()

	// Final size should be the number of writers
	finalSize := db.Size()
	assert.Equal(t, writers, finalSize, "Final size should match number of writes")
}

// TestStdNetDB_Size_LargeDatabase tests Size() with many entries
func TestStdNetDB_Size_LargeDatabase(t *testing.T) {
	tempDir := t.TempDir()
	db := NewStdNetDB(tempDir)

	// Add many entries
	expectedCount := 1000
	for i := 0; i < expectedCount; i++ {
		var testHash common.Hash
		// Use more bytes to ensure uniqueness
		testHash[0] = byte(i >> 8)
		testHash[1] = byte(i & 0xFF)

		ri := router_info.RouterInfo{}
		db.riMutex.Lock()
		db.RouterInfos[testHash] = Entry{RouterInfo: &ri}
		db.riMutex.Unlock()
	}

	size := db.Size()
	assert.Equal(t, expectedCount, size, "Database should handle large number of entries")
}

// TestStdNetDB_Size_DuplicateHash tests that duplicate hashes don't increase size
func TestStdNetDB_Size_DuplicateHash(t *testing.T) {
	tempDir := t.TempDir()
	db := NewStdNetDB(tempDir)

	var testHash common.Hash
	testHash[0] = 0x01

	// Add same hash twice
	ri1 := router_info.RouterInfo{}
	db.riMutex.Lock()
	db.RouterInfos[testHash] = Entry{RouterInfo: &ri1}
	db.riMutex.Unlock()

	assert.Equal(t, 1, db.Size(), "Should have 1 entry")

	// Add again with same hash (should replace, not add)
	ri2 := router_info.RouterInfo{}
	db.riMutex.Lock()
	db.RouterInfos[testHash] = Entry{RouterInfo: &ri2}
	db.riMutex.Unlock()

	assert.Equal(t, 1, db.Size(), "Duplicate hash should not increase size")
}

// TestStdNetDB_Size_ThreadSafety tests mutex protection in Size()
func TestStdNetDB_Size_ThreadSafety(t *testing.T) {
	tempDir := t.TempDir()
	db := NewStdNetDB(tempDir)

	// This test ensures Size() properly uses mutex locking
	// Run with -race flag to detect race conditions

	iterations := 100
	var wg sync.WaitGroup

	// Concurrent writers and readers
	for i := 0; i < iterations; i++ {
		wg.Add(2)

		// Writer goroutine
		go func(index int) {
			defer wg.Done()
			var testHash common.Hash
			testHash[0] = byte(index >> 8)
			testHash[1] = byte(index & 0xFF)
			ri := router_info.RouterInfo{}
			db.riMutex.Lock()
			db.RouterInfos[testHash] = Entry{RouterInfo: &ri}
			db.riMutex.Unlock()
		}(i)

		// Reader goroutine
		go func() {
			defer wg.Done()
			_ = db.Size() // Should not race with writers
		}()
	}

	wg.Wait()

	// Verify final count
	finalSize := db.Size()
	assert.Equal(t, iterations, finalSize, "All writes should be counted")
}

// TestStdNetDB_RecalculateSize_NoOp tests that RecalculateSize is now a no-op
func TestStdNetDB_RecalculateSize_NoOp(t *testing.T) {
	tempDir := t.TempDir()
	db := NewStdNetDB(tempDir)

	// Add some entries
	for i := 0; i < 5; i++ {
		var testHash common.Hash
		testHash[0] = byte(i)
		ri := router_info.RouterInfo{}
		db.riMutex.Lock()
		db.RouterInfos[testHash] = Entry{RouterInfo: &ri}
		db.riMutex.Unlock()
	}

	// RecalculateSize should not affect Size() result
	sizeBefore := db.Size()
	err := db.RecalculateSize()
	require.NoError(t, err, "RecalculateSize should not return error")
	sizeAfter := db.Size()

	assert.Equal(t, sizeBefore, sizeAfter, "RecalculateSize should not change Size() result")
	assert.Equal(t, 5, sizeAfter, "Size should still be accurate")
}

// BenchmarkStdNetDB_Size benchmarks the Size() method
func BenchmarkStdNetDB_Size(b *testing.B) {
	tempDir := b.TempDir()
	db := NewStdNetDB(tempDir)

	// Add some entries
	for i := 0; i < 100; i++ {
		var testHash common.Hash
		testHash[0] = byte(i)
		ri := router_info.RouterInfo{}
		db.riMutex.Lock()
		db.RouterInfos[testHash] = Entry{RouterInfo: &ri}
		db.riMutex.Unlock()
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = db.Size()
	}
}

// BenchmarkStdNetDB_Size_Parallel benchmarks Size() under concurrent access
func BenchmarkStdNetDB_Size_Parallel(b *testing.B) {
	tempDir := b.TempDir()
	db := NewStdNetDB(tempDir)

	// Add entries
	for i := 0; i < 100; i++ {
		var testHash common.Hash
		testHash[0] = byte(i)
		ri := router_info.RouterInfo{}
		db.riMutex.Lock()
		db.RouterInfos[testHash] = Entry{RouterInfo: &ri}
		db.riMutex.Unlock()
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = db.Size()
		}
	})
}
