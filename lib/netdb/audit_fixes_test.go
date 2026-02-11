package netdb

import (
	"bytes"
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/stretchr/testify/assert"
)

// TestCongestionCache_TTLEvictsFromMap verifies that expired entries are
// actually removed from the cache map when Get encounters them, not just
// hidden from the return value.
func TestCongestionCache_TTLEvictsFromMap(t *testing.T) {
	cache := &CongestionCache{
		flags:   make(map[common.Hash]cachedFlag),
		maxSize: 100,
		ttl:     50 * time.Millisecond,
	}

	hash := testCongestionHash(100)
	cache.Set(hash, config.CongestionFlagD, time.Now())

	// Should be in the map
	assert.Equal(t, 1, cache.Size())

	// Wait for TTL to expire
	time.Sleep(60 * time.Millisecond)

	// Get should return not-found AND evict the expired entry
	_, _, found := cache.Get(hash)
	assert.False(t, found, "expired entry should not be returned")

	// The entry should actually be removed from the map
	assert.Equal(t, 0, cache.Size(), "expired entry should be evicted from cache")
}

// TestCongestionCache_TTLEvictionConcurrent verifies that concurrent TTL
// eviction doesn't cause races or panics.
func TestCongestionCache_TTLEvictionConcurrent(t *testing.T) {
	cache := &CongestionCache{
		flags:   make(map[common.Hash]cachedFlag),
		maxSize: 100,
		ttl:     10 * time.Millisecond,
	}

	// Add entries
	for i := 0; i < 20; i++ {
		cache.Set(testCongestionHash(byte(i)), config.CongestionFlagG, time.Now())
	}

	// Wait for TTL to expire
	time.Sleep(20 * time.Millisecond)

	// Concurrently read all entries (triggering evictions)
	done := make(chan bool, 20)
	for i := 0; i < 20; i++ {
		go func(idx int) {
			cache.Get(testCongestionHash(byte(idx)))
			done <- true
		}(i)
	}

	for i := 0; i < 20; i++ {
		<-done
	}

	// All entries should be evicted
	assert.Equal(t, 0, cache.Size(), "all expired entries should be evicted")
}

// TestPeerTracker_EMAConvergence verifies that the exponential moving average
// stabilizes properly and gives appropriate weight to history vs new samples.
func TestPeerTracker_EMAConvergence(t *testing.T) {
	pt := NewPeerTracker()
	hash := testHash(0xEE)

	// Record 10 samples of 100ms
	for i := 0; i < 10; i++ {
		pt.RecordSuccess(hash, 100)
	}

	stats := pt.GetStats(hash)
	assert.Equal(t, int64(100), stats.AvgResponseTimeMs,
		"constant samples should converge to the sample value")

	// Record a single spike of 1000ms
	pt.RecordSuccess(hash, 1000)
	stats = pt.GetStats(hash)

	// With alpha=0.2: 0.2*1000 + 0.8*100 = 200+80 = 280
	// A single outlier should NOT dominate (old formula would give (100+1000)/2 = 550)
	assert.Equal(t, int64(280), stats.AvgResponseTimeMs,
		"EMA should dampen impact of single outlier")
	assert.True(t, stats.AvgResponseTimeMs < 500,
		"EMA should be less than 500 (old formula gave 550)")
}

// TestEntry_ReadFromShortReader verifies that readEntryType and readDataLength
// properly handle readers that return short reads without error.
func TestEntry_ReadFromShortReader(t *testing.T) {
	e := &Entry{}

	// io.ReadFull should handle zero-byte reads by retrying until full or error
	// Test with an empty reader — should get an error, not proceed with zero bytes
	emptyReader := bytes.NewReader([]byte{})
	_, err := e.readEntryType(emptyReader)
	assert.Error(t, err, "readEntryType should error on empty reader")

	_, err = e.readDataLength(emptyReader)
	assert.Error(t, err, "readDataLength should error on empty reader")

	// Test with valid data — should succeed
	validReader := bytes.NewReader([]byte{0x01})
	entryType, err := e.readEntryType(validReader)
	assert.NoError(t, err)
	assert.Equal(t, byte(0x01), entryType)

	// Test readDataLength with valid 2-byte data
	validLenReader := bytes.NewReader([]byte{0x00, 0x0A}) // length = 10
	dataLen, err := e.readDataLength(validLenReader)
	assert.NoError(t, err)
	assert.Equal(t, uint16(10), dataLen)
}
