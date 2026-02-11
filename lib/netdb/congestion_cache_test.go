package netdb

import (
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/stretchr/testify/assert"
)

func testCongestionHash(id byte) common.Hash {
	var h common.Hash
	h[0] = id
	return h
}

func TestCongestionCache_MaxSizeEviction(t *testing.T) {
	cache := &CongestionCache{
		flags:   make(map[common.Hash]cachedFlag),
		maxSize: 3,
		ttl:     30 * time.Minute,
	}

	// Fill to capacity
	for i := byte(1); i <= 3; i++ {
		cache.Set(testCongestionHash(i), config.CongestionFlagD, time.Now())
	}
	assert.Equal(t, 3, cache.Size())

	// Adding a 4th should evict the oldest
	cache.Set(testCongestionHash(4), config.CongestionFlagE, time.Now())
	assert.Equal(t, 3, cache.Size(), "cache should not exceed maxSize")
}

func TestCongestionCache_TTLExpiration(t *testing.T) {
	cache := &CongestionCache{
		flags:   make(map[common.Hash]cachedFlag),
		maxSize: 100,
		ttl:     50 * time.Millisecond,
	}

	hash := testCongestionHash(1)
	cache.Set(hash, config.CongestionFlagG, time.Now())

	// Should be found immediately
	flag, _, found := cache.Get(hash)
	assert.True(t, found)
	assert.Equal(t, config.CongestionFlagG, flag)

	// After TTL expires, should not be found
	time.Sleep(60 * time.Millisecond)
	_, _, found = cache.Get(hash)
	assert.False(t, found, "expired entry should not be returned")
}

func TestCongestionCache_DefaultLimits(t *testing.T) {
	cache := NewCongestionCache()
	assert.Equal(t, 2048, cache.maxSize, "default max size should be 2048")
	assert.Equal(t, 30*time.Minute, cache.ttl, "default TTL should be 30 minutes")
}

func TestCongestionCache_EvictsOldestEntry(t *testing.T) {
	cache := &CongestionCache{
		flags:   make(map[common.Hash]cachedFlag),
		maxSize: 2,
		ttl:     0, // no TTL for this test
	}

	h1 := testCongestionHash(1)
	h2 := testCongestionHash(2)
	h3 := testCongestionHash(3)

	// Add h1, then wait briefly, then h2
	cache.Set(h1, config.CongestionFlagD, time.Now())
	time.Sleep(5 * time.Millisecond)
	cache.Set(h2, config.CongestionFlagE, time.Now())

	// Adding h3 should evict h1 (oldest)
	cache.Set(h3, config.CongestionFlagG, time.Now())

	_, _, found := cache.Get(h1)
	assert.False(t, found, "h1 should have been evicted as the oldest")

	_, _, found = cache.Get(h2)
	assert.True(t, found, "h2 should still be present")

	_, _, found = cache.Get(h3)
	assert.True(t, found, "h3 should be present")
}
