package ntcp2

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReplayCache_NewKeyNotReplay(t *testing.T) {
	rc := NewReplayCache()
	defer rc.Close()

	var key [32]byte
	key[0] = 0x42
	assert.False(t, rc.CheckAndAdd(key), "first insert should not be a replay")
}

func TestReplayCache_DuplicateKeyIsReplay(t *testing.T) {
	rc := NewReplayCache()
	defer rc.Close()

	var key [32]byte
	key[0] = 0x42

	assert.False(t, rc.CheckAndAdd(key))
	assert.True(t, rc.CheckAndAdd(key), "second insert should be detected as replay")
}

func TestReplayCache_DifferentKeysNotReplay(t *testing.T) {
	rc := NewReplayCache()
	defer rc.Close()

	var key1, key2 [32]byte
	key1[0] = 0x01
	key2[0] = 0x02

	assert.False(t, rc.CheckAndAdd(key1))
	assert.False(t, rc.CheckAndAdd(key2))
}

func TestReplayCache_Size(t *testing.T) {
	rc := NewReplayCache()
	defer rc.Close()

	assert.Equal(t, 0, rc.Size())

	var key1, key2 [32]byte
	key1[0] = 0x01
	key2[0] = 0x02

	rc.CheckAndAdd(key1)
	assert.Equal(t, 1, rc.Size())

	rc.CheckAndAdd(key2)
	assert.Equal(t, 2, rc.Size())

	// Duplicate doesn't increase size
	rc.CheckAndAdd(key1)
	assert.Equal(t, 2, rc.Size())
}

func TestReplayCache_Concurrent(t *testing.T) {
	rc := NewReplayCache()
	defer rc.Close()

	const numGoroutines = 100
	var wg sync.WaitGroup

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			var key [32]byte
			key[0] = byte(idx % 10) // Some collisions expected
			rc.CheckAndAdd(key)
		}(i)
	}

	wg.Wait()
	// Should have at most 10 unique keys
	assert.LessOrEqual(t, rc.Size(), 10)
	assert.Greater(t, rc.Size(), 0)
}

func TestReplayCache_EvictExpired(t *testing.T) {
	rc := NewReplayCache()
	defer rc.Close()

	// Manually insert an entry with an old timestamp
	var key [32]byte
	key[0] = 0x01

	rc.mu.Lock()
	rc.entries[key] = time.Now().Add(-3 * replayCacheTTL) // way past TTL
	rc.mu.Unlock()

	assert.Equal(t, 1, rc.Size())
	rc.evictExpired()
	assert.Equal(t, 0, rc.Size())
}

func TestReplayCache_ExpiredKeyNotReplay(t *testing.T) {
	rc := NewReplayCache()
	defer rc.Close()

	var key [32]byte
	key[0] = 0x42

	// Insert with backdated timestamp (expired)
	rc.mu.Lock()
	rc.entries[key] = time.Now().Add(-3 * replayCacheTTL)
	rc.mu.Unlock()

	// Should not be considered a replay since the entry is expired
	assert.False(t, rc.CheckAndAdd(key))
}

func TestReplayCache_MaxSizeEviction(t *testing.T) {
	rc := NewReplayCache()
	defer rc.Close()

	// Fill cache to near max
	rc.mu.Lock()
	for i := 0; i < replayCacheMaxSize; i++ {
		var key [32]byte
		key[0] = byte(i >> 24)
		key[1] = byte(i >> 16)
		key[2] = byte(i >> 8)
		key[3] = byte(i)
		rc.entries[key] = time.Now()
	}
	rc.mu.Unlock()

	require.Equal(t, replayCacheMaxSize, rc.Size())

	// Adding one more should trigger eviction
	var newKey [32]byte
	newKey[31] = 0xFF
	rc.CheckAndAdd(newKey)

	// Size should be less than or equal to max
	assert.LessOrEqual(t, rc.Size(), replayCacheMaxSize)
}
