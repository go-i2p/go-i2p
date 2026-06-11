package ssu2

import (
	"sync"
	"testing"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/transport"
	"github.com/go-i2p/logger"
	"github.com/stretchr/testify/assert"
)

// SA-2: Test that SessionRegistry.SetShutdown() marks shutdown state correctly.
func TestSessionRegistry_SetShutdown(t *testing.T) {
	registry := transport.NewSessionRegistry(logger.WithField("test", "shutdown"))

	// Initially not shutting down
	assert.False(t, registry.IsShuttingDown())

	// Set shutdown
	registry.SetShutdown()
	assert.True(t, registry.IsShuttingDown())
}

// SA-2: Test that DecrementCountSafe handles concurrent decrements correctly.
func TestSessionRegistry_DecrementCountSafe(t *testing.T) {
	registry := transport.NewSessionRegistry(logger.WithField("test", "decrement"))

	// Manually set count to 5 for testing
	registry.CheckLimitAndIncrement(100) // +1 = 1
	registry.CheckLimitAndIncrement(100) // +1 = 2
	registry.CheckLimitAndIncrement(100) // +1 = 3
	registry.CheckLimitAndIncrement(100) // +1 = 4
	registry.CheckLimitAndIncrement(100) // +1 = 5

	assert.Equal(t, int32(5), registry.Count())

	// Decrement once
	registry.DecrementCountSafe()
	assert.Equal(t, int32(4), registry.Count())

	// Decrement again
	registry.DecrementCountSafe()
	assert.Equal(t, int32(3), registry.Count())
}

// SA-2: Test that concurrent Remove calls update count correctly.
func TestSessionRegistry_ConcurrentRemove(t *testing.T) {
	registry := transport.NewSessionRegistry(logger.WithField("test", "concurrent_remove"))

	// Set up 10 sessions with count
	hashes := make([]data.Hash, 10)
	for i := 0; i < 10; i++ {
		h := data.Hash{byte(i)}
		hashes[i] = h
		registry.StoreWithCount(h, &struct{}{})
	}

	assert.Equal(t, int32(10), registry.Count())

	// Concurrently remove all sessions
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			registry.Remove(hashes[idx])
		}(i)
	}

	wg.Wait()

	// All should be removed
	assert.Equal(t, int32(0), registry.Count())

	// Verify none are in map
	count := 0
	registry.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	assert.Equal(t, 0, count, "Expected no sessions in map")
}

// SA-2: Test Remove protection against negative count.
func TestSessionRegistry_DecrementNeverNegative(t *testing.T) {
	registry := transport.NewSessionRegistry(logger.WithField("test", "decrement_never_negative"))

	// Try to decrement when count is 0 - should not go negative
	registry.DecrementCountSafe()
	assert.Equal(t, int32(0), registry.Count())

	// Try multiple times - should stay at 0
	registry.DecrementCountSafe()
	registry.DecrementCountSafe()
	assert.Equal(t, int32(0), registry.Count())
}
