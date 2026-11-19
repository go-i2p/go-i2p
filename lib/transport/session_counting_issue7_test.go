// Regression tests for Issue 7: session-count accounting must never go
// negative under double-teardown. The CRITICAL log
// "sessionCount would go negative on decrement (accounting bug detected)"
// fires when a session is decremented more times than it was incremented,
// which violates the SA-2 invariant (sessionCount == live session-map entries).
//
// These tests exercise the registry's idempotent removal primitives directly:
// Remove and RemoveIfSession are delete-then-decrement guarded by the map
// delete reporting "existed", so a second teardown of an already-removed
// session must be a no-op rather than a second decrement.
package transport

import (
	"sync"
	"testing"

	"github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testHash(b byte) data.Hash {
	var h data.Hash
	h[0] = b
	return h
}

// TestSessionRegistry_DoubleRemoveDoesNotGoNegative verifies that removing the
// same peer twice decrements the count exactly once: the second Remove finds
// the entry already gone and must not decrement again.
func TestSessionRegistry_DoubleRemoveDoesNotGoNegative(t *testing.T) {
	registry := NewSessionRegistry(log.WithField("test", t.Name()))
	peerHash := testHash(0x71)

	session := &struct{ id string }{id: "session"}
	registry.StoreWithCount(peerHash, session)
	require.Equal(t, int32(1), registry.Count(), "one session stored")

	// First removal: entry exists, count drops to 0.
	registry.Remove(peerHash)
	assert.Equal(t, int32(0), registry.Count(), "first Remove must decrement once")

	// Second removal of the same (already-removed) peer: must be a no-op.
	registry.Remove(peerHash)
	assert.Equal(t, int32(0), registry.Count(), "second Remove must not decrement again")

	// Count must never have gone negative and must match the (now empty) map.
	assert.Equal(t, int32(0), registry.Count())
	assert.Equal(t, 0, mapEntryCount(registry), "map must be empty")
}

// TestSessionRegistry_DoubleRemoveIfSessionDoesNotGoNegative verifies the
// identity-scoped removal is idempotent: closing the same session twice (e.g.
// an explicit Close plus a connection-lost handler) decrements exactly once.
func TestSessionRegistry_DoubleRemoveIfSessionDoesNotGoNegative(t *testing.T) {
	registry := NewSessionRegistry(log.WithField("test", t.Name()))
	peerHash := testHash(0x72)

	session := &struct{ id string }{id: "session"}
	registry.StoreWithCount(peerHash, session)
	require.Equal(t, int32(1), registry.Count())

	// First teardown wins the CompareAndDelete and decrements.
	require.True(t, registry.RemoveIfSession(peerHash, session), "first removal must succeed")
	assert.Equal(t, int32(0), registry.Count())

	// Second teardown of the same session: entry is gone, CAS fails, no decrement.
	require.False(t, registry.RemoveIfSession(peerHash, session), "second removal must be a no-op")
	assert.Equal(t, int32(0), registry.Count(), "second RemoveIfSession must not decrement")

	assert.Equal(t, 0, mapEntryCount(registry))
}

// TestSessionRegistry_CloseAndConnectionLostRace is the core concurrency
// regression: a session torn down by two racing paths (an explicit close and a
// connection-lost/cleanup sweep) must decrement the count exactly once, never
// go negative, and leave the count matching the map size.
func TestSessionRegistry_CloseAndConnectionLostRace(t *testing.T) {
	registry := NewSessionRegistry(log.WithField("test", t.Name()))

	const numPeers = 200
	peers := make([]data.Hash, numPeers)
	sessions := make([]interface{}, numPeers)
	for i := 0; i < numPeers; i++ {
		peers[i] = testHash(byte(i + 1))
		sessions[i] = &struct{ id int }{id: i}
		registry.StoreWithCount(peers[i], sessions[i])
	}
	require.Equal(t, int32(numPeers), registry.Count(), "all peers stored and counted")

	// For each peer, race two teardown paths that both call RemoveIfSession
	// with the same session identity. Exactly one should decrement.
	var wg sync.WaitGroup
	for i := 0; i < numPeers; i++ {
		wg.Add(2)
		go func(idx int) {
			defer wg.Done()
			registry.RemoveIfSession(peers[idx], sessions[idx]) // explicit close
		}(i)
		go func(idx int) {
			defer wg.Done()
			registry.RemoveIfSession(peers[idx], sessions[idx]) // connection-lost sweep
		}(i)
	}
	wg.Wait()

	// After every peer is torn down by two racing paths, the count must be
	// exactly 0 (one decrement per peer, never two), never negative, and must
	// match the (now empty) map.
	assert.Equal(t, int32(0), registry.Count(), "count must be exactly 0 after double-teardown of all peers")
	assert.Equal(t, 0, mapEntryCount(registry), "map must be empty")
	assert.Equal(t, registry.Count(), int32(mapEntryCount(registry)), "SA-2 invariant: count must equal map size")
}

// mapEntryCount counts all entries currently in the registry's map.
func mapEntryCount(registry *SessionRegistry) int {
	count := 0
	registry.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	return count
}
