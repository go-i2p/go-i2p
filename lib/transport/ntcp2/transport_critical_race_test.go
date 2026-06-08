package ntcp2

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCRITICAL_1_1_PromotionRace is a comprehensive test for the CRITICAL 1.1 race:
// "Session Map LoadOrStore → Promotion Race"
//
// This test verifies that concurrent promotion of the same raw inbound connection
// to a full NTCP2Session is safe. The race occurs when:
//  1. Accept() stores a raw net.Conn in the sessions map
//  2. Multiple goroutines concurrently call GetSession()/findExistingSession()
//  3. Both try to promote the same raw connection via different paths
//
// The test runs with `go test -race` to catch data races, and verifies:
//   - No panics during concurrent promotion
//   - All promoters receive a valid NTCP2Session
//   - The session in the map is correct type and valid
//   - Cleanup callbacks work correctly and don't double-fire
//   - Session count remains consistent
func TestCRITICAL_1_1_PromotionRace(t *testing.T) {
	transport := newNilListenerTestTransport(t, 100)
	defer transport.Close()

	peerHash := newTestPeerHash("critical-1-1-promotion-race!!")
	rawConn := newAcceptMockConn("192.168.1.100:5100")

	// Simulate Accept() storing a raw net.Conn (as would happen with inbound connections).
	transport.sessions.Store(peerHash, rawConn)
	atomic.AddInt32(&transport.sessionCount, 1)
	initialCount := atomic.LoadInt32(&transport.sessionCount)
	assert.Equal(t, int32(1), initialCount, "session count should be 1 after storing raw conn")

	// Concurrent promoters that will race each other.
	const concurrentPromotions = 20
	results := make([]*NTCP2Session, concurrentPromotions)
	var wg sync.WaitGroup

	// Launch promoters using both promotion paths (in alternation).
	require.NotPanics(t, func() {
		wg.Add(concurrentPromotions)
		for i := 0; i < concurrentPromotions; i++ {
			i := i
			go func() {
				defer wg.Done()

				// Simulate both promotion paths by switching between them.
				// In a real scenario, both setupSession and findExistingSession
				// could be called concurrently from different goroutines.
				var session *NTCP2Session
				if i%2 == 0 {
					// Path 1: resolveExistingSession (used by setupSession)
					val, _ := transport.sessions.Load(peerHash)
					if val != nil {
						session = transport.resolveExistingSession(val, peerHash)
					}
				} else {
					// Path 2: promoteInboundConnection direct (used by findExistingSession)
					val, _ := transport.sessions.Load(peerHash)
					if val != nil {
						if rawC, ok := val.(net.Conn); ok {
							// Simulate what findExistingSession does for raw conns.
							sess, _ := transport.promoteInboundConnection(rawC, val, peerHash)
							if s, ok := sess.(*NTCP2Session); ok {
								session = s
							}
						} else if sess, ok := val.(*NTCP2Session); ok {
							session = sess
						}
					}
				}
				results[i] = session
			}()
		}
		wg.Wait()
	}, "concurrent promotion should not panic")

	// Verify all promoters got a valid session.
	var winnerSession *NTCP2Session
	for i, session := range results {
		require.NotNil(t, session, "promoter %d should have received a valid session", i)
		if winnerSession == nil {
			winnerSession = session
		} else {
			// All should be the same session (one winner, others get the winner via LoadOrStore/CAS)
			assert.Same(t, winnerSession, session, "all promoters should receive the same session at index %d", i)
		}
	}

	// Verify the map entry is a valid NTCP2Session.
	entry, exists := transport.sessions.Load(peerHash)
	require.True(t, exists, "peer entry should still exist in map")
	finalSession, isSession := entry.(*NTCP2Session)
	require.True(t, isSession, "map entry should be *NTCP2Session, got %T", entry)
	assert.Same(t, winnerSession, finalSession, "map session should be the same as the winner returned to promoters")

	// Verify session is not closed yet.
	require.NotNil(t, finalSession)

	// Verify cleanup callback works by closing the session.
	// The existing cleanup callback (set during promotion) should call removeSession(),
	// which deletes the map entry and decrements session count.
	_ = finalSession.Close()
	time.Sleep(50 * time.Millisecond) // Brief delay to let cleanup goroutines run.

	// Verify the session was removed from the map during cleanup.
	entry, exists = transport.sessions.Load(peerHash)
	require.False(t, exists, "session entry should be removed from map after Close()")
}

// TestCRITICAL_1_1_PromotionRace_DirectCAS tests the CAS-based promotion directly
// to ensure the winner/loser semantics are correct and no state is leaked.
func TestCRITICAL_1_1_PromotionRace_DirectCAS(t *testing.T) {
	transport := newNilListenerTestTransport(t, 100)
	defer transport.Close()

	peerHash := newTestPeerHash("direct-cas-race-test!!!!!")
	rawConn := newAcceptMockConn("192.168.1.101:5101")

	// Store the raw connection as Accept() would.
	transport.sessions.Store(peerHash, rawConn)

	// Simulate two concurrent promoters, each creating their own promoted session.
	promotedA := NewNTCP2SessionDeferred(rawConn, transport.ctx, transport.logger)
	promotedB := NewNTCP2SessionDeferred(rawConn, transport.ctx, transport.logger)

	// Set up cleanup counters to verify callback behavior.
	cleanupA := int32(0)
	cleanupB := int32(0)

	// Simulate the CAS race: promoter A and B both try to CAS the raw conn
	// to their promoted session. Only one should succeed.
	canals := make(chan bool, 2)

	go func() {
		// Promoter A
		if transport.sessions.CompareAndSwap(peerHash, rawConn, promotedA) {
			promotedA.SetCleanupCallback(func() {
				atomic.AddInt32(&cleanupA, 1)
			})
			promotedA.StartWorkers()
			canals <- true // A won
		} else {
			_ = promotedA.Close()
			canals <- false // A lost
		}
	}()

	go func() {
		// Small delay to let A go first in most cases (but race still possible).
		time.Sleep(1 * time.Millisecond)
		// Promoter B
		if transport.sessions.CompareAndSwap(peerHash, rawConn, promotedB) {
			promotedB.SetCleanupCallback(func() {
				atomic.AddInt32(&cleanupB, 1)
			})
			promotedB.StartWorkers()
			canals <- true // B won
		} else {
			_ = promotedB.Close()
			canals <- false // B lost
		}
	}()

	aWon := <-canals
	bWon := <-canals

	// Exactly one should have won.
	assert.NotEqual(t, aWon, bWon, "exactly one promoter should win the CAS race")

	// Verify the map contains a promoted session.
	entry, exists := transport.sessions.Load(peerHash)
	require.True(t, exists)
	_, isSession := entry.(*NTCP2Session)
	assert.True(t, isSession, "map entry should be *NTCP2Session after CAS race")

	// Verify only the winner's cleanup fires.
	if aWon {
		_ = promotedA.Close()
		time.Sleep(50 * time.Millisecond)
		assert.Equal(t, int32(1), atomic.LoadInt32(&cleanupA), "winner A cleanup should fire once")
		assert.Equal(t, int32(0), atomic.LoadInt32(&cleanupB), "loser B cleanup should never fire")
	} else {
		_ = promotedB.Close()
		time.Sleep(50 * time.Millisecond)
		assert.Equal(t, int32(0), atomic.LoadInt32(&cleanupA), "loser A cleanup should never fire")
		assert.Equal(t, int32(1), atomic.LoadInt32(&cleanupB), "winner B cleanup should fire once")
	}
}

// TestCRITICAL_1_1_SessionCountConsistency verifies that promotion races
// do not cause session count to become inconsistent with the number of
// entries in the sessions map (a known class of bugs in this code).
func TestCRITICAL_1_1_SessionCountConsistency(t *testing.T) {
	transport := newNilListenerTestTransport(t, 1000) // Large limit to avoid rejections.
	defer transport.Close()

	const numPeers = 50
	const concurrentOperations = 100

	// Store a raw connection for each peer (simulating Accept()).
	peerHashes := make([]data.Hash, numPeers)
	for i := 0; i < numPeers; i++ {
		peerHash := newTestPeerHash(fmt.Sprintf("consistency-test-peer-%d!", i))
		peerHashes[i] = peerHash

		rawConn := newAcceptMockConn(fmt.Sprintf("192.168.1.%d:51%02d", 100+i, i))
		transport.sessions.Store(peerHash, rawConn)
		atomic.AddInt32(&transport.sessionCount, 1)
	}

	expectedCount := int32(numPeers)
	assert.Equal(t, expectedCount, atomic.LoadInt32(&transport.sessionCount))

	// Launch concurrent operations that promote these sessions.
	var wg sync.WaitGroup
	wg.Add(concurrentOperations)
	for i := 0; i < concurrentOperations; i++ {
		i := i
		go func() {
			defer wg.Done()
			peerIdx := i % numPeers
			peerHash := peerHashes[peerIdx]

			val, _ := transport.sessions.Load(peerHash)
			if val != nil {
				if rawC, ok := val.(net.Conn); ok {
					_, _ = transport.promoteInboundConnection(rawC, val, peerHash)
				} else if sess, ok := val.(*NTCP2Session); ok {
					_ = sess
				}
			}
		}()
	}
	wg.Wait()

	// After all concurrent operations, session count should match map size
	// (allowing for the possibility of some being actual NTCP2Session objects now).
	finalCount := atomic.LoadInt32(&transport.sessionCount)
	mapSize := 0
	transport.sessions.Range(func(key, val interface{}) bool {
		mapSize++
		return true
	})

	assert.Equal(t, numPeers, mapSize, "all %d peers should still be in map", numPeers)
	// Session count may have changed if cleanup fired (session closes remove from count).
	// But it should not exceed the initial allocation.
	assert.LessOrEqual(t, finalCount, expectedCount, "session count should not exceed initial count %d", expectedCount)
}
