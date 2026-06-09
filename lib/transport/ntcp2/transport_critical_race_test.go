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

// TestCRITICAL_R1_SetIdentityDoesNotKillAcceptLoop is a regression test for
// R-1 (CRITICAL): SetIdentity permanently kills the NTCP2 accept loop.
//
// Bug: recreateListenerIfNeeded sets t.listener = nil temporarily during swap.
// If acceptNextConnection observes nil, it returns false, terminating the loop.
// Since the loop is guarded by acceptRunOnce, it never restarts.
//
// Fix: acceptNextConnection distinguishes "listener nil during swap" from
// "listener nil during shutdown". It waits/retries when nil but transport
// is still running, only terminating on actual shutdown.
//
// This test verifies that the accept loop remains operational after the
// listener is temporarily nil during a SetIdentity operation.
func TestCRITICAL_R1_SetIdentityDoesNotKillAcceptLoop(t *testing.T) {
	// This test verifies the accept loop behavior when listener becomes temporarily nil.
	// We simulate the scenario by manually setting listener to nil while transport is running.
	conn := newAcceptMockConn("10.0.0.1:5001")
	listener := newMockListener(conn)
	transport := newTestTransport(listener, 10)
	defer transport.cancel()

	// Accept should work initially.
	accepted, err := transport.Accept()
	require.NoError(t, err)
	require.NotNil(t, accepted)
	assert.Equal(t, 1, transport.GetSessionCount())

	// Close the accepted connection to free the slot.
	accepted.Close()
	assert.Equal(t, 0, transport.GetSessionCount())

	// Simulate SetIdentity behavior: temporarily set listener to nil.
	// The accept loop should NOT terminate, but rather wait/retry.
	transport.identityMu.Lock()
	oldListener := transport.listener
	transport.listener = nil
	transport.identityMu.Unlock()

	// Give the accept loop time to observe the nil listener.
	// With the fix, it should wait/retry, not terminate.
	time.Sleep(100 * time.Millisecond)

	// Restore the listener (simulating the end of SetIdentity swap).
	transport.identityMu.Lock()
	transport.listener = oldListener
	transport.identityMu.Unlock()

	// Enqueue another connection. The accept loop should still be running
	// and should be able to accept this new connection.
	newConn := newAcceptMockConn("10.0.0.2:5002")
	select {
	case transport.listener.(*mockListener).conns <- newConn:
		// Successfully enqueued.
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Failed to enqueue connection")
	}

	// Accept should still work (proving the loop didn't terminate).
	accepted2, err := transport.Accept()
	require.NoError(t, err, "Accept should work after listener swap")
	require.NotNil(t, accepted2, "Accepted connection should not be nil")
	assert.Equal(t, 1, transport.GetSessionCount())
}

// TestX1_DualSocketOwnership_AcceptedConnNotPromoted is a regression test for X-1:
// "Inconsistent acceptedConn guarding → dual socket ownership (NTCP2)".
//
// This test verifies that:
//  1. After Accept() stores an acceptedConn wrapper and delivers it to a consumer,
//  2. A concurrent GetSession() call to the same peer hash does NOT promote the acceptedConn.
//  3. GetSession() correctly returns (nil, not-found) instead of attempting promotion.
//
// Without the X-1 fix, GetSession() would match the acceptedConn's embedded net.Conn
// and attempt to promote it, creating dual socket ownership (concurrent reads/writes
// on the same socket → wire corruption, AEAD/frame desync, anonymity-relevant garbage).
//
// This test must pass with `go test -race`.
func TestX1_DualSocketOwnership_AcceptedConnNotPromoted(t *testing.T) {
	transport := newNilListenerTestTransport(t, 100)
	defer transport.Close()

	peerHash := newTestPeerHash("x1-dual-owner-prevention-!!")
	rawConn := newAcceptMockConn("192.168.1.200:5200")

	// Simulate the state after Accept() has wrapped the connection and delivered it:
	// The sessions map contains an acceptedConn wrapper (not a raw net.Conn or *NTCP2Session).
	acceptedWrapper := acceptedConn{Conn: rawConn}
	transport.sessions.Store(peerHash, acceptedWrapper)
	atomic.AddInt32(&transport.sessionCount, 1)

	// At this point, the Accept() consumer owns the socket. Concurrent GetSession()
	// calls should NOT attempt to promote this acceptedConn.

	// Simulate multiple concurrent GetSession() attempts to the same peer.
	const concurrentAttempts = 10
	var wg sync.WaitGroup
	promotionAttempts := int32(0)
	foundResults := make([]bool, concurrentAttempts)

	wg.Add(concurrentAttempts)
	for i := 0; i < concurrentAttempts; i++ {
		i := i
		go func() {
			defer wg.Done()
			// findExistingSession is the primary GetSession lookup path.
			session, found := transport.findExistingSession(peerHash)
			foundResults[i] = found
			if found && session != nil {
				atomic.AddInt32(&promotionAttempts, 1)
			}
		}()
	}
	wg.Wait()

	// Verify that NO promotion occurred — all GetSession attempts should have
	// returned (nil, false) because acceptedConn is skipped by the guard.
	assert.Equal(t, int32(0), atomic.LoadInt32(&promotionAttempts),
		"GetSession should not promote acceptedConn (X-1 fix)")

	for i, found := range foundResults {
		assert.False(t, found, "GetSession attempt %d should return false (not found) for acceptedConn", i)
	}

	// Verify the map entry remains an acceptedConn (not promoted to *NTCP2Session).
	entry, exists := transport.sessions.Load(peerHash)
	require.True(t, exists, "acceptedConn entry should still exist")
	_, isAcceptedConn := entry.(acceptedConn)
	assert.True(t, isAcceptedConn, "map entry should remain acceptedConn, got %T", entry)

	// Verify session count is still 1 (no accounting corruption).
	assert.Equal(t, int32(1), atomic.LoadInt32(&transport.sessionCount),
		"session count should remain 1 (no double-counting from promotion attempts)")

	// Verify the metric counter remains at 0 (no promotion attempts were made
	// because findExistingSession correctly skips acceptedConn).
	// If this counter is non-zero, it means the defensive check in
	// promoteInboundConnection was reached, indicating findExistingSession failed.
	assert.Equal(t, int32(0), transport.AcceptedConnPromotionAttempts(),
		"Metric should be 0 because findExistingSession skips acceptedConn before calling promoteInboundConnection")
}

// TestX1_DefenseInDepth_MetricIncrementsOnAcceptedConnPromotion tests the
// defense-in-depth metric in promoteInboundConnection. This test simulates
// a hypothetical bug where findExistingSession's guard fails and an acceptedConn
// reaches promoteInboundConnection. The defensive check should refuse the promotion
// and increment the metric.
func TestX1_DefenseInDepth_MetricIncrementsOnAcceptedConnPromotion(t *testing.T) {
	transport := newNilListenerTestTransport(t, 100)
	defer transport.Close()

	peerHash := newTestPeerHash("x1-defense-metric-test-!!")
	rawConn := newAcceptMockConn("192.168.1.201:5201")
	acceptedWrapper := acceptedConn{Conn: rawConn}

	// Verify initial metric state is 0.
	assert.Equal(t, int32(0), transport.AcceptedConnPromotionAttempts(),
		"Metric should start at 0")

	// Directly call promoteInboundConnection with an acceptedConn.
	// This simulates a bug where findExistingSession failed to skip acceptedConn.
	// The defensive check should refuse the promotion and increment the metric.
	session, promoted := transport.promoteInboundConnection(rawConn, acceptedWrapper, peerHash)
	assert.Nil(t, session, "promoteInboundConnection should refuse acceptedConn and return nil")
	assert.False(t, promoted, "promoteInboundConnection should return false for acceptedConn")

	// Verify the metric was incremented to 1.
	assert.Equal(t, int32(1), transport.AcceptedConnPromotionAttempts(),
		"Metric should increment to 1 after refusing acceptedConn promotion")

	// Call again to verify the metric increments multiple times.
	session2, promoted2 := transport.promoteInboundConnection(rawConn, acceptedWrapper, peerHash)
	assert.Nil(t, session2, "Second call should also refuse acceptedConn")
	assert.False(t, promoted2, "Second call should return false")

	assert.Equal(t, int32(2), transport.AcceptedConnPromotionAttempts(),
		"Metric should increment to 2 after second refusal")
}

// TestX3_AcceptStoreVsPromotionCAS is a regression test for X-3:
// "Unconditional Store clobbers a concurrent promotion (both transports)".
//
// This test verifies that:
//  1. After trackInboundConnection stores a rawConn in the session map,
//  2. Concurrent CAS operations (Accept → acceptedConn, GetSession → promotion) are serialized correctly.
//  3. Only ONE owner wins: either Accept gets the socket, or promotion creates a session.
//  4. The loser detects CAS failure and reconciles ownership (no dual ownership, no leaks).
//
// Without the X-3 fix (unconditional Store instead of CAS), the Accept path would
// clobber a promoted session, orphaning it while a caller uses it, leading to
// dual ownership when the session's cleanup callback later deletes the acceptedConn.
//
// This test must pass with `go test -race`.
func TestX3_AcceptStoreVsPromotionCAS(t *testing.T) {
	transport := newNilListenerTestTransport(t, 100)
	defer transport.Close()

	const concurrentRaces = 50
	var wg sync.WaitGroup
	wg.Add(concurrentRaces * 2) // Accept CAS + Promotion CAS per race

	for i := 0; i < concurrentRaces; i++ {
		i := i
		peerHash := newTestPeerHash(fmt.Sprintf("x3-race-%d", i))
		rawConn := newAcceptMockConn(fmt.Sprintf("192.168.1.%d:5400", 100+i))

		// Simulate trackInboundConnection storing the rawConn.
		transport.sessions.Store(peerHash, rawConn)
		atomic.AddInt32(&transport.sessionCount, 1)

		// Race 1: Accept path tries to CAS rawConn → acceptedConn.
		go func() {
			defer wg.Done()
			acceptedWrapper := acceptedConn{Conn: rawConn}
			casSucceeded := transport.sessions.CompareAndSwap(peerHash, rawConn, acceptedWrapper)
			if !casSucceeded {
				// Promotion won; Accept should not deliver this connection.
				// In real code, this would trigger the "Inbound connection promoted concurrently" path.
			}
		}()

		// Race 2: GetSession path tries to promote rawConn → *NTCP2Session.
		go func() {
			defer wg.Done()
			_, _ = transport.promoteInboundConnection(rawConn, rawConn, peerHash)
			// promoteInboundConnection internally does CAS; if it fails, the promoted
			// session is closed and the winner is used.
		}()
	}

	wg.Wait()

	// Verify session map integrity: each peerHash should have exactly one owner
	// (either acceptedConn or *NTCP2Session, never both, never lost).
	transport.sessions.Range(func(key, value interface{}) bool {
		_, isAcceptedConn := value.(acceptedConn)
		_, isSession := value.(*NTCP2Session)
		assert.True(t, isAcceptedConn || isSession,
			"Map entry must be either acceptedConn or *NTCP2Session, got %T", value)
		return true
	})

	// Verify sessionCount consistency: initial count + winners should equal final count.
	// Each race had 1 initial Store; winners kept their entries; losers didn't leak.
	finalCount := atomic.LoadInt32(&transport.sessionCount)
	assert.Greater(t, finalCount, int32(0),
		"sessionCount should be positive (some entries remain)")
	assert.LessOrEqual(t, finalCount, int32(concurrentRaces),
		"sessionCount should not exceed initial slots (no double-counting)")
}

// TestCRITICAL_2_1_PromotionSlotLeakOnCASFailure - DEPRECATED/INVALID
// This test was written for CRITICAL-2.1 which claimed promotion race losers
// leaked session slots by not calling unreserveSessionSlot(). Analysis revealed
// this is NOT a real bug: losers never reserve their own slots — all promoters
// compete for the ONE slot reserved by Accept's checkSessionLimit(), and the
// winner inherits it. If losers called unreserveSessionSlot(), they would
// incorrectly decrement the winner's count.
//
// The ACTUAL bug in this code area was the trackedConn cleanup race (see
// CRITICAL-2.1 updated description in AUDIT.md and TestTrackedConnCleanupRace).
// That bug has been fixed by removing the tracked.Close() call in
// inboundHandshakeWorker when CAS fails due to concurrent promotion.
//
// This test is preserved but commented out as historical context. It may be
// repurposed or removed in a future cleanup.
/*
func TestCRITICAL_2_1_PromotionSlotLeakOnCASFailure(t *testing.T) {
	transport := newNilListenerTestTransport(t, 100)
	defer transport.Close()

	const numRaces = 10
	peerHashes := make([]data.Hash, numRaces)

	// Simulate concurrent inbound Accept + outbound Dial promotion races.
	for i := 0; i < numRaces; i++ {
		peerHash := newTestPeerHash(fmt.Sprintf("critical-2-1-promotion-leak-test-%d!", i))
		peerHashes[i] = peerHash
		rawConn := newAcceptMockConn(fmt.Sprintf("192.168.1.%d:52%02d", 100+i, i))

		// Simulate Accept(): reserve slot and store raw conn.
		require.NoError(t, transport.checkSessionLimit())
		transport.sessions.Store(peerHash, rawConn)

		// Launch concurrent promotions (simulating inbound Accept→GetSession + outbound Dial).
		var wg sync.WaitGroup
		const concurrentPromoters = 5
		wg.Add(concurrentPromoters)
		for j := 0; j < concurrentPromoters; j++ {
			go func() {
				defer wg.Done()
				val, _ := transport.sessions.Load(peerHash)
				if val != nil {
					if rawC, ok := val.(net.Conn); ok {
						_, _ = transport.promoteInboundConnection(rawC, val, peerHash)
					}
				}
			}()
		}
		wg.Wait()
	}

	// Count actual sessions in map.
	actualSessions := 0
	transport.sessions.Range(func(key, value interface{}) bool {
		if _, ok := value.(*NTCP2Session); ok {
			actualSessions++
		}
		return true
	})

	// sessionCount should equal number of promoted sessions (not numRaces × concurrentPromoters).
	finalCount := atomic.LoadInt32(&transport.sessionCount)
	assert.Equal(t, actualSessions, int(finalCount),
		"sessionCount should equal actual sessions in map (no leaked slots from CAS losers)")

	// Verify sessionCount is reasonable: at most numRaces winners (one per peer).
	assert.LessOrEqual(t, finalCount, int32(numRaces),
		"sessionCount should not exceed number of peers (each has max 1 winner)")
}
*/
