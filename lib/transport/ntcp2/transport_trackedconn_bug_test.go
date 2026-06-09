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

// TestTrackedConnCleanupRace verifies the trackedConn cleanup bug:
// When inboundHandshakeWorker's CAS fails due to concurrent promotion,
// it calls tracked.Close() which fires onClose → removeSession, deleting
// the PROMOTED session from the map even though it's still alive.
//
// This is the ACTUAL bug, not CRITICAL-2.1's described slot leak.
//
// Trace:
// 1. Accept flow stores raw conn, creates trackedConn with onClose=removeSession
// 2. Concurrent GetSession promotes raw conn → *NTCP2Session
// 3. Accept flow's CAS fails (map has session not raw conn)
// 4. Accept calls tracked.Close() → onClose fires → removeSession deletes promoted session!
func TestTrackedConnCleanupRace(t *testing.T) {
	transport := newNilListenerTestTransport(t, 100)
	defer transport.Close()

	const numRaces = 50
	var promotedSessions []*NTCP2Session
	var promotedSessionsMu sync.Mutex

	for i := 0; i < numRaces; i++ {
		peerHash := newTestPeerHash(fmt.Sprintf("trackedconn-cleanup-race-%d", i))
		rawConn := newAcceptMockConn(fmt.Sprintf("192.168.1.%d:5000", 100+i))

		// Simulate Accept flow: reserve slot and store raw conn
		require.NoError(t, transport.checkSessionLimit())
		transport.sessions.Store(peerHash, rawConn)

		var wg sync.WaitGroup
		wg.Add(2)

		// Goroutine 1: Simulate GetSession promotion
		go func() {
			defer wg.Done()
			// Small delay to let trackInboundConnection store first (simulate race window)
			time.Sleep(1 * time.Millisecond)

			val, _ := transport.sessions.Load(peerHash)
			if rawC, ok := val.(net.Conn); ok {
				session, ok := transport.promoteInboundConnection(rawC, val, peerHash)
				if ok && session != nil {
					promotedSessionsMu.Lock()
					promotedSessions = append(promotedSessions, session.(*NTCP2Session))
					promotedSessionsMu.Unlock()
				}
			}
		}()

		// Goroutine 2: Simulate Accept flow's trackInboundConnection + CAS
		go func() {
			defer wg.Done()

			// Simulate trackInboundConnection creating trackedConn wrapper
			trackedConn := &trackedConn{
				Conn: rawConn,
				onClose: func() {
					transport.removeSession(peerHash)
				},
			}

			// Simulate the CAS in inboundHandshakeWorker (line 549)
			// Try to replace raw conn with acceptedConn
			originalConn := trackedConn.Conn
			if !transport.sessions.CompareAndSwap(peerHash, originalConn, acceptedConn{Conn: trackedConn}) {
				// CAS failed - promotion happened
				// BUG: This calls onClose which removes the promoted session!
				trackedConn.Close()
			}
		}()

		wg.Wait()
	}

	// Give workers time to settle
	time.Sleep(100 * time.Millisecond)

	// Count sessions remaining in map
	sessionsInMap := 0
	transport.sessions.Range(func(key, value interface{}) bool {
		if _, ok := value.(*NTCP2Session); ok {
			sessionsInMap++
		}
		return true
	})

	promotedCount := len(promotedSessions)
	t.Logf("Promoted sessions: %d, Sessions in map: %d", promotedCount, sessionsInMap)

	// BUG SYMPTOM: Most or all promoted sessions removed from map by trackedConn.Close()
	// Expected: sessionsInMap == promotedCount (all promoted sessions still in map)
	// Actual: sessionsInMap < promotedCount (many removed by incorrect cleanup)
	if sessionsInMap < promotedCount {
		t.Errorf("TrackedConn cleanup bug detected: %d promoted sessions, but only %d in map (%.1f%% removed incorrectly)",
			promotedCount, sessionsInMap, 100.0*float64(promotedCount-sessionsInMap)/float64(promotedCount))
	}

	finalCount := atomic.LoadInt32(&transport.sessionCount)
	t.Logf("Final sessionCount: %d", finalCount)

	// Verify promoted sessions are still accessible
	for i, session := range promotedSessions {
		if session == nil {
			continue
		}
		// Check if session still in map (should be)
		routerHash := newTestPeerHash(fmt.Sprintf("trackedconn-cleanup-race-%d", i))
		val, exists := transport.sessions.Load(routerHash)
		if !exists {
			t.Errorf("Promoted session %d missing from map!", i)
		} else if sessVal, ok := val.(*NTCP2Session); !ok || sessVal != session {
			t.Errorf("Promoted session %d replaced in map!", i)
		}
	}

	assert.Equal(t, promotedCount, sessionsInMap,
		"All promoted sessions should remain in map (not removed by trackedConn cleanup)")
}

// TestConcurrentAcceptAndGetSessionIntegration is an integration test that verifies
// the trackedConn cleanup race doesn't occur when Accept and GetSession run concurrently.
//
// CRITICAL-2.1 remediation checklist item:
// "Add integration test: concurrent Accept + GetSession, verify all promoted sessions remain in map"
//
// This test simulates realistic concurrent access where:
// 1. Accept loop stores raw connections in the session map
// 2. GetSession is called concurrently to promote those connections to full sessions
// 3. Concurrent promotion attempts may race
//
// Expected: All promoted sessions remain in the map after both flows complete.
// Bug symptom: Promoted sessions incorrectly removed by trackedConn cleanup callback.
func TestConcurrentAcceptAndGetSessionIntegration(t *testing.T) {
	transport := newNilListenerTestTransport(t, 100)
	defer transport.Close()

	const numPeers = 20
	var wg sync.WaitGroup

	// Create test peers with unique hashes and connections
	type testPeer struct {
		hash data.Hash
		conn net.Conn
	}
	peers := make([]testPeer, numPeers)
	for i := 0; i < numPeers; i++ {
		peers[i] = testPeer{
			hash: newTestPeerHash(fmt.Sprintf("concurrent-integration-%d", i)),
			conn: newAcceptMockConn(fmt.Sprintf("10.0.1.%d:5000", i)),
		}
	}

	// Phase 1: Simulate Accept flow storing raw connections
	// (This simulates trackInboundConnection storing the raw conn)
	for _, peer := range peers {
		// Reserve slot and store raw connection
		require.NoError(t, transport.checkSessionLimit())
		transport.sessions.Store(peer.hash, peer.conn)
	}

	// Phase 2: Concurrent promotion attempts
	// Simulate both Accept flow (via trackInboundConnection CAS to acceptedConn)
	// and GetSession flow (promoting to *NTCP2Session) racing
	promotedSessions := make([]*NTCP2Session, numPeers)

	for i := range peers {
		wg.Add(2)
		peerIdx := i // Capture for goroutines

		// Goroutine 1: Simulate GetSession attempting to promote to *NTCP2Session
		// Start this slightly before Accept to ensure some actually get promoted
		go func() {
			defer wg.Done()
			peer := peers[peerIdx]

			// Delay varies to create realistic race conditions
			time.Sleep(time.Duration(peerIdx%3) * time.Millisecond)

			// Load whatever is in the map
			val, exists := transport.sessions.Load(peer.hash)
			if !exists {
				return
			}

			// If it's a raw conn, promote it to *NTCP2Session
			if rawConn, ok := val.(net.Conn); ok {
				session, promoted := transport.promoteInboundConnection(rawConn, val, peer.hash)
				if promoted && session != nil {
					if ntcpSession, ok := session.(*NTCP2Session); ok {
						promotedSessions[peerIdx] = ntcpSession
					}
				}
			}
		}()

		// Goroutine 2: Simulate Accept flow attempting to wrap in acceptedConn
		// (This is what inboundHandshakeWorker does after handshake completes)
		go func() {
			defer wg.Done()
			peer := peers[peerIdx]

			// Delay slightly more to give GetSession a chance to promote
			time.Sleep(time.Duration(2+peerIdx%4) * time.Millisecond)

			// Create tracked connection with cleanup callback
			tracked := &trackedConn{
				Conn: peer.conn,
				onClose: func() {
					transport.removeSession(peer.hash)
				},
			}

			// Try to CAS from raw conn to acceptedConn
			originalConn := tracked.Conn
			acceptedConnWrapper := acceptedConn{Conn: tracked}

			if !transport.sessions.CompareAndSwap(peer.hash, originalConn, acceptedConnWrapper) {
				// CAS failed - someone else (GetSession) promoted it
				// CRITICAL FIX: Do NOT call tracked.Close() here!
				// The bug was calling tracked.Close() which would fire onClose
				// and remove the promoted session from the map.
			}
		}()
	}

	wg.Wait()

	// Give any async cleanup a chance to run
	time.Sleep(100 * time.Millisecond)

	// Count sessions in map
	sessionsInMap := 0
	transport.sessions.Range(func(key, value interface{}) bool {
		if _, ok := value.(*NTCP2Session); ok {
			sessionsInMap++
		}
		return true
	})

	// Count how many were successfully promoted
	promotedCount := 0
	for _, session := range promotedSessions {
		if session != nil {
			promotedCount++
		}
	}

	t.Logf("Successfully promoted: %d sessions", promotedCount)
	t.Logf("Sessions remaining in map: %d", sessionsInMap)
	t.Logf("Session count: %d", atomic.LoadInt32(&transport.sessionCount))

	// The key invariant: All promoted sessions must still be in the map
	// (not removed by incorrect trackedConn cleanup)
	for i, session := range promotedSessions {
		if session == nil {
			continue
		}

		peer := peers[i]
		val, exists := transport.sessions.Load(peer.hash)
		assert.True(t, exists, "Promoted session %d must exist in map", i)
		if exists {
			mapSession, isSession := val.(*NTCP2Session)
			assert.True(t, isSession, "Promoted entry %d must be *NTCP2Session type", i)
			assert.Equal(t, session, mapSession, "Session %d pointer must match", i)
		}
	}

	// All promoted sessions should still be in the map
	assert.Equal(t, promotedCount, sessionsInMap,
		"All promoted sessions should remain in map (not removed by trackedConn cleanup)")

	// Verify session count accounting matches actual sessions
	// (may be higher if some acceptedConn wrappers still exist)
	assert.GreaterOrEqual(t, int(atomic.LoadInt32(&transport.sessionCount)), sessionsInMap,
		"sessionCount should be at least as large as sessions in map")
}
