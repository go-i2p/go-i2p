package ntcp2

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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
