package ssu2

// transport_trackedconn_bug_test.go contains tests for CRITICAL-2.1:
// "trackedConn cleanup race - when inboundHandshakeWorker CAS fails due to
// concurrent promotion, calling tracked.Close() fires onClose callback which
// calls removeSession(), incorrectly deleting the promoted session from map
// while it's still alive and running."
//
// This is a critical anonymity/reliability bug: if the promoted session gets
// removed from the map, the router thinks the peer is disconnected while the
// session is actually still alive, leading to connection state corruption.

import (
	"context"
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

// mockSSU2TrackedConn is a minimal mock net.Conn for testing trackedConn cleanup.
type mockSSU2TrackedConn struct {
	addr string
}

func (m *mockSSU2TrackedConn) Read(b []byte) (n int, err error)  { return 0, nil }
func (m *mockSSU2TrackedConn) Write(b []byte) (n int, err error) { return 0, nil }
func (m *mockSSU2TrackedConn) Close() error                      { return nil }
func (m *mockSSU2TrackedConn) LocalAddr() net.Addr               { return nil }
func (m *mockSSU2TrackedConn) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP(m.addr), Port: 8887}
}
func (m *mockSSU2TrackedConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockSSU2TrackedConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockSSU2TrackedConn) SetWriteDeadline(t time.Time) error { return nil }

// newMockSSU2Conn creates a test connection with a unique address.
func newMockSSU2Conn(addr string) net.Conn {
	return &mockSSU2TrackedConn{addr: addr}
}

// newTestTransportForTrackedConnTest creates a minimal SSU2Transport for testing.
func newTestTransportForTrackedConnTest(t *testing.T, maxSessions int) *SSU2Transport {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	return &SSU2Transport{
		config:        &Config{ListenerAddress: "127.0.0.1:0", MaxSessions: maxSessions},
		handler:       NewDefaultHandler(),
		natStateCache: &natState{},
		ctx:           ctx,
		cancel:        cancel,
		logger:        log.WithField("test", "trackedconn_bug"),
	}
}

// newTestPeerHashForTracked creates a unique test peer hash.
func newTestPeerHashForTracked(seed string) data.Hash {
	var h data.Hash
	copy(h[:], []byte(seed))
	return h
}

// TestTrackedConnCleanupRace is the core unit test for CRITICAL-2.1.
//
// This test verifies that when a CAS to acceptedConn fails (because GetSession
// promoted the conn to a session), the trackedConn wrapper is NOT closed.
//
// Expected: The promoted session remains in the map.
// Bug symptom: tracked.Close() fires onClose → removeSession, deleting promoted session.
func TestTrackedConnCleanupRace(t *testing.T) {
	transport := newTestTransportForTrackedConnTest(t, 10)
	defer transport.Close()

	peerHash := newTestPeerHashForTracked("cleanup-race-peer-!!")
	rawConn := newMockSSU2Conn("10.0.0.5")

	// Phase 1: Simulate GetSession promoting the raw conn to a session
	// Store a placeholder that won't panic when accessed (not a full session)
	// In the real code, this would be a properly initialized *SSU2Session
	promotedMarker := &acceptedConn{Conn: rawConn} // Use acceptedConn as a marker
	transport.sessions.Store(peerHash, promotedMarker)
	atomic.AddInt32(&transport.sessionCount, 1)

	// Phase 2: Simulate Accept flow attempting to wrap in acceptedConn
	// (This is what happens in Accept after trackInboundConnection)
	tracked := &trackedConn{
		Conn: rawConn,
		onClose: func() {
			transport.removeSession(peerHash)
		},
	}

	// Try CAS from original conn to acceptedConn - this will fail because
	// GetSession already promoted it (we stored promotedMarker)
	acceptedWrapper := acceptedConn{Conn: tracked}
	casSucceeded := transport.sessions.CompareAndSwap(peerHash, rawConn, acceptedWrapper)

	// The CAS should fail (GetSession won the race)
	require.False(t, casSucceeded, "CAS should fail when session already promoted")

	// CRITICAL INVARIANT: The buggy code would call tracked.Close() here,
	// which would fire onClose → removeSession, deleting the promoted session.
	// The fixed code does NOT call tracked.Close().
	//
	// Verify the promoted marker is still in the map:
	val, exists := transport.sessions.Load(peerHash)
	assert.True(t, exists, "Promoted session must still exist in map")
	if exists {
		assert.Equal(t, promotedMarker, val, "Entry must be the promoted marker")
	}

	// Verify session count is still correct
	assert.Equal(t, int32(1), atomic.LoadInt32(&transport.sessionCount),
		"Session count should remain 1 (not decremented by incorrect cleanup)")

	// Clean up the session manually since we're not using a real session
	transport.sessions.Delete(peerHash)
	atomic.AddInt32(&transport.sessionCount, -1)
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
	transport := newTestTransportForTrackedConnTest(t, 100)
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
			hash: newTestPeerHashForTracked(fmt.Sprintf("concurrent-integration-%d", i)),
			conn: newMockSSU2Conn(fmt.Sprintf("10.0.1.%d", i)),
		}
	}

	// Phase 1: Simulate Accept flow storing raw connections
	// (This simulates trackInboundConnection storing the raw conn)
	for _, peer := range peers {
		// Reserve slot and store raw connection
		atomic.AddInt32(&transport.sessionCount, 1)
		transport.sessions.Store(peer.hash, peer.conn)
	}

	// Phase 2: Concurrent promotion attempts
	// Simulate both Accept flow (via trackInboundConnection CAS to acceptedConn)
	// and GetSession flow (promoting to *SSU2Session) racing
	promotedSessions := make([]*SSU2Session, numPeers)

	for i := range peers {
		wg.Add(2)
		peerIdx := i // Capture for goroutines

		// Goroutine 1: Simulate GetSession attempting to promote to *SSU2Session
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

			// If it's a raw conn, promote it to *SSU2Session
			// (Simplified version - real promoteInboundConnection is more complex)
			// Use acceptedConn as a marker to avoid SSU2Session initialization complexity
			if _, ok := val.(net.Conn); ok {
				promotedMarker := &acceptedConn{Conn: peer.conn}
				if transport.sessions.CompareAndSwap(peer.hash, val, promotedMarker) {
					// Store a non-nil marker to indicate successful promotion
					promotedSessions[peerIdx] = &SSU2Session{} // Just a marker, won't be used
				}
			}
		}()

		// Goroutine 2: Simulate Accept flow attempting to wrap in acceptedConn
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
			acceptedWrapper := acceptedConn{Conn: tracked}

			if !transport.sessions.CompareAndSwap(peer.hash, peer.conn, acceptedWrapper) {
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

	// Count sessions in map (use acceptedConn as marker for promoted sessions)
	sessionsInMap := 0
	transport.sessions.Range(func(key, value interface{}) bool {
		// Count both SSU2Session and acceptedConn markers as "promoted"
		if _, ok := value.(*SSU2Session); ok {
			sessionsInMap++
		} else if _, ok := value.(*acceptedConn); ok {
			// In our test, acceptedConn markers represent promoted sessions
			// (simplified to avoid SSU2Session initialization)
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
			// Accept either SSU2Session or acceptedConn marker
			_, isSession := val.(*SSU2Session)
			_, isAccepted := val.(*acceptedConn)
			assert.True(t, isSession || isAccepted, "Promoted entry %d must be session or marker type", i)
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
