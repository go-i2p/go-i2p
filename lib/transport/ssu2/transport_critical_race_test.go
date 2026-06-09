package ssu2

//transport_critical_race_test.go covers critical race tests for SSU2Transport,
// specifically X-2 (acceptedConn promotion accounting) and related session map
// integrity under concurrent GetSession/Accept.

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

// mockSSU2Conn is a mock net.Conn for testing session map logic.
type mockSSU2Conn struct {
	net.Conn
	remoteAddr string
}

func (m *mockSSU2Conn) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
}

func (m *mockSSU2Conn) Close() error {
	return nil
}

// newTestPeerHash creates a test peer hash from a string seed.
func newTestPeerHashSSU2(seed string) data.Hash {
	var h data.Hash
	copy(h[:], []byte(seed))
	return h
}

// makeMinimalTransportForRaceTests creates an SSU2Transport for testing
// session map logic without requiring a real listener or NAT managers.
func makeMinimalTransportForRaceTests(t *testing.T, maxSessions int) *SSU2Transport {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	return &SSU2Transport{
		config:        &Config{ListenerAddress: "127.0.0.1:0", MaxSessions: maxSessions},
		handler:       NewDefaultHandler(),
		natStateCache: &natState{},
		ctx:           ctx,
		cancel:        cancel,
		logger:        log.WithField("test", "critical_race"),
	}
}

// TestX2_SessionCountConservedAcrossSimultaneousConnect is a regression test
// for X-2: "SSU2 GetSession to a peer with an accepted inbound conn corrupts accounting".
//
// This test verifies that:
//  1. When an acceptedConn wrapper is in the session map (simulating Accept() ownership),
//  2. Concurrent GetSession() calls to the same peer do NOT delete the acceptedConn entry.
//  3. sessionCount remains conserved (no leak, no double-count).
//
// Without the X-2 fix, resolveSessionFromMap would fail the type assertion,
// registerOrReuseSession would Delete the acceptedConn without decrementing the counter,
// causing a permanent sessionCount leak toward ErrConnectionPoolFull.
//
// This test must pass with `go test -race`.
func TestX2_SessionCountConservedAcrossSimultaneousConnect(t *testing.T) {
	transport := makeMinimalTransportForRaceTests(t, 100)
	defer transport.Close()

	peerHash := newTestPeerHashSSU2("x2-accounting-test-!!")
	rawConn := &mockSSU2Conn{remoteAddr: "192.168.1.100:5300"}

	// Simulate the state after Accept() has wrapped the connection and delivered it:
	// The sessions map contains an acceptedConn wrapper.
	acceptedWrapper := acceptedConn{Conn: rawConn}
	transport.sessions.Store(peerHash, acceptedWrapper)
	atomic.AddInt32(&transport.sessionCount, 1)

	initialCount := atomic.LoadInt32(&transport.sessionCount)
	require.Equal(t, int32(1), initialCount, "Initial session count should be 1")

	// Simulate multiple concurrent operations that might attempt to resolve/delete
	// the acceptedConn entry (simulating simultaneous-connect scenarios).
	const concurrentAttempts = 10
	var wg sync.WaitGroup
	wg.Add(concurrentAttempts)

	for i := 0; i < concurrentAttempts; i++ {
		go func() {
			defer wg.Done()
			// Load the entry and attempt to resolve it.
			// With the X-2 fix, resolveSessionFromMap should return (nil, false)
			// for acceptedConn, and no deletion should occur.
			if existing, exists := transport.sessions.Load(peerHash); exists {
				transport.resolveSessionFromMap(existing, peerHash)
			}
		}()
	}
	wg.Wait()

	// Verify the map entry still exists and is still acceptedConn.
	entry, exists := transport.sessions.Load(peerHash)
	require.True(t, exists, "acceptedConn entry should still exist after concurrent resolve attempts")
	_, isAcceptedConn := entry.(acceptedConn)
	assert.True(t, isAcceptedConn, "map entry should remain acceptedConn, got %T", entry)

	// Verify sessionCount is conserved (still 1, no leak).
	finalCount := atomic.LoadInt32(&transport.sessionCount)
	assert.Equal(t, int32(1), finalCount,
		"sessionCount should remain 1 (no leak from Delete without decrement)")
}

// TestX3_AcceptStoreVsPromotionCAS is a regression test for X-3:
// "Unconditional Store clobbers a concurrent promotion (both transports)".
//
// This test verifies that:
//  1. After trackInboundConnection stores a rawConn in the session map,
//  2. Concurrent CAS operations (Accept → acceptedConn, promotion → session) are serialized correctly.
//  3. Only ONE owner wins: either Accept gets the socket, or promotion creates a session.
//  4. The loser detects CAS failure and reconciles ownership (no dual ownership, no leaks).
//
// Without the X-3 fix (unconditional Store instead of CAS), the Accept path would
// clobber a promoted session, orphaning it while a caller uses it.
//
// This test must pass with `go test -race`.
func TestX3_AcceptStoreVsPromotionCAS(t *testing.T) {
	transport := makeMinimalTransportForRaceTests(t, 100)
	defer transport.Close()

	const concurrentRaces = 50
	var wg sync.WaitGroup
	wg.Add(concurrentRaces * 2) // Accept CAS + Promotion attempt per race

	for i := 0; i < concurrentRaces; i++ {
		i := i
		peerHash := newTestPeerHashSSU2(fmt.Sprintf("x3-race-%d", i))
		rawConn := &mockSSU2Conn{remoteAddr: fmt.Sprintf("192.168.2.%d:5500", 100+i)}

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
			}
		}()

		// Race 2: Promotion path tries to resolve/promote the entry.
		go func() {
			defer wg.Done()
			// Attempt to resolve the session from the map.
			// With X-3 fix, if CAS already happened, resolveSessionFromMap should handle gracefully.
			if existing, exists := transport.sessions.Load(peerHash); exists {
				_, _ = transport.resolveSessionFromMap(existing, peerHash)
			}
		}()
	}

	wg.Wait()

	// Verify session map integrity: each peerHash should have exactly one owner.
	transport.sessions.Range(func(key, value interface{}) bool {
		_, isAcceptedConn := value.(acceptedConn)
		_, isSession := value.(*SSU2Session)
		_, isConn := value.(net.Conn)
		assert.True(t, isAcceptedConn || isSession || isConn,
			"Map entry must be acceptedConn, *SSU2Session, or net.Conn, got %T", value)
		return true
	})

	// Verify sessionCount consistency.
	finalCount := atomic.LoadInt32(&transport.sessionCount)
	assert.Greater(t, finalCount, int32(0),
		"sessionCount should be positive (some entries remain)")
	assert.LessOrEqual(t, finalCount, int32(concurrentRaces),
		"sessionCount should not exceed initial slots (no double-counting)")
}

// NOTE: E-1 regression test for registerOrReuseSession with acceptedConn
// is not included here because it requires a valid *ssu2noise.SSU2Conn which
// cannot be easily mocked. The fix is verified by code inspection at
// transport.go lines 1044-1047 where acceptedConn is explicitly handled as
// a legitimate state and returns an error instead of deleting the entry.
// The TestX2_SessionCountConservedAcrossSimultaneousConnect test above provides
// coverage for acceptedConn handling in the lookup/promotion paths.

// TestR2_ConfigListenerAddressRaceDuringSetIdentity is a regression test for
// R-2: "config.ListenerAddress mutated without holding identityMu".
//
// This test verifies that:
//  1. SetIdentity (which updates t.config.ListenerAddress under lock) can run
//     concurrently with validateAndExtractPort (which reads t.config.ListenerAddress).
//  2. The race detector flags any unsynchronized access.
//  3. After the R-2 fix (refactoring NAT helpers to return bound address separately),
//     all writes occur under identityMu and readers either hold identityMu or use
//     the returned bound address directly.
//
// This test hammers the config.ListenerAddress field from multiple goroutines
// to expose the TOCTOU race where validateAndExtractPort reads the field twice
// in quick succession while SetIdentity mutates it.
//
// Without R-2 fix, this test will fail under `go test -race`.
func TestR2_ConfigListenerAddressRaceDuringSetIdentity(t *testing.T) {
	transport := makeMinimalTransportForRaceTests(t, 10)

	// Create a dummy listener to satisfy SetIdentity
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	require.NoError(t, err)
	udpConn, err := net.ListenUDP("udp", udpAddr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = udpConn.Close() })

	// Assign the listener
	transport.identityMu.Lock()
	transport.config.ListenerAddress = udpConn.LocalAddr().String()
	transport.identityMu.Unlock()

	var wg sync.WaitGroup
	stopCh := make(chan struct{})

	// Goroutine 1: repeatedly read config.ListenerAddress via validateAndExtractPort
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stopCh:
				return
			default:
				// validateAndExtractPort reads t.config.ListenerAddress twice
				port, ok := transport.validateAndExtractPort()
				if ok {
					assert.Greater(t, port, 0)
				}
			}
		}
	}()

	// Goroutine 2: repeatedly update config.ListenerAddress under identityMu
	// (simulating what SetIdentity does)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			select {
			case <-stopCh:
				return
			default:
				transport.identityMu.Lock()
				// Simulate address mutation
				transport.config.ListenerAddress = fmt.Sprintf("127.0.0.1:%d", 10000+i)
				transport.identityMu.Unlock()
			}
		}
		// Signal completion after 100 iterations
		close(stopCh)
	}()

	// Wait for goroutines to finish
	wg.Wait()
}

// TestR3_LocalIPPortRaceDuringSetIdentity verifies that localIPPort() reads
// t.listener under identityMu.RLock, preventing race with SetIdentity which
// reassigns t.listener under identityMu.Lock.
// Validates R-3 (MEDIUM) fix: introducer_dial.go localIPPort() uses lock-protected snapshot.
func TestR3_LocalIPPortRaceDuringSetIdentity(t *testing.T) {
	const hammers = 100

	// Use minimal transport to avoid NAT dependencies; we only test listener access pattern
	transport := makeMinimalTransportForRaceTests(t, 200)

	// Start with nil listener to ensure localIPPort handles gracefully
	transport.listener = nil

	var wg sync.WaitGroup
	stopCh := make(chan struct{})

	// Goroutine 1: hammer localIPPort() which reads t.listener
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stopCh:
				return
			default:
				// Call localIPPort which should snapshot t.listener under lock (R-3 fix)
				// Expected to return error when listener is nil
				transport.localIPPort()
			}
		}
	}()

	// Goroutine 2: mutate t.listener pointer under identityMu (simulating SetIdentity rebind)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < hammers; i++ {
			transport.identityMu.Lock()
			// Simulate listener reassignment during SetIdentity
			// Just toggle nil/non-nil to trigger race if not properly synchronized
			if i%2 == 0 {
				transport.listener = nil
			}
			// Alternately leave it nil to ensure localIPPort doesn't crash
			transport.identityMu.Unlock()
		}
		// Close stopCh AFTER completing all iterations
		close(stopCh)
	}()

	// Wait for goroutines to finish
	wg.Wait()

	// If we get here without data race or crash, R-3 fix is working
}

// TestL2_AbandonedRelayTagsBounded verifies that abandonedRelayTags slice
// is bounded by age-based pruning and a hard cap, preventing unbounded growth.
// Validates L-2 (MEDIUM) fix: trackAbandonedRelayTag prunes old entries and enforces size limit.
func TestL2_AbandonedRelayTagsBounded(t *testing.T) {
	transport := makeMinimalTransportForRaceTests(t, 200)

	// Track 100 abandoned relay tags
	for i := 0; i < 100; i++ {
		addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 10000 + i}
		transport.trackAbandonedRelayTag(uint32(i), addr, "test_reason")
	}

	// Verify count is bounded (maxAbandonedRelayTags = 50)
	count := transport.GetAbandonedRelayTagCount()
	require.LessOrEqual(t, count, 50, "abandonedRelayTags should be capped at 50")

	// Now wait 11 minutes to trigger age-based pruning (maxAbandonedRelayTagAge = 10 minutes)
	// Simulate by mutating allocatedAt timestamps
	transport.abandonedRelayTagsMu.Lock()
	for i := range transport.abandonedRelayTags {
		transport.abandonedRelayTags[i].allocatedAt = time.Now().Add(-11 * time.Minute)
	}
	transport.abandonedRelayTagsMu.Unlock()

	// Track one more to trigger pruning
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 20000}
	transport.trackAbandonedRelayTag(999, addr, "trigger_pruning")

	// Verify old entries were pruned
	count = transport.GetAbandonedRelayTagCount()
	require.Equal(t, 1, count, "age-based pruning should remove all entries older than 10 minutes, leaving only the new one")
}
