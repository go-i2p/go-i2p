// Regression tests for finding 006: NTCP2 sessions that hit any error were only
// cancelled, never closed.
//
// Before the fix, every fatal read/write path funnelled through setError, which
// cancelled the session context and returned. Cancelling stops the workers but
// releases nothing else: the socket stayed open and the cleanup callback never
// ran, so the session stayed in the transport registry, in the router's
// activeSessions, and held its muxer slot. The router kept handing that dead
// session to tunnel forwarding and never redialled the peer, making the lost
// link permanent until restart; enough peers like that fill the session limit
// and no new NTCP2 session can open.
//
// These tests pin the properties that close that hole:
//   - a fatal read or write error runs the full teardown (socket closed, cleanup run),
//   - the transport registry entry and its slot reservation are released,
//   - a dead session is evicted rather than reused, so the next lookup re-dials,
//   - idle maintenance reaps a session cancelled without a teardown,
//   - a late teardown never evicts the peer's replacement session.

package ntcp2

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-i2p/common/data"
	gontcp2 "github.com/go-i2p/go-noise/ntcp2"

	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// registerTestSession mirrors NTCP2Transport.setupSession's outbound wiring
// (slot already reserved, LoadOrStore, identity-scoped cleanup, StartWorkers)
// for a net.Conn. setupSession itself takes the concrete *ntcp2.Conn produced by
// a real handshake, so — as in the other session tests here — the registry
// bookkeeping is reproduced directly instead of dialling a peer.
func registerTestSession(t *testing.T, tr *NTCP2Transport, conn net.Conn, peerHash data.Hash) *NTCP2Session {
	t.Helper()

	session := NewNTCP2SessionDeferred(conn, tr.ctx, logger.WithField("test", t.Name()))
	existing, loaded := tr.sessionRegistry.LoadOrStore(peerHash, session)
	if loaded {
		if prev, ok := existing.(*NTCP2Session); ok {
			prev.DetachConn()
		}
		session.DetachConn()
		require.NoError(t, session.Close())
		return existing.(*NTCP2Session)
	}
	session.SetCleanupCallback(func() { tr.removeSessionIfCurrent(peerHash, session) })
	session.StartWorkers()
	return session
}

// isClosed reports whether the session closed this frame source.
func (f *frameSource) isClosed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

// waitUntil polls cond until it holds or the timeout expires, so a correct
// teardown returns immediately and a missing one fails fast.
func waitUntil(t *testing.T, within time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s", within, what)
}

// writeFailConn is a live-looking connection whose writes always fail, so the
// send worker's error path can be exercised without a real peer.
type writeFailConn struct {
	*liveMockConn
	writeErr error
}

func newWriteFailConn() *writeFailConn {
	return &writeFailConn{
		liveMockConn: newLiveMockConn("10.0.0.1:6000"),
		writeErr:     errors.New("simulated write failure"),
	}
}

func (c *writeFailConn) Write(p []byte) (int, error) { return 0, c.writeErr }

// TestSessionReadErrorClosesSocketAndRunsCleanup is the core of finding 006: a
// malformed data-phase frame must tear the session down completely, not merely
// cancel its context.
func TestSessionReadErrorClosesSocketAndRunsCleanup(t *testing.T) {
	// A frame whose single block declares 50 bytes but carries 2: ParseBlocks
	// fails, which is a peer-triggerable fatal read error.
	conn := newFrameSource([]byte{0x03, 0x00, 0x32, 0x01, 0x02})
	session := NewNTCP2Session(conn, context.Background(), logger.WithField("test", t.Name()))

	cleaned := make(chan struct{})
	var once sync.Once
	session.SetCleanupCallback(func() { once.Do(func() { close(cleaned) }) })

	select {
	case <-session.GetContext().Done():
	case <-time.After(5 * time.Second):
		require.FailNow(t, "session context was not cancelled after the malformed frame")
	}

	select {
	case <-cleaned:
	case <-time.After(5 * time.Second):
		require.FailNow(t, "cleanup callback never ran: the session leaked its socket and registry entry")
	}

	assert.False(t, session.IsAlive(), "a session that hit a read error is not alive")
	assert.True(t, session.CloseRequested(), "the error path must start the teardown")
	waitUntil(t, 5*time.Second, "the socket to be closed", conn.isClosed)

	_ = session.Close()
}

// TestSessionWriteErrorClosesSocketAndRunsCleanup pins the same teardown for the
// outbound direction: a write failure is fatal and must not leave a half-open
// session registered.
func TestSessionWriteErrorClosesSocketAndRunsCleanup(t *testing.T) {
	conn := newWriteFailConn()
	session := NewNTCP2Session(conn, context.Background(), logger.WithField("test", t.Name()))

	cleaned := make(chan struct{})
	var once sync.Once
	session.SetCleanupCallback(func() { once.Do(func() { close(cleaned) }) })

	msg := i2np.NewDataMessage([]byte("finding 006 write path"))
	msg.SetExpiration(time.Now().Add(time.Minute))
	require.NoError(t, session.QueueSendI2NP(msg))

	select {
	case <-cleaned:
	case <-time.After(5 * time.Second):
		require.FailNow(t, "cleanup callback never ran after a write error")
	}

	assert.False(t, session.IsAlive(), "a session that hit a write error is not alive")
	assert.True(t, conn.isLiveClosed(), "the socket must be closed after a write error")

	_ = session.Close()
}

// TestTransportReleasesSlotWhenSessionErrors covers the slot-exhaustion half of
// the finding: after a peer-triggered read error the transport must stop counting
// the session, so the connection pool cannot fill with dead entries.
func TestTransportReleasesSlotWhenSessionErrors(t *testing.T) {
	tr := newNilListenerTestTransport(t, 10)
	peerHash := newTestPeerHash("finding006-slot-exhaustion")

	// Reserve the slot the way createOutboundSession does, then wire the session.
	require.NoError(t, tr.checkSessionLimit())
	conn := newFrameSource([]byte{0x03, 0x00, 0x32, 0x01, 0x02})
	session := registerTestSession(t, tr, conn, peerHash)
	require.NotNil(t, session)
	require.EqualValues(t, 1, tr.GetSessionCount(), "the session occupies one slot")

	waitUntil(t, 5*time.Second, "the errored session to leave the transport registry", func() bool {
		return tr.GetSessionCount() == 0
	})

	_, exists := tr.sessionRegistry.Load(peerHash)
	assert.False(t, exists, "the dead session must be removed from the registry")

	// The slot is free again, so a fresh dial is possible rather than the pool
	// being permanently full of corpses.
	require.NoError(t, tr.checkSessionLimit())
	tr.unreserveSessionSlot()
}

// TestGetSessionEvictsDeadSessionAndRedials pins the router-facing half: a dead
// session must not be handed back to the caller, because that is what stopped
// the router from ever redialling the peer.
func TestGetSessionEvictsDeadSessionAndRedials(t *testing.T) {
	tr := newNilListenerTestTransport(t, 10)
	peerHash := newTestPeerHash("finding006-evict-and-redial")

	require.NoError(t, tr.checkSessionLimit())
	conn := newLiveMockConn("10.9.8.7:5000")
	session := registerTestSession(t, tr, conn, peerHash)
	require.NotNil(t, session)

	session.setError(errors.New("simulated fatal read error"))

	waitUntil(t, 5*time.Second, "the dead session to leave the registry", func() bool {
		_, exists := tr.sessionRegistry.Load(peerHash)
		return !exists
	})

	_, found := tr.findExistingSession(peerHash)
	assert.False(t, found, "a dead session must not be reused; the caller must re-dial")

	assert.False(t, session.IsAlive())
	assert.True(t, conn.isLiveClosed(), "the teardown must close the socket too")
}

// TestIdleMaintenanceReapsCancelledSessionWithoutTeardown exercises the
// failsafe: a session cancelled by a path that never started a close must still
// be reaped, or its socket and slot stay held forever.
func TestIdleMaintenanceReapsCancelledSessionWithoutTeardown(t *testing.T) {
	tr := newNilListenerTestTransport(t, 10)
	peerHash := newTestPeerHash("finding006-idle-reap")

	require.NoError(t, tr.checkSessionLimit())
	conn := newLiveMockConn("10.5.5.5:5000")
	session := registerTestSession(t, tr, conn, peerHash)
	require.NotNil(t, session)

	// Cancel the context behind Close's back, as an unfinished teardown would:
	// the registry entry, the socket and the slot are all still held.
	session.Cancel()
	require.Error(t, session.GetContext().Err())
	require.False(t, session.CloseRequested(), "precondition: no teardown was started")

	tr.runIdleMaintenancePass()

	waitUntil(t, 5*time.Second, "idle maintenance to reap the cancelled session", func() bool {
		return conn.isLiveClosed() && tr.GetSessionCount() == 0
	})

	_, exists := tr.sessionRegistry.Load(peerHash)
	assert.False(t, exists, "the reaped session must be gone from the registry")
}

// TestStaleSessionEvictionClosesSocket pins the same behaviour on the lookup
// path GetSession uses, the only place the router notices a peer is gone when it
// is not actively forwarding to it.
func TestStaleSessionEvictionClosesSocket(t *testing.T) {
	tr := newNilListenerTestTransport(t, 10)
	peerHash := newTestPeerHash("finding006-stale-lookup")

	require.NoError(t, tr.checkSessionLimit())
	conn := newLiveMockConn("10.4.4.4:5000")
	session := registerTestSession(t, tr, conn, peerHash)
	require.NotNil(t, session)

	session.Cancel()

	evicted, ok := tr.validateExistingSession(session, peerHash)
	assert.Nil(t, evicted)
	assert.False(t, ok, "a session with a cancelled context must not be reused")

	waitUntil(t, 5*time.Second, "the stale session's socket to be closed", func() bool {
		return conn.isLiveClosed()
	})
}

// TestSessionCleanupDoesNotEvictReplacement covers the re-dial race the fix
// introduces: an old session that finally tears down after the transport has
// already re-connected to the peer must not delete the new session.
func TestSessionCleanupDoesNotEvictReplacement(t *testing.T) {
	tr := newNilListenerTestTransport(t, 10)
	peerHash := newTestPeerHash("finding006-replacement-race")

	require.NoError(t, tr.checkSessionLimit())
	oldConn := newLiveMockConn("10.3.3.3:5000")
	oldSession := registerTestSession(t, tr, oldConn, peerHash)
	require.NotNil(t, oldSession)

	// The peer reconnects: a newer session takes over the hash.
	newConn := newLiveMockConn("10.3.3.3:5001")
	newSession := NewNTCP2SessionDeferred(newConn, tr.ctx, logger.WithField("test", t.Name()))
	tr.sessionRegistry.Store(peerHash, newSession)
	newSession.SetCleanupCallback(func() { tr.removeSessionIfCurrent(peerHash, newSession) })
	newSession.StartWorkers()

	// The old session's cleanup runs late.
	tr.removeSessionIfCurrent(peerHash, oldSession)

	entry, exists := tr.sessionRegistry.Load(peerHash)
	require.True(t, exists, "the replacement session must survive the old one's cleanup")
	assert.Same(t, newSession, entry, "the registry must still hold the replacement")

	// Only when the replacement closes does the hash become free.
	require.NoError(t, newSession.Close())
	_, exists = tr.sessionRegistry.Load(peerHash)
	assert.False(t, exists, "the replacement's own cleanup must remove it")

	_ = oldSession.Close()
}

// TestPromotionLoserDoesNotCloseWinnersSocket pins the second defect found while
// fixing 006: the inbound promotion loser used to close the shared connection,
// killing the winner's live session. Because a failed read now tears a session
// down and unregisters it, that alone could turn a healthy peer link into a
// permanent dead one.
func TestPromotionLoserDoesNotCloseWinnersSocket(t *testing.T) {
	tr := newNilListenerTestTransport(t, 10)
	peerHash := newTestPeerHash("finding006-promotion-loser")

	conn := newLiveMockConn("10.2.2.2:5000")
	tr.sessionRegistry.StoreWithCount(peerHash, conn)

	winner := NewNTCP2SessionDeferred(conn, tr.ctx, logger.WithField("test", t.Name()+"-winner"))
	swapped := tr.sessionRegistry.CompareAndSwap(peerHash, conn, winner)
	require.True(t, swapped, "winner must take the registry entry")
	winner.SetCleanupCallback(func() { tr.removeSessionIfCurrent(peerHash, winner) })
	winner.StartWorkers()

	// A loser tries to promote the same conn against a stale original value.
	// Losing the CAS is expected to hand back the winner's session, not a new one.
	result, ok := tr.promoteInboundConnection(conn, struct{}{}, peerHash)
	require.True(t, ok, "the loser resolves to the winner's session")
	assert.Same(t, winner, result, "the resolved session must be the winner's, not the loser's")

	assert.False(t, conn.isLiveClosed(), "the loser must not close the winner's socket")
	assert.True(t, winner.IsAlive(), "the winner's session must still be usable")

	require.NoError(t, winner.Close())
	assert.True(t, conn.isLiveClosed(), "the winner's own close must release the socket")
}

// TestTerminationReasonForReadError pins the reason-code mapping the error-driven
// teardown uses.
func TestTerminationReasonForReadError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want byte
	}{
		{"block order violation", &BlockOrderViolation{Reason: TerminationPaddingViolation}, TerminationPaddingViolation},
		{"wrapped violation", oops.Wrapf(&BlockOrderViolation{Reason: TerminationPayloadFormatError}, "invalid NTCP2 block ordering"), TerminationPayloadFormatError},
		{"aead failure", oops.Code("DECRYPT_FAILED").Errorf("failed to decrypt frame"), TerminationAEADFailure},
		{"wrapped aead", WrapNTCP2Error(oops.Code("DECRYPT_FAILED").Errorf("failed to decrypt frame"), "reading message"), TerminationAEADFailure},
		{"frame too small", oops.Code("FRAME_TOO_SMALL").Errorf("frame below minimum"), TerminationAEADFailure},
		{"nonce exhausted", oops.Code("NONCE_EXHAUSTED").Errorf("nonce exhausted"), TerminationAEADFailure},
		{"plain EOF", io.EOF, TerminationNormalClose},
		{"generic", errors.New("boom"), TerminationNormalClose},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, terminationReasonForReadError(tc.err))
		})
	}
}

// TestSessionIsAliveNilSafe documents that a nil or zero-value session reports
// itself dead rather than panicking, so a session map can gate every lookup on
// liveness unconditionally.
func TestSessionIsAliveNilSafe(t *testing.T) {
	var nilSession *NTCP2Session
	assert.False(t, nilSession.IsAlive(), "a nil session is not alive")
	assert.False(t, nilSession.CloseRequested())

	zero := &NTCP2Session{}
	assert.False(t, zero.IsAlive(), "a session without a core is not alive")

	session := NewNTCP2SessionDeferred(newLiveMockConn("10.1.1.1:5000"), context.Background(),
		logger.WithField("test", t.Name()))
	assert.True(t, session.IsAlive())
	session.Cancel()
	assert.False(t, session.IsAlive())
}

// TestTransportHasSessionIgnoresDeadSessions keeps reachability hints honest: a
// peer whose session just died must not be reported as connected, or hop
// selection keeps choosing a dead link.
func TestTransportHasSessionIgnoresDeadSessions(t *testing.T) {
	tr := newNilListenerTestTransport(t, 10)
	peerHash := newTestPeerHash("finding006-has-session")

	require.NoError(t, tr.checkSessionLimit())
	conn := newLiveMockConn("10.0.0.9:5000")
	session := registerTestSession(t, tr, conn, peerHash)
	require.NotNil(t, session)
	require.True(t, tr.HasSession(peerHash), "a live session means the peer is reachable")

	session.Cancel()
	assert.False(t, tr.HasSession(peerHash), "a cancelled session must not count as reachable")

	_ = session.Close()
}

// TestUpdateIdleExpireWriteTimeTerminatesWithUnseededWindow guards the failsafe
// loop that finding 006's reaper runs inside. updateIdleExpireWriteTime normalises
// a non-positive stored window before computing its next value; the CAS must still
// compare against the RAW stored value, otherwise it can never succeed and the
// loop spins forever with the idle window never updated. Transports built by the
// production constructor are seeded, but hand-built fixtures are not, and a
// spinning maintenance pass means dead sessions are never reaped.
func TestUpdateIdleExpireWriteTimeTerminatesWithUnseededWindow(t *testing.T) {
	tr := newNilListenerTestTransport(t, 10)
	require.Zero(t, atomic.LoadInt64(&tr.idleExpireWriteTime), "fixture starts unseeded")

	done := make(chan struct{})
	go func() {
		tr.updateIdleExpireWriteTime(true)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		require.FailNow(t, "updateIdleExpireWriteTime spun without updating the idle window")
	}

	assert.Positive(t, atomic.LoadInt64(&tr.idleExpireWriteTime),
		"the idle window must be seeded and advanced")
}

// TestIdleMaintenancePassTerminatesWithUnseededWindow runs the whole pass, which
// is the path that reaps sessions cancelled without a teardown.
func TestIdleMaintenancePassTerminatesWithUnseededWindow(t *testing.T) {
	tr := newNilListenerTestTransport(t, 10)
	peerHash := newTestPeerHash("finding006-pass-terminates")

	require.NoError(t, tr.checkSessionLimit())
	conn := newLiveMockConn("10.6.6.6:5000")
	session := registerTestSession(t, tr, conn, peerHash)
	require.NotNil(t, session)
	session.Cancel()

	done := make(chan struct{})
	go func() {
		tr.runIdleMaintenancePass()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		require.FailNow(t, "idle maintenance pass did not terminate")
	}

	waitUntil(t, 5*time.Second, "the pass to reap the cancelled session", func() bool {
		return conn.isLiveClosed() && tr.GetSessionCount() == 0
	})
}

// --- wire-level confirmation with a real NTCP2 handshake pair ---

// wireHandshakePair performs a genuine NTCP2 wire handshake between a go-noise
// initiator and a go-i2p-driven responder, returning both data-phase
// connections. This is the pair the finding was reproduced with: the teardown
// must be driven by a real AEAD/framing failure, not a mock's error string.
func wireHandshakePair(t *testing.T) (initiator, responder *gontcp2.Conn) {
	t.Helper()
	return wireHandshakePairWith(t, nil)
}

// wireHandshakePairWith is wireHandshakePair with a hook to adjust the configs
// before the handshake runs — used by tests that need a specific frame or
// padding setting on the initiator side.
func wireHandshakePairWith(t *testing.T, configure func(*ntcp2TestKeyPair)) (initiator, responder *gontcp2.Conn) {
	t.Helper()

	p := newNTCP2TestKeyPair(t)
	if configure != nil {
		configure(&p)
	}

	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = tcpLn.Close() })

	ntcp2Ln, err := gontcp2.NewNTCP2Listener(tcpLn, p.responderConfig)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ntcp2Ln.Close() })

	tr := newTestTransport(ntcp2Ln, 10)
	t.Cleanup(tr.cancel)

	type responderResult struct {
		conn *gontcp2.Conn
		err  error
	}
	responderDone := make(chan responderResult, 1)
	go func() {
		conn, acceptErr := ntcp2Ln.Accept()
		if acceptErr != nil {
			responderDone <- responderResult{nil, acceptErr}
			return
		}
		rc, ok := conn.(*gontcp2.Conn)
		if !ok {
			responderDone <- responderResult{nil, errUnexpectedConnType}
			return
		}
		responderDone <- responderResult{rc, tr.executeHandshake(rc, context.Background())}
	}()

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(dialCancel)
	initiator, dialErr := gontcp2.DialNTCP2WithHandshakeContext(dialCtx, "tcp", tcpLn.Addr().String(), p.initiatorConfig)

	res := <-responderDone
	require.NoError(t, dialErr, "initiator dial")
	require.NoError(t, res.err, "responder handshake")
	return initiator, res.conn
}

// TestWirePeerCloseRunsFullTeardown reproduces finding 006 on a live session:
// when the peer closes TCP, the session used to be cancelled only. Both the
// malformed-frame and the plain-close variants must now close the socket and run
// cleanup, which is what lets the router notice and re-dial.
func TestWirePeerCloseRunsFullTeardown(t *testing.T) {
	for _, mode := range []string{"malformed-block", "peer-tcp-close"} {
		t.Run(mode, func(t *testing.T) {
			ic, rc := wireHandshakePair(t)

			cleaned := make(chan struct{})
			var once sync.Once
			session := NewNTCP2Session(rc, context.Background(), logger.WithField("test", t.Name()))
			session.SetCleanupCallback(func() { once.Do(func() { close(cleaned) }) })

			time.Sleep(100 * time.Millisecond) // let the receive worker enter Read

			if mode == "malformed-block" {
				// One valid AEAD frame whose only block claims 50 bytes but carries 2.
				_, err := ic.Write([]byte{0x03, 0x00, 0x32, 0x01, 0x02})
				require.NoError(t, err)
			} else {
				require.NoError(t, ic.Close())
			}

			select {
			case <-session.GetContext().Done():
			case <-time.After(5 * time.Second):
				require.FailNowf(t, "session not cancelled", "%s: context still live", mode)
			}

			select {
			case <-cleaned:
			case <-time.After(5 * time.Second):
				require.FailNowf(t, "cleanup never ran",
					"%s: the session leaked its socket, registry entry and slot", mode)
			}

			assert.False(t, session.IsAlive())

			if mode == "malformed-block" {
				// The socket must not be left half-open. The victim sends its
				// Termination block first, so the peer may legitimately read that
				// frame; what it must NOT get is an indefinite hang with the
				// session nobody is servicing any more.
				require.NoError(t, ic.SetReadDeadline(time.Now().Add(5*time.Second)))
				buf := make([]byte, 4096)
				var endErr error
				for endErr == nil {
					_, endErr = ic.Read(buf)
				}
				assert.Error(t, endErr, "%s: peer must observe the connection ending", mode)
			}

			_ = session.Close()
			_ = ic.Close()
		})
	}
}

// TestTruncatedBlockFrameClosesWithPayloadFormatError pins the reason code for a
// frame that does not decode into whole blocks (the truncated-padding class,
// H-017). It must be reported as a payload format error (ntcp2.rst:1706), not a
// silent normal close, and it must run the same full teardown.
func TestTruncatedBlockFrameClosesWithPayloadFormatError(t *testing.T) {
	// I2NP block declaring 50 bytes, carrying 2: ParseBlocks fails outright.
	conn := newFrameSource([]byte{0x03, 0x00, 0x32, 0x01, 0x02})
	session := NewNTCP2Session(conn, context.Background(), logger.WithField("test", t.Name()))

	waitUntil(t, 5*time.Second, "the malformed frame to tear the session down", func() bool {
		return conn.isClosed() && !session.IsAlive()
	})

	blocks, err := ParseBlocks([]byte{0x03, 0x00, 0x32, 0x01, 0x02})
	require.Error(t, err, "precondition: the frame must not decode")
	assert.Empty(t, blocks)
	assert.Equal(t, byte(TerminationPayloadFormatError),
		terminationReasonForReadError(newBlockParseError("frame does not decode", err)))

	_ = session.Close()
}

// TestParseBlockErrorIsTerminal verifies the typed parse failure carries the
// reason code through wrapping, which is how the teardown funnel picks it up.
func TestParseBlockErrorIsTerminal(t *testing.T) {
	base := newBlockParseError("truncated block data", errors.New("truncated block data at offset 3"))
	wrapped := oops.Wrapf(base, "failed to parse NTCP2 blocks")

	assert.Equal(t, byte(TerminationPayloadFormatError), terminationReasonForReadError(wrapped))

	var target *BlockParseError
	require.ErrorAs(t, wrapped, &target)
	assert.NotNil(t, target.Unwrap(), "the underlying decode error must stay unwrappable")
}

// TestBlockParseErrorInTerminationCases extends the reason-mapping table with the
// parse-failure class.
func TestBlockParseErrorInTerminationCases(t *testing.T) {
	assert.Equal(t, byte(TerminationPayloadFormatError),
		terminationReasonForReadError(WrapNTCP2Error(newBlockParseError("bad", nil), "reading message")))
}

// TestWireTeardownCompletesPromptly bounds how long a peer-triggered teardown
// takes to release the socket, the registry entry and the session slot.
//
// Finding 006 was graded High because a dead session was never released at all:
// the link stayed dead until the router restarted. Phase 3 measured a recovery
// window of one to five minutes, which came from the router's periodic redial
// round, not from the teardown — the session itself was still registered and its
// descriptor still open during that whole time.
//
// With the teardown driven from setError, the release is immediate, so the
// recovery window is the redial scheduling delay alone. Pinning it here keeps
// the "promptly" part of that claim honest: a regression that reintroduces a
// blocking step in Close (a parked write, a joined worker that never exits)
// would push the recovery back towards minutes and is caught by this bound.
func TestWireTeardownCompletesPromptly(t *testing.T) {
	for _, mode := range []string{"peer-tcp-close", "malformed-block"} {
		t.Run(mode, func(t *testing.T) {
			ic, rc := wireHandshakePair(t)

			cleaned := make(chan time.Time, 1)
			session := NewNTCP2Session(rc, context.Background(), logger.WithField("test", t.Name()))
			session.SetCleanupCallback(func() {
				select {
				case cleaned <- time.Now():
				default:
				}
			})

			// Let the receive worker park in Read before the peer acts, so the
			// teardown is driven by a real blocked reader rather than a race.
			time.Sleep(100 * time.Millisecond)

			start := time.Now()
			if mode == "peer-tcp-close" {
				require.NoError(t, ic.Close())
			} else {
				_, err := ic.Write([]byte{0x03, 0x00, 0x32, 0x01, 0x02})
				require.NoError(t, err)
			}

			select {
			case done := <-cleaned:
				elapsed := done.Sub(start)
				// The bound sits above the internal termination-write timeout
				// (ntcp2TerminationWriteTimeout), which a peer that has already
				// gone can consume in full: the block is best-effort, so the
				// teardown waits for TCP to give up on it before closing the
				// socket. Measured here at ~17 ms to ~1.6 s depending on whether
				// that write is attempted at all. Anything approaching minutes
				// means a step of Close has started blocking again.
				assert.Less(t, elapsed, 5*time.Second,
					"teardown took %s: the socket, registry entry and slot stay held while a peer-triggered close is stuck", elapsed)
				t.Logf("%s: full teardown in %s", mode, elapsed)
			case <-time.After(10 * time.Second):
				require.FailNow(t, "teardown never completed: the session leaked its socket and slot")
			}

			assert.False(t, session.IsAlive())
			_ = session.Close()
			_ = ic.Close()
		})
	}
}

// TestSlotExhaustionErrorStormFreesSlots answers the availability question the
// finding left open: can a peer drive enough sessions into the error path that
// the transport's session limit fills with dead entries and no new session can
// open?
//
// Before the fix that state was permanent — every errored session kept its
// registry entry, so once the limit was reached it stayed reached until restart.
// Each teardown now releases its slot as part of Close, which turns the question
// into whether the release keeps up with the errors.
//
// The transport is filled to its limit, the limit is observed to refuse a new
// peer, and then every session is driven through the real error path: an AEAD
// frame whose only block claims 50 bytes and carries 2, so ParseBlocks fails.
// The slots must all come back and the freed capacity must be usable.
func TestSlotExhaustionErrorStormFreesSlots(t *testing.T) {
	const peerCount = 32

	tr := newNilListenerTestTransport(t, peerCount)
	require.Equal(t, peerCount, tr.config.Load().GetMaxSessions(),
		"precondition: the transport limit must equal the number of peers under test")

	// The malformed frame is queued before the session is built, so the read
	// worker fails on its very first read. Queueing it afterwards would serialise
	// the test against each worker's read timeout, which holds the mock's lock.
	malformed := []byte{0x03, 0x00, 0x32, 0x01, 0x02}

	peers := make([]data.Hash, peerCount)
	sessions := make([]*NTCP2Session, peerCount)
	for i := range peers {
		peers[i] = newTestPeerHash(fmt.Sprintf("slot-storm-peer-%04d", i))
		sessions[i] = NewNTCP2SessionDeferred(newFrameSource(malformed), tr.ctx, logger.WithField("test", t.Name()))

		// Registered and counted, but not started: the "at the limit" state has
		// to be observed before any session can tear itself down.
		tr.sessionRegistry.StoreWithCount(peers[i], sessions[i])
		sessions[i].SetCleanupCallback(func() { tr.removeSessionIfCurrent(peers[i], sessions[i]) })
	}

	require.Equal(t, int32(peerCount), tr.GetSessionCount(),
		"precondition: the transport must be at its session limit")
	require.Error(t, tr.checkSessionLimit(),
		"precondition: admission must be refused at the limit")

	start := time.Now()
	for _, session := range sessions {
		session.StartWorkers()
	}

	waitUntil(t, 30*time.Second, "the error storm to release every slot", func() bool {
		return tr.GetSessionCount() == 0
	})
	t.Logf("released %d slots in %s", peerCount, time.Since(start))

	// Capacity is available again, so the router can serve new peers. The check
	// below reserves a slot itself, so the registration pairs with it exactly as
	// setupSession does: LoadOrStore, no second increment.
	require.NoError(t, tr.checkSessionLimit(),
		"slot exhaustion must not persist once errored sessions tear down")

	replacementHash := newTestPeerHash("slot-storm-replacement")
	replacement := NewNTCP2SessionDeferred(newFrameSource(), tr.ctx, logger.WithField("test", t.Name()))
	tr.sessionRegistry.LoadOrStore(replacementHash, replacement)
	replacement.SetCleanupCallback(func() { tr.removeSessionIfCurrent(replacementHash, replacement) })
	replacement.StartWorkers()

	assert.True(t, replacement.IsAlive(), "a session registered after the storm must be live")
	assert.Equal(t, int32(1), tr.GetSessionCount(), "the new session occupies exactly one slot")

	_ = replacement.Close()
	waitUntil(t, 5*time.Second, "the post-storm session to release its slot", func() bool {
		return tr.GetSessionCount() == 0
	})
}
