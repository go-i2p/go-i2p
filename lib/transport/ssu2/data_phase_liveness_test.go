// data_phase_liveness_test.go covers finding 012 on the go-i2p side: a session
// whose handshake the peer never completed must not stay registered, and a
// message that exhausts its retransmissions into a peer that has never answered
// must close the session rather than be dropped silently.

package ssu2

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/crypto/rand"
	ssu2noise "github.com/go-i2p/go-noise/ssu2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// livenessConn builds a bare initiator conn over a throwaway socket, enough to
// answer PeerDataReceived without running a handshake.
func livenessConn(t *testing.T) *ssu2noise.SSU2Conn {
	t.Helper()

	var hash data.Hash
	_, err := rand.Read(hash[:])
	require.NoError(t, err)

	staticKey := make([]byte, 32)
	_, err = rand.Read(staticKey)
	require.NoError(t, err)

	socket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	t.Cleanup(func() { _ = socket.Close() })

	remoteHash := data.Hash{0x01}
	cfg, err := ssu2noise.NewSSU2Config(hash, true)
	require.NoError(t, err)
	cfg = cfg.
		WithStaticKey(staticKey).
		WithDestroyTimeout(0).
		WithRemoteStaticKey(staticKey).
		WithRouterInfoValidator(func(_, _ []byte) error { return nil })
	cfg.RemoteRouterHash = &remoteHash

	conn, err := ssu2noise.NewSSU2Conn(
		socket,
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9999},
		cfg,
		true,
		staticKey,
		staticKey,
	)
	require.NoError(t, err)
	t.Cleanup(func() { conn.CloseImmediate() })
	return conn
}

// livenessResponderConn is livenessConn in the responder role, for asserting that
// inbound sessions are never judged by peer silence.
func livenessResponderConn(t *testing.T) *ssu2noise.SSU2Conn {
	t.Helper()

	var hash data.Hash
	_, err := rand.Read(hash[:])
	require.NoError(t, err)

	staticKey := make([]byte, 32)
	_, err = rand.Read(staticKey)
	require.NoError(t, err)

	socket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	t.Cleanup(func() { _ = socket.Close() })

	cfg, err := ssu2noise.NewSSU2Config(hash, false)
	require.NoError(t, err)
	cfg = cfg.
		WithStaticKey(staticKey).
		WithDestroyTimeout(0).
		WithRouterInfoValidator(func(_, _ []byte) error { return nil })

	conn, err := ssu2noise.NewSSU2Conn(
		socket,
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9999},
		cfg,
		false,
		staticKey,
		nil,
	)
	require.NoError(t, err)
	t.Cleanup(func() { conn.CloseImmediate() })
	return conn
}

// livenessSession returns a session whose workers were never started, so a
// requestClose() cannot deadlock on WaitGroup().Wait() while the test observes it.
func livenessSession(t *testing.T, conn *ssu2noise.SSU2Conn) *SSU2Session {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s := NewSSU2SessionDeferred(conn, ctx, newTestLogger("liveness"))
	s.maxRetransmit = 2
	return s
}

func TestSSU2Session_PeerSilent(t *testing.T) {
	conn := livenessConn(t)
	s := livenessSession(t, conn)

	assert.True(t, s.peerSilent(),
		"a peer that has never sent a data packet must read as silent")
}

// TestSSU2Session_PeerSilent_InboundSessionIsNeverSilent guards the scoping: a
// peer that dialled us has already proved itself by completing the handshake, and
// may simply not have sent data yet. Treating that as a dead peer would close
// healthy inbound sessions on a race.
func TestSSU2Session_PeerSilent_InboundSessionIsNeverSilent(t *testing.T) {
	conn := livenessResponderConn(t)
	s := livenessSession(t, conn)

	require.False(t, conn.IsInitiator(), "fixture must be the responder role")
	assert.False(t, s.peerSilent(),
		"an inbound session with no peer data yet must not be read as a dead peer")
}

func TestSSU2Session_PeerSilent_DetachedConnIsNotSilent(t *testing.T) {
	conn := livenessConn(t)
	s := livenessSession(t, conn)
	s.DetachConn()

	assert.False(t, s.peerSilent(),
		"a detached session is tearing down, not being ignored by a peer")
}

// TestSSU2Session_ProcessRetransmission_ClosesSilentPeer is the go-i2p half of
// finding 012: the transport used to drop the message and deliberately keep the
// session, which is what let a dead half-session occupy a slot forever.
func TestSSU2Session_ProcessRetransmission_ClosesSilentPeer(t *testing.T) {
	conn := livenessConn(t)
	s := livenessSession(t, conn)

	seq := s.trackPendingBlocks([]byte("payload"), nil)
	p := s.pendingMsgs[seq]
	require.NotNil(t, p)
	p.attempts = s.maxRetransmit

	action := s.processRetransmission(seq, p, time.Now())
	assert.Equal(t, retransmitDelete, action)
	// Close() waits on the worker WaitGroup and this runs on one of those workers,
	// so the teardown is asynchronous by necessity.
	require.Eventually(t, func() bool { return !s.IsAlive() },
		2*time.Second, 10*time.Millisecond,
		"a message that aged out into a peer that never answered must end the session")
}

// TestSSU2Session_ProcessRetransmission_DropsWhenPeerIsTalking covers the
// regression that made this teardown be removed in the first place (7c03218bc):
// a session with a live peer must survive one message ageing out.
func TestSSU2Session_ProcessRetransmission_DropsWhenPeerIsTalking(t *testing.T) {
	conn := livenessConn(t)
	s := livenessSession(t, conn)

	// A peer that has begun the data phase is not silent. Delivered through the
	// real inbound path, the way a peer's first data packet arrives.
	conn.ProcessInboundPacket(&ssu2noise.SSU2Packet{
		MessageType:  ssu2noise.MessageTypeData,
		PacketNumber: 0,
		Header:       make([]byte, ssu2noise.ShortHeaderSize),
	})

	seq := s.trackPendingBlocks([]byte("payload"), nil)
	p := s.pendingMsgs[seq]
	require.NotNil(t, p)
	p.attempts = s.maxRetransmit

	action := s.processRetransmission(seq, p, time.Now())
	assert.Equal(t, retransmitDelete, action)
	assert.True(t, s.IsAlive(),
		"an old message on a live session must be dropped, not close the session")
}

// TestSSU2Transport_HasSession_IgnoresDeadSession proves the router learns the
// peer left. A registry entry for a cancelled session made HasSession answer true
// forever, so peer selection kept preferring a dead peer and never redialled.
func TestSSU2Transport_HasSession_IgnoresDeadSession(t *testing.T) {
	tr := makeMinimalTransport()
	var peer data.Hash
	_, err := rand.Read(peer[:])
	require.NoError(t, err)

	conn := livenessConn(t)
	s := livenessSession(t, conn)
	tr.sessionRegistry.Store(peer, s)

	require.True(t, tr.HasSession(peer), "a live session must be reported")

	s.Cancel()
	assert.False(t, tr.HasSession(peer),
		"a session whose context is gone must not be reported as connected")
}

// TestSSU2Session_ReceiveWorker_TearsDownOnFatalRead covers the registry leak
// found while fixing 012: the receive worker returned on a fatal read error
// without closing, so the session kept its registry entry and the peer looked
// connected forever.
func TestSSU2Session_ReceiveWorker_TearsDownOnFatalRead(t *testing.T) {
	conn := livenessConn(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s := NewSSU2SessionDeferred(conn, ctx, newTestLogger("fatal_read"))

	var closed atomic.Bool
	s.SetCleanupCallback(func() { closed.Store(true) })

	s.StartWorkers()
	// Closing the conn underneath the session makes the next read fail in a way
	// that is not a timeout, which is exactly the fatal case.
	conn.CloseImmediate()

	require.Eventually(t, func() bool { return closed.Load() },
		5*time.Second, 20*time.Millisecond,
		"a fatal read must close the session and release its registry entry")
}

// TestSSU2Transport_HasSession_KeepsRawConn guards the other half: a registry
// entry that is not yet a session is still a connection and must still count.
func TestSSU2Transport_HasSession_KeepsRawConn(t *testing.T) {
	tr := makeMinimalTransport()
	var peer data.Hash
	_, err := rand.Read(peer[:])
	require.NoError(t, err)

	conn := livenessConn(t)
	tr.sessionRegistry.Store(peer, conn)

	assert.True(t, tr.HasSession(peer),
		"a raw connection entry must not be judged by session liveness")
}
