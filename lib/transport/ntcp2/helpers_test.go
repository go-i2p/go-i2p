package ntcp2

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/go-noise/ntcp2"
	"github.com/go-i2p/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestRouterHash creates a 32-byte test router hash with each byte set to
// its index plus the given offset.
func newTestRouterHash(offset byte) data.Hash {
	var h data.Hash
	for i := range h {
		h[i] = byte(i) + offset
	}
	return h
}

// newTestNTCP2Config creates a test NTCP2Config with a standard 32-byte router
// hash (sequential bytes starting at 0). Use newTestRouterHash directly when
// the test needs a non-default hash or must inspect the hash value.
func newTestNTCP2Config(t *testing.T, isInitiator bool) *ntcp2.Config {
	t.Helper()
	routerHash := newTestRouterHash(0)
	config, err := ntcp2.NewNTCP2Config(routerHash, isInitiator)
	require.NoError(t, err, "NewNTCP2Config must succeed with valid 32-byte hash")
	return config
}

// newTestSession creates an NTCP2Session backed by a mockConn for testing.
// The session's context and Close are registered with t.Cleanup automatically.
func newTestSession(t *testing.T) *NTCP2Session {
	t.Helper()
	conn := &mockConn{data: []byte{}}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	log := logger.WithField("test", t.Name())
	session := NewNTCP2Session(conn, ctx, log)
	t.Cleanup(func() { session.Close() })
	return session
}

// newTestPeerHash creates a data.Hash from the given string content.
func newTestPeerHash(content string) data.Hash {
	var h data.Hash
	copy(h[:], []byte(content))
	return h
}

// newAcceptTestSetup creates an accept-test fixture with a mock connection
// ready to be consumed by Accept(). This bypasses the handshake path (which
// would reject the mock connection per SM-3 fix) and injects a pre-tracked
// connection directly into pendingConns to test session tracking logic
// independently of handshake validation. The connection is fully tracked: it's
// in the sessions map, the session count is incremented, and the onClose
// callback will clean up properly. The transport's context is cleaned up
// automatically via t.Cleanup.
func newAcceptTestSetup(t *testing.T, remoteAddr string, maxSessions int) (*NTCP2Transport, *acceptMockConn) {
	t.Helper()
	conn := newAcceptMockConn(remoteAddr)

	// Create transport with a mock listener (to pass Accept() nil check) and pendingConns channel
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	mockListener := newMockListener() // No connections in channel yet

	transport := &NTCP2Transport{
		ctx:                          ctx,
		cancel:                       cancel,
		logger:                       logger.WithField("test", "accept"),
		sessions:                     sync.Map{},
		pendingConns:                 make(chan net.Conn, 10),
		listener:                     mockListener, // Set listener to pass Accept() nil check
		testBypassHandshakeTypeCheck: true,         // Allow mock connections in tests
	}

	// HIGH-1.3 fix: Initialize atomic.Pointer[Config] after struct creation
	transport.config.Store(&Config{
		ListenerAddress: "127.0.0.1:0",
		MaxSessions:     maxSessions,
	})

	// Mark the acceptRunOnce as already executed so Accept() won't start the
	// real accept loop (which would try to read from the mock listener and block)
	transport.acceptRunOnce.Do(func() {
		// pendingConns is already initialized above
	})

	// Extract peer hash for session tracking (mimics trackInboundConnection)
	peerHash := transport.extractPeerHash(conn)

	// Store the raw connection in sessions map (will be replaced with tracked conn)
	transport.sessions.Store(peerHash, conn)

	// Increment session count (mimics checkSessionLimit reservation)
	atomic.AddInt32(&transport.sessionCount, 1)

	// Create tracked connection wrapper with cleanup callback that calls removeSession
	// (mimics trackInboundConnection wrapping)
	tracked := &trackedConn{
		Conn: conn,
		onClose: func() {
			transport.removeSession(peerHash)
		},
	}

	// Update sessions map with the tracked connection
	transport.sessions.Store(peerHash, tracked)

	// Inject into pendingConns for Accept() to consume
	transport.pendingConns <- tracked

	return transport, conn
}

// newNilListenerTestTransport creates an NTCP2Transport with a nil listener,
// suitable for testing session-map operations without Accept. The transport's
// context is cleaned up automatically via t.Cleanup.
func newNilListenerTestTransport(t *testing.T, maxSessions int) *NTCP2Transport {
	t.Helper()
	transport := newTestTransport(nil, maxSessions)
	t.Cleanup(func() { transport.cancel() })
	return transport
}

// newMinimalTransportWithHash creates a minimal transport (no listener, no
// crypto) together with a data.Hash derived from hashContent. The transport's
// context is cleaned up automatically via t.Cleanup.
func newMinimalTransportWithHash(t *testing.T, hashContent string) (*NTCP2Transport, data.Hash) {
	t.Helper()
	transport, cancel := newMinimalTransport()
	t.Cleanup(cancel)
	return transport, newTestPeerHash(hashContent)
}

// newPersistentConfigWithIV creates a PersistentConfig in a fresh temp
// directory and generates (or loads) an obfuscation IV. Returns the temp
// directory path, the PersistentConfig, and the generated IV.
func newPersistentConfigWithIV(t *testing.T) (string, *PersistentConfig, []byte) {
	t.Helper()
	tempDir := t.TempDir()
	pc := NewPersistentConfig(tempDir)
	iv, err := pc.LoadOrGenerateObfuscationIV()
	require.NoError(t, err, "Failed to generate obfuscation IV")
	return tempDir, pc, iv
}

// assertConvertToRouterAddressError calls ConvertToRouterAddress on transport
// and asserts that it returns an error containing errContains.
func assertConvertToRouterAddressError(t *testing.T, transport *NTCP2Transport, errContains string) {
	t.Helper()
	routerAddr, err := ConvertToRouterAddress(transport)
	assert.Error(t, err)
	assert.Nil(t, routerAddr)
	assert.Contains(t, err.Error(), errContains)
}
