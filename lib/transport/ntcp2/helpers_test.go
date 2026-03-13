package ntcp2

import (
	"context"
	"testing"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/go-noise/ntcp2"
	"github.com/go-i2p/logger"
	"github.com/stretchr/testify/require"
)

// newTestRouterHash creates a 32-byte test router hash with each byte set to
// its index plus the given offset.
func newTestRouterHash(offset byte) []byte {
	h := make([]byte, 32)
	for i := range h {
		h[i] = byte(i) + offset
	}
	return h
}

// newTestNTCP2Config creates a test NTCP2Config with a standard 32-byte router
// hash (sequential bytes starting at 0). Use newTestRouterHash directly when
// the test needs a non-default hash or must inspect the hash value.
func newTestNTCP2Config(t *testing.T, isInitiator bool) *ntcp2.NTCP2Config {
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

// newAcceptTestSetup creates an accept-test fixture: a mock connection fed
// through a mock listener into an NTCP2Transport. The transport's context is
// cleaned up automatically via t.Cleanup.
func newAcceptTestSetup(t *testing.T, remoteAddr string, maxSessions int) (*NTCP2Transport, *acceptMockConn) {
	t.Helper()
	conn := newAcceptMockConn(remoteAddr)
	listener := newMockListener(conn)
	transport := newTestTransport(listener, maxSessions)
	t.Cleanup(func() { transport.cancel() })
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
