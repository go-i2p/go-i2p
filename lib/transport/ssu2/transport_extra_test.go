package ssu2

// transport_extra_test.go covers additional SSU2Transport helpers that were
// not yet hit by the existing test suite: Compatible, createSSU2Config,
// initializeCryptoKeys, extractPeerHash, and trackedConn.Close.

import (
	"context"
	"crypto/rand"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/crypto/types"
	ssu2noise "github.com/go-i2p/go-noise/ssu2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Mock helpers
// ---------------------------------------------------------------------------

// mockPrivateKey is a minimal types.PrivateEncryptionKey implementation that
// returns a fixed 32-byte key.
type mockPrivateKey struct {
	key []byte
}

func (m *mockPrivateKey) Bytes() []byte                              { return m.key }
func (m *mockPrivateKey) Zero()                                      {}
func (m *mockPrivateKey) NewDecrypter() (types.Decrypter, error)     { return nil, nil }
func (m *mockPrivateKey) Public() (types.PublicEncryptionKey, error) { return nil, nil }

// mockKeystore satisfies KeystoreProvider.
type mockKeystore struct {
	privKey types.PrivateEncryptionKey
}

func (m *mockKeystore) GetEncryptionPrivateKey() types.PrivateEncryptionKey { return m.privKey }

// ---------------------------------------------------------------------------
// Compatible
// ---------------------------------------------------------------------------

// TestCompatible_EmptyRouterInfo verifies that Compatible returns false for a
// zero-value RouterInfo (no SSU2 addresses).
func TestCompatible_EmptyRouterInfo(t *testing.T) {
	tr := makeMinimalTransport()
	var ri router_info.RouterInfo
	assert.False(t, tr.Compatible(ri))
}

// ---------------------------------------------------------------------------
// createSSU2Config
// ---------------------------------------------------------------------------

// TestCreateSSU2Config_NilIdentity verifies that createSSU2Config propagates
// the error from IdentHash when router_identity is nil.
func TestCreateSSU2Config_NilIdentity(t *testing.T) {
	var ri router_info.RouterInfo // router_identity is nil → IdentHash errors
	_, err := createSSU2Config(ri)
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// initializeCryptoKeys
// ---------------------------------------------------------------------------

// TestInitializeCryptoKeys_AlreadySet verifies that when the SSU2Config
// already has a 32-byte StaticKey, initializeCryptoKeys is a no-op and
// the keystore is never consulted.
func TestInitializeCryptoKeys_AlreadySet(t *testing.T) {
	cfg := &ssu2noise.SSU2Config{StaticKey: make([]byte, 32)}
	err := initializeCryptoKeys(cfg, nil) // keystore is nil, should not be called
	assert.NoError(t, err)
}

// TestInitializeCryptoKeys_NilKey verifies that initializeCryptoKeys returns
// an error when the keystore returns a nil encryption key.
func TestInitializeCryptoKeys_NilKey(t *testing.T) {
	cfg := &ssu2noise.SSU2Config{} // empty StaticKey
	ks := &mockKeystore{privKey: nil}
	err := initializeCryptoKeys(cfg, ks)
	assert.Error(t, err)
}

// TestInitializeCryptoKeys_WrongKeySize verifies that initializeCryptoKeys
// returns an error when the provided key is not exactly 32 bytes.
func TestInitializeCryptoKeys_WrongKeySize(t *testing.T) {
	cfg := &ssu2noise.SSU2Config{}
	ks := &mockKeystore{privKey: &mockPrivateKey{key: make([]byte, 16)}} // too short
	err := initializeCryptoKeys(cfg, ks)
	assert.Error(t, err)
}

// TestInitializeCryptoKeys_ValidKey verifies the happy path where a 32-byte
// key is loaded into the config.
func TestInitializeCryptoKeys_ValidKey(t *testing.T) {
	cfg := &ssu2noise.SSU2Config{}
	key32 := make([]byte, 32)
	for i := range key32 {
		key32[i] = byte(i)
	}
	ks := &mockKeystore{privKey: &mockPrivateKey{key: key32}}
	err := initializeCryptoKeys(cfg, ks)
	require.NoError(t, err)
	assert.Equal(t, key32, cfg.StaticKey)
}

// ---------------------------------------------------------------------------
// extractPeerHash
// ---------------------------------------------------------------------------

// fakeConn is a minimal net.Conn that exposes a controllable RemoteAddr.
type fakeConn struct {
	net.Conn
	remoteAddr net.Addr
}

func (f *fakeConn) RemoteAddr() net.Addr { return f.remoteAddr }

// TestExtractPeerHash_NonSSU2Addr verifies that extractPeerHash falls back to
// address-derived hash when the connection does not use an SSU2Addr.
func TestExtractPeerHash_NonSSU2Addr(t *testing.T) {
	tr := makeMinimalTransport()
	conn := &fakeConn{remoteAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}}
	hash := tr.extractPeerHash(conn)
	// Must not be the zero hash (something was derived from the address).
	var zeroHash [32]byte
	assert.NotEqual(t, zeroHash, hash)
}

// ---------------------------------------------------------------------------
// trackedConn.Close
// ---------------------------------------------------------------------------

// TestTrackedConn_Close verifies that Close invokes the onClose callback and
// delegates to the underlying connection.
func TestTrackedConn_Close(t *testing.T) {
	if testing.Short() {
		t.Skip("skips loopback allocation in short mode")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	serverConn, clientConn := loopbackPair(t, ctx)
	defer clientConn.Close()

	var mu sync.Mutex
	var callCount int
	tc := &trackedConn{
		Conn: serverConn,
		onClose: func() {
			mu.Lock()
			callCount++
			mu.Unlock()
		},
	}

	require.NoError(t, tc.Close())

	mu.Lock()
	n := callCount
	mu.Unlock()
	assert.Equal(t, 1, n, "onClose should be invoked exactly once")
}

// TestTrackedConn_CloseIdempotent verifies that calling Close twice only
// triggers the callback once (sync.Once guard).
func TestTrackedConn_CloseIdempotent(t *testing.T) {
	if testing.Short() {
		t.Skip("skips loopback allocation in short mode")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	serverConn, clientConn := loopbackPair(t, ctx)
	defer clientConn.Close()

	var mu sync.Mutex
	var callCount int
	tc := &trackedConn{
		Conn: serverConn,
		onClose: func() {
			mu.Lock()
			callCount++
			mu.Unlock()
		},
	}

	tc.Close() //nolint:errcheck
	tc.Close() //nolint:errcheck

	mu.Lock()
	n := callCount
	mu.Unlock()
	assert.Equal(t, 1, n, "onClose must fire at most once")
}

// ---------------------------------------------------------------------------
// GetTotalBandwidth with active sessions
// ---------------------------------------------------------------------------

// TestGetTotalBandwidth_WithSessions verifies that GetTotalBandwidth sums
// bandwidth stats from all stored SSU2Sessions.
func TestGetTotalBandwidth_WithSessions(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping loopback test in short mode")
	}
	server, client, cancel := makeTestSession(t)
	defer cancel()
	defer server.Close()
	defer client.Close()

	tr := makeMinimalTransport()
	var key [32]byte
	key[0] = 0x01
	tr.sessions.Store(key, server)

	sent, received := tr.GetTotalBandwidth()
	// Fresh sessions have zero bandwidth.
	assert.Equal(t, uint64(0), sent)
	assert.Equal(t, uint64(0), received)
}

// ---------------------------------------------------------------------------
// setupUDPListener
// ---------------------------------------------------------------------------

// TestSetupUDPListener_ValidListenerAddress verifies that setupUDPListener
// binds to an ephemeral UDP port and initialises the NAT managers.
func TestSetupUDPListener_ValidListenerAddress(t *testing.T) {
	var routerHash data.Hash
	_, err := rand.Read(routerHash[:])
	require.NoError(t, err)

	cfg, err := ssu2noise.NewSSU2Config(routerHash, false)
	require.NoError(t, err)
	cfg = cfg.WithRouterInfoValidator(func(routerInfo, authenticatedStaticKey []byte) error {
		return nil // Accept any RouterInfo in tests
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tr := &SSU2Transport{
		logger: log.WithField("test", "setup_udp"),
		ctx:    ctx,
		cancel: cancel,
	}
	config := &Config{ListenerAddress: "127.0.0.1:0"}

	err = setupUDPListener(tr, config, cfg)
	require.NoError(t, err)
	require.NotNil(t, tr.listener)
	defer func() {
		tr.listener.Close()
	}()

	// NAT managers should also be initialised.
	assert.NotNil(t, tr.peerTestManager)
	assert.NotNil(t, tr.relayManager)
}

// TestSetupUDPListener_InvalidAddress verifies that an invalid address returns
// an error.
func TestSetupUDPListener_InvalidAddress(t *testing.T) {
	var routerHash data.Hash
	cfg, _ := ssu2noise.NewSSU2Config(routerHash, false)

	tr := &SSU2Transport{
		logger: log.WithField("test", "setup_udp_err"),
	}
	config := &Config{ListenerAddress: "not-a-valid-address"}

	err := setupUDPListener(tr, config, cfg)
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// Accept
// ---------------------------------------------------------------------------

// TestAccept_NilListener verifies that Accept returns ErrSessionClosed when
// there is no listener.
func TestAccept_NilListener(t *testing.T) {
	tr := makeMinimalTransport() // listener = nil
	_, err := tr.Accept()
	assert.Error(t, err)
}

// TestAccept_SessionLimitFull verifies that Accept returns ErrConnectionPoolFull
// once all session slots are reserved — before it calls listener.Accept().
func TestAccept_SessionLimitFull(t *testing.T) {
	tr, cleanup := makeTestTransportWithListener(t)
	defer cleanup()

	maxSessions := tr.config.GetMaxSessions()
	for i := 0; i < maxSessions; i++ {
		require.NoError(t, tr.checkSessionLimit())
	}

	_, err := tr.Accept()
	assert.ErrorIs(t, err, ErrConnectionPoolFull)
}

// ---------------------------------------------------------------------------
// findExistingSession
// ---------------------------------------------------------------------------

// TestFindExistingSession_NotFound verifies that a missing key returns false.
func TestFindExistingSession_NotFound(t *testing.T) {
	tr := makeMinimalTransport()
	var hash data.Hash
	_, found := tr.findExistingSession(hash)
	assert.False(t, found)
}

// TestFindExistingSession_LiveSession verifies that a live SSU2Session is
// returned when its context is still active.
func TestFindExistingSession_LiveSession(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping loopback test in short mode")
	}
	server, client, cancel := makeTestSession(t)
	defer cancel()
	defer client.Close()

	tr := makeMinimalTransport()
	var hash data.Hash
	hash[0] = 0x42
	tr.sessions.Store(hash, server)
	atomic.AddInt32(&tr.sessionCount, 1) // reflect the reservation

	session, found := tr.findExistingSession(hash)
	assert.True(t, found)
	assert.Equal(t, server, session)

	server.Close()
}

// TestFindExistingSession_DeadSession verifies that a session whose context is
// cancelled is removed from the map and returns false.
func TestFindExistingSession_DeadSession(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping loopback test in short mode")
	}
	server, client, cancel := makeTestSession(t)
	// Cancel first so the session is "dead".
	cancel()
	defer client.Close()

	tr := makeMinimalTransport()
	var hash data.Hash
	hash[0] = 0x43
	tr.sessions.Store(hash, server)
	atomic.AddInt32(&tr.sessionCount, 1)

	_, found := tr.findExistingSession(hash)
	assert.False(t, found)
	// Session should have been removed and count decremented.
	assert.Equal(t, 0, tr.GetSessionCount())
}
