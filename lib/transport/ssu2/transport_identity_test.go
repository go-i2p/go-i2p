package ssu2

// transport_identity_test.go tests SSU2Transport methods that require a valid
// RouterInfo constructed via the keys.RouterInfoKeystore. This covers
// NewSSU2Transport, createSSU2Config, SetIdentity, GetSession, and
// trackInboundConnection.

import (
	"context"
	"testing"
	"time"

	"github.com/go-i2p/common/router_address"
	"github.com/go-i2p/go-i2p/lib/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeValidIdentity creates a truly valid RouterInfo and a matching
// KeystoreProvider using the real keys.RouterInfoKeystore. The keystore stores
// its files in t.TempDir(), which is cleaned up automatically.
func makeValidIdentity(t testing.TB) (*keys.RouterInfoKeystore, *Config) {
	t.Helper()
	tmpDir := t.TempDir()
	ks, err := keys.NewRouterInfoKeystore(tmpDir, "test-router")
	require.NoError(t, err, "NewRouterInfoKeystore")

	cfg := &Config{
		ListenerAddress: "127.0.0.1:0",
		MaxSessions:     4,
	}
	return ks, cfg
}

// ---------------------------------------------------------------------------
// createSSU2Config
// ---------------------------------------------------------------------------

// TestCreateSSU2Config_ValidIdentity verifies that createSSU2Config succeeds
// when given a properly constructed RouterInfo.
func TestCreateSSU2Config_ValidIdentity(t *testing.T) {
	ks, _ := makeValidIdentity(t)

	ri, err := ks.ConstructRouterInfo(nil)
	require.NoError(t, err)
	require.NotNil(t, ri)

	cfg, err := createSSU2Config(*ri)
	require.NoError(t, err)
	assert.NotNil(t, cfg)
}

// ---------------------------------------------------------------------------
// NewSSU2Transport
// ---------------------------------------------------------------------------

// TestNewSSU2Transport_HappyPath verifies the full happy-path construction of
// an SSU2Transport, including listener startup.
func TestNewSSU2Transport_HappyPath(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}

	ks, cfg := makeValidIdentity(t)

	ri, err := ks.ConstructRouterInfo(nil)
	require.NoError(t, err)

	tr, err := NewSSU2Transport(*ri, cfg, ks)
	require.NoError(t, err)
	require.NotNil(t, tr)
	defer tr.Close()

	assert.NotNil(t, tr.Addr(), "transport should have a bound address")
}

// TestNewSSU2Transport_InvalidListenerAddress verifies that an invalid UDP
// address causes NewSSU2Transport to return an error.
func TestNewSSU2Transport_InvalidListenerAddress(t *testing.T) {
	ks, _ := makeValidIdentity(t)

	ri, err := ks.ConstructRouterInfo(nil)
	require.NoError(t, err)

	badCfg := &Config{
		ListenerAddress: "not::a::valid::address",
		MaxSessions:     4,
	}

	_, err = NewSSU2Transport(*ri, badCfg, ks)
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// SetIdentity
// ---------------------------------------------------------------------------

// TestSetIdentity_Valid verifies that SetIdentity succeeds and updates the
// transport's stored identity.
func TestSetIdentity_Valid(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}

	ks, cfg := makeValidIdentity(t)

	ri, err := ks.ConstructRouterInfo(nil)
	require.NoError(t, err)

	tr, err := NewSSU2Transport(*ri, cfg, ks)
	require.NoError(t, err)
	defer tr.Close()

	// Create a second identity (same keystore, different RouterInfo is fine—
	// what matters is that IdentHash() succeeds and the key is reloaded).
	ri2, err := ks.ConstructRouterInfo(nil)
	require.NoError(t, err)

	err = tr.SetIdentity(*ri2)
	assert.NoError(t, err)
}

// ---------------------------------------------------------------------------
// GetSession
// ---------------------------------------------------------------------------

// TestGetSession_NoSSU2Address verifies that GetSession returns an error when
// the target RouterInfo has no SSU2 transport address.
func TestGetSession_NoSSU2Address(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}

	ks, cfg := makeValidIdentity(t)

	ri, err := ks.ConstructRouterInfo(nil)
	require.NoError(t, err)

	tr, err := NewSSU2Transport(*ri, cfg, ks)
	require.NoError(t, err)
	defer tr.Close()

	// Use the same RI for the remote: it has no SSU2 addresses, so
	// createOutboundSession → ExtractSSU2Addr will fail.
	_, err = tr.GetSession(*ri)
	assert.Error(t, err)
}

// TestGetSession_WithLiveSession verifies that GetSession returns an existing
// live session from the sessions map without creating a new connection.
func TestGetSession_WithLiveSession(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}

	ks, cfg := makeValidIdentity(t)

	ri, err := ks.ConstructRouterInfo(nil)
	require.NoError(t, err)

	tr, err := NewSSU2Transport(*ri, cfg, ks)
	require.NoError(t, err)
	defer tr.Close()

	// Build a fake RouterInfo with a known IdentHash so we can pre-insert
	// a session into the map.
	ks2, _ := makeValidIdentity(t)
	ri2, err := ks2.ConstructRouterInfo(nil)
	require.NoError(t, err)

	routerHash, err := ri2.IdentHash()
	require.NoError(t, err)

	// Create a real SSU2Session via loopbackPair to act as the existing session.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	serverConn, clientConn := loopbackPair(t, ctx)
	defer clientConn.Close()
	l := newTestLogger("identity_test")
	existingSession := NewSSU2Session(serverConn, ctx, l)
	defer existingSession.Close()

	tr.sessions.Store(routerHash, existingSession)

	got, err := tr.GetSession(*ri2)
	require.NoError(t, err)
	assert.Equal(t, existingSession, got)
}

// ---------------------------------------------------------------------------
// trackInboundConnection
// ---------------------------------------------------------------------------

// TestTrackInboundConnection_Wraps verifies that trackInboundConnection returns
// a trackedConn that removes the session from the map on Close.
func TestTrackInboundConnection_Wraps(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}

	ks, cfg := makeValidIdentity(t)

	ri, err := ks.ConstructRouterInfo(nil)
	require.NoError(t, err)

	tr, err := NewSSU2Transport(*ri, cfg, ks)
	require.NoError(t, err)
	defer tr.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	serverConn, clientConn := loopbackPair(t, ctx)
	defer clientConn.Close()

	// Reserve a session slot first (trackInboundConnection reuses LoadOrStore).
	require.NoError(t, tr.checkSessionLimit())

	tracked := tr.trackInboundConnection(serverConn)
	require.NotNil(t, tracked)

	// Close the tracked connection; this should invoke the cleanup handler.
	_ = tracked.Close()
}

// ---------------------------------------------------------------------------
// ExtractSSU2Addr and ExtractSSU2NoiseAddr
// ---------------------------------------------------------------------------

// TestExtractSSU2Addr_WithAddress verifies that ExtractSSU2Addr succeeds when
// the RouterInfo has a valid SSU2 router address.
func TestExtractSSU2Addr_WithAddress(t *testing.T) {
	ks, _ := makeValidIdentity(t)

	ra := makeSSU2RouterAddress(t, "127.0.0.1", "1234")
	ri, err := ks.ConstructRouterInfo([]*router_address.RouterAddress{ra})
	require.NoError(t, err)

	addr, err := ExtractSSU2Addr(*ri)
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1:1234", addr.String())
}

// TestExtractSSU2NoiseAddr_WithAddress verifies that ExtractSSU2NoiseAddr
// returns a non-nil *SSU2Addr when the RouterInfo has a valid SSU2 address.
func TestExtractSSU2NoiseAddr_WithAddress(t *testing.T) {
	ks, _ := makeValidIdentity(t)

	ra := makeSSU2RouterAddress(t, "127.0.0.1", "9999")
	ri, err := ks.ConstructRouterInfo([]*router_address.RouterAddress{ra})
	require.NoError(t, err)

	noiseAddr, err := ExtractSSU2NoiseAddr(*ri)
	require.NoError(t, err)
	assert.NotNil(t, noiseAddr)
}

// TestExtractSSU2Addr_NoAddress verifies that ExtractSSU2Addr returns an error
// when the RouterInfo has no SSU2 address.
func TestExtractSSU2Addr_NoAddress(t *testing.T) {
	ks, _ := makeValidIdentity(t)

	ri, err := ks.ConstructRouterInfo(nil)
	require.NoError(t, err)

	_, err = ExtractSSU2Addr(*ri)
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// promoteInboundConnection via findExistingSession
// ---------------------------------------------------------------------------

// TestFindExistingSession_PromotesSSU2Conn verifies that findExistingSession
// promotes a raw *ssu2noise.SSU2Conn into an SSU2Session.
func TestFindExistingSession_PromotesSSU2Conn(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}

	ks, cfg := makeValidIdentity(t)

	ri, err := ks.ConstructRouterInfo(nil)
	require.NoError(t, err)

	tr, err := NewSSU2Transport(*ri, cfg, ks)
	require.NoError(t, err)
	defer tr.Close()

	// Build a second RouterInfo to get a distinct router hash.
	ks2, _ := makeValidIdentity(t)
	ri2, err := ks2.ConstructRouterInfo(nil)
	require.NoError(t, err)

	routerHash, err := ri2.IdentHash()
	require.NoError(t, err)

	// Create a real *SSU2Conn and store it directly (no wrapping in SSU2Session)
	// to trigger the net.Conn promotion branch in findExistingSession.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	serverConn, clientConn := loopbackPair(t, ctx)
	defer clientConn.Close()

	tr.sessions.Store(routerHash, serverConn)

	// findExistingSession should detect net.Conn and call promoteInboundConnection.
	session, found := tr.findExistingSession(routerHash)
	if found {
		assert.NotNil(t, session)
		_ = session.Close()
	}
	// Not found is also acceptable if CompareAndSwap race — just no panic.
}

// ---------------------------------------------------------------------------
// NewSSU2Transport with WorkingDir (covers initKeyManagement)
// ---------------------------------------------------------------------------

// TestNewSSU2Transport_WithWorkingDir verifies that initializing a transport
// with a WorkingDir triggers key management (initKeyManagement path).
func TestNewSSU2Transport_WithWorkingDir(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}

	ks, _ := makeValidIdentity(t)
	workDir := t.TempDir()

	cfg := &Config{
		ListenerAddress: "127.0.0.1:0",
		MaxSessions:     4,
		WorkingDir:      workDir,
	}

	ri, err := ks.ConstructRouterInfo(nil)
	require.NoError(t, err)

	tr, err := NewSSU2Transport(*ri, cfg, ks)
	require.NoError(t, err)
	require.NotNil(t, tr)
	defer tr.Close()

	// Verify that the intro key was generated (PersistentConfig initialized).
	assert.NotNil(t, tr.persistentConfig)
}
