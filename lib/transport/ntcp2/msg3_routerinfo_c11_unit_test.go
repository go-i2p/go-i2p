// Tests for the NTCP2 msg3 RouterInfo validation gate (audit finding C11).
//
// Spec (ntcp2.rst, SessionConfirmed Notes): Bob must perform the usual Router
// Info validation — supported signature type, signature verification, and
// timestamp within bounds — and "on any error, including AEAD, RI, DH,
// timestamp, or key validation failure, Bob must halt further message
// processing and close the connection."

package ntcp2

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	i2pbase64 "github.com/go-i2p/common/base64"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/keys_and_cert"
	"github.com/go-i2p/common/router_address"
	"github.com/go-i2p/common/router_identity"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/common/signature"
	"github.com/go-i2p/crypto/curve25519"
	"github.com/go-i2p/crypto/ed25519"
	i2prand "github.com/go-i2p/crypto/rand"
	"github.com/go-i2p/crypto/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- mock msg3 connection ---

type mockMsg3Conn struct {
	riBytes     []byte
	staticKey   []byte
	remoteAddr  net.Addr
	closeCalled bool
}

func (m *mockMsg3Conn) Close() error {
	m.closeCalled = true
	return nil
}

func (m *mockMsg3Conn) PeerRouterInfoBytes() []byte { return m.riBytes }

func (m *mockMsg3Conn) PeerStaticKey() []byte { return m.staticKey }

func (m *mockMsg3Conn) RemoteAddr() net.Addr {
	if m.remoteAddr != nil {
		return m.remoteAddr
	}
	return &net.TCPAddr{IP: net.IPv4(203, 0, 111, 5), Port: 3333}
}

// The msg3 gate also takes the raw net.Conn for logging only; the mock
// satisfies net.Conn with inert stubs.
func (m *mockMsg3Conn) LocalAddr() net.Addr              { return m.RemoteAddr() }
func (m *mockMsg3Conn) Read([]byte) (int, error)         { return 0, io.EOF }
func (m *mockMsg3Conn) Write(p []byte) (int, error)      { return len(p), nil }
func (m *mockMsg3Conn) SetDeadline(time.Time) error      { return nil }
func (m *mockMsg3Conn) SetReadDeadline(time.Time) error  { return nil }
func (m *mockMsg3Conn) SetWriteDeadline(time.Time) error { return nil }

// --- failable storer ---

type failingRIStorer struct{ err error }

func (f failingRIStorer) StoreRouterInfo(_ router_info.RouterInfo) {}

func (f failingRIStorer) StoreRouterInfoWithError(_ router_info.RouterInfo) error {
	return f.err
}

type recordingRIStorer struct {
	stored []router_info.RouterInfo
}

func (r *recordingRIStorer) StoreRouterInfo(_ router_info.RouterInfo) {}

func (r *recordingRIStorer) StoreRouterInfoWithError(ri router_info.RouterInfo) error {
	r.stored = append(r.stored, ri)
	return nil
}

// --- signed RouterInfo builder with a chosen published timestamp ---

type signedRIFixture struct {
	ri        router_info.RouterInfo
	staticKey []byte // X25519 (Noise "s") public key bytes
}

func buildSignedRI(t *testing.T, published time.Time) *signedRIFixture {
	t.Helper()

	ed25519PrivKey, err := ed25519.GenerateEd25519Key()
	require.NoError(t, err)
	privTyped := ed25519PrivKey.(ed25519.Ed25519PrivateKey)
	ed25519PubKey, err := privTyped.Public()
	require.NoError(t, err)

	x25519PubKey, _, err := curve25519.GenerateKeyPair()
	require.NoError(t, err)
	receivingPubKey, ok := x25519PubKey.(types.ReceivingPublicKey)
	require.True(t, ok)
	staticKeyBytes := receivingPubKey.Bytes()
	require.Len(t, staticKeyBytes, 32)

	cert, err := key_certificate.NewEd25519X25519KeyCertificate()
	require.NoError(t, err)

	pubKeySize := cert.CryptoSize()
	sigKeySize := cert.SigningPublicKeySize()
	padding := make([]byte, keys_and_cert.KEYS_AND_CERT_DATA_SIZE-pubKeySize-sigKeySize)
	_, err = i2prand.Read(padding)
	require.NoError(t, err)

	identity, err := router_identity.NewRouterIdentity(receivingPubKey, ed25519PubKey, &cert.Certificate, padding)
	require.NoError(t, err)

	addr, err := router_address.NewRouterAddress(3, published.Add(24*time.Hour), "NTCP2", map[string]string{
		"host": "203.0.111.5",
		"port": "3333",
		"s":    i2pbase64.I2PEncoding.EncodeToString(staticKeyBytes),
		"v":    "2",
	})
	require.NoError(t, err)

	ri, err := router_info.NewRouterInfo(
		identity,
		published,
		[]*router_address.RouterAddress{addr},
		map[string]string{"netId": "2", "router.version": "0.9.64"},
		&privTyped,
		signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
	)
	require.NoError(t, err)
	require.NoError(t, ri.Validate())

	return &signedRIFixture{ri: *ri, staticKey: staticKeyBytes}
}

func riBytesOf(t *testing.T, ri router_info.RouterInfo) []byte {
	t.Helper()
	b, err := ri.Bytes()
	require.NoError(t, err)
	return b
}

// --- tests ---

// A valid, fresh, correctly-signed msg3 RouterInfo whose "s" option matches
// the Noise-authenticated static key must pass the gate and be stored.
func TestC11_Msg3RouterInfo_ValidAcceptedAndStored(t *testing.T) {
	tr, cancel := newMinimalTransport()
	t.Cleanup(cancel)

	fixture := buildSignedRI(t, time.Now())
	storer := &recordingRIStorer{}
	tr.routerInfoStorer.Store(storer)

	mock := &mockMsg3Conn{
		riBytes:   riBytesOf(t, fixture.ri),
		staticKey: fixture.staticKey,
	}
	require.NoError(t, tr.extractAndStorePeerRouterInfo(mock, mock))
	assert.False(t, mock.closeCalled, "connection must stay open on success")
	require.Len(t, storer.stored, 1, "peer RouterInfo must be stored")
}

// A RouterInfo with a broken signature must halt the handshake and close.
func TestC11_Msg3RouterInfo_BadSignatureHalts(t *testing.T) {
	tr, cancel := newMinimalTransport()
	t.Cleanup(cancel)

	fixture := buildSignedRI(t, time.Now())
	riBytes := riBytesOf(t, fixture.ri)
	// Flip a byte inside the trailing signature so verification fails while
	// the record still parses.
	riBytes[len(riBytes)-1] ^= 0xFF

	storer := &recordingRIStorer{}
	tr.routerInfoStorer.Store(storer)

	mock := &mockMsg3Conn{riBytes: riBytes, staticKey: fixture.staticKey}
	err := tr.extractAndStorePeerRouterInfo(mock, mock)
	require.Error(t, err, "invalid signature must be a fatal handshake error")
	assert.Contains(t, err.Error(), "signature")
	assert.True(t, mock.closeCalled, "connection must be closed on RI validation error")
	assert.Empty(t, storer.stored, "a RouterInfo that failed validation must not be stored")
}

// A RouterInfo older than the msg3 maximum age must halt the handshake.
func TestC11_Msg3RouterInfo_TooOldHalts(t *testing.T) {
	tr, cancel := newMinimalTransport()
	t.Cleanup(cancel)

	stale := time.Now().Add(-msg3RouterInfoMaxAge - time.Hour)
	fixture := buildSignedRI(t, stale)

	mock := &mockMsg3Conn{
		riBytes:   riBytesOf(t, fixture.ri),
		staticKey: fixture.staticKey,
	}
	err := tr.extractAndStorePeerRouterInfo(mock, mock)
	require.Error(t, err, "stale RouterInfo must be a fatal handshake error")
	assert.Contains(t, err.Error(), "too old")
	assert.True(t, mock.closeCalled)
}

// A RouterInfo dated too far in the future must halt the handshake.
func TestC11_Msg3RouterInfo_TooFutureHalts(t *testing.T) {
	tr, cancel := newMinimalTransport()
	t.Cleanup(cancel)

	future := time.Now().Add(msg3RouterInfoMaxFutureSkew + time.Hour)
	fixture := buildSignedRI(t, future)

	mock := &mockMsg3Conn{
		riBytes:   riBytesOf(t, fixture.ri),
		staticKey: fixture.staticKey,
	}
	err := tr.extractAndStorePeerRouterInfo(mock, mock)
	require.Error(t, err, "future-dated RouterInfo must be a fatal handshake error")
	assert.Contains(t, err.Error(), "future")
	assert.True(t, mock.closeCalled)
}

// Just inside the bounds must be accepted (no off-by-one rejections).
func TestC11_Msg3RouterInfo_BoundaryAccepted(t *testing.T) {
	tr, cancel := newMinimalTransport()
	t.Cleanup(cancel)

	fixture := buildSignedRI(t, time.Now().Add(-msg3RouterInfoMaxAge+time.Minute))
	mock := &mockMsg3Conn{
		riBytes:   riBytesOf(t, fixture.ri),
		staticKey: fixture.staticKey,
	}
	require.NoError(t, tr.extractAndStorePeerRouterInfo(mock, mock))
}

// The static key presented in the handshake must match the RouterInfo "s"
// option (F107); a mismatch halts and closes.
func TestC11_Msg3RouterInfo_StaticKeyMismatchHalts(t *testing.T) {
	tr, cancel := newMinimalTransport()
	t.Cleanup(cancel)

	fixture := buildSignedRI(t, time.Now())
	wrongKey := make([]byte, 32)
	copy(wrongKey, fixture.staticKey)
	wrongKey[0] ^= 0xAA

	mock := &mockMsg3Conn{riBytes: riBytesOf(t, fixture.ri), staticKey: wrongKey}
	err := tr.extractAndStorePeerRouterInfo(mock, mock)
	require.Error(t, err, "static key mismatch must be a fatal handshake error")
	assert.True(t, mock.closeCalled)
}

// If the NetDB refuses to persist the RouterInfo the session cannot be
// routed to; the gate must halt rather than continue degraded.
func TestC11_Msg3RouterInfo_StoreFailureHalts(t *testing.T) {
	tr, cancel := newMinimalTransport()
	t.Cleanup(cancel)

	fixture := buildSignedRI(t, time.Now())
	tr.routerInfoStorer.Store(failingRIStorer{err: errors.New("netdb full")})

	mock := &mockMsg3Conn{
		riBytes:   riBytesOf(t, fixture.ri),
		staticKey: fixture.staticKey,
	}
	err := tr.extractAndStorePeerRouterInfo(mock, mock)
	require.Error(t, err, "storage failure must be a fatal handshake error")
	assert.Contains(t, err.Error(), "netdb full")
	assert.True(t, mock.closeCalled)
}

// Unparseable msg3 RouterInfo bytes must halt the handshake.
func TestC11_Msg3RouterInfo_ParseFailureHalts(t *testing.T) {
	tr, cancel := newMinimalTransport()
	t.Cleanup(cancel)

	mock := &mockMsg3Conn{riBytes: []byte{0x01, 0x02, 0x03}}
	err := tr.extractAndStorePeerRouterInfo(mock, mock)
	require.Error(t, err)
	assert.True(t, mock.closeCalled)
}
