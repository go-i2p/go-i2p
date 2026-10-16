// Tests for SetIdentity on a REAL bound SSU2 transport.
//
// Regression coverage for the previous implementation, which tore down the NAT
// managers and then tried to acquire a second UDP socket on the same port. That
// bind can never succeed (the old listener stays open for the swap to be
// atomic), so SetIdentity always failed -- and because it had already called
// stopNATManagers, it left relay registration, peer tests, hole punching and
// intro-key publication permanently dead. No existing test built a real SSU2
// transport, so this went unnoticed.

package ssu2

import (
	"testing"

	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/crypto/types"
	"github.com/go-i2p/go-i2p/lib/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testKeystore implements KeystoreProvider for bound-transport tests. SSU2 uses
// the X25519 encryption private key as its Noise static key.
type testKeystore struct {
	keyData []byte
}

func (k *testKeystore) GetEncryptionPrivateKey() types.PrivateEncryptionKey {
	return &testEncKey{keyData: k.keyData}
}

func (k *testKeystore) GetSigningPrivateKey() types.PrivateKey {
	return &testSignKey{keyData: k.keyData}
}

type testEncKey struct {
	keyData []byte
}

func (p *testEncKey) Bytes() []byte { return p.keyData }

func (p *testEncKey) Zero() {
	for i := range p.keyData {
		p.keyData[i] = 0
	}
}

func (p *testEncKey) NewDecrypter() (types.Decrypter, error)     { return nil, nil }
func (p *testEncKey) Public() (types.PublicEncryptionKey, error) { return nil, nil }

// testSignKey satisfies types.PrivateKey, whose Public() returns a
// SigningPublicKey rather than a PublicEncryptionKey.
type testSignKey struct {
	keyData []byte
}

func (p *testSignKey) Bytes() []byte { return p.keyData }

func (p *testSignKey) Zero() {
	for i := range p.keyData {
		p.keyData[i] = 0
	}
}

func (p *testSignKey) Public() (types.SigningPublicKey, error) { return nil, nil }

// newBoundSSU2Transport builds a real SSU2 transport bound to a loopback UDP
// socket, with key management enabled via WorkingDir so IntroKey and the
// obfuscation IV are populated the way production does.
func newBoundSSU2Transport(t *testing.T) (*SSU2Transport, router_info.RouterInfo) {
	t.Helper()

	identity := testutil.CreateSignedTestRouterInfo(t, map[string]string{}, nil)
	require.NotNil(t, identity)

	config, err := NewConfig("127.0.0.1:0")
	require.NoError(t, err)
	config.WorkingDir = t.TempDir()

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 0xA0)
	}

	transport, err := NewSSU2Transport(*identity, config, &testKeystore{keyData: key})
	require.NoError(t, err, "constructing a bound SSU2 transport must succeed")
	require.NotNil(t, transport.listener, "transport must have a bound listener")

	return transport, *identity
}

func TestSetIdentity_BoundTransportUpdatesInPlace(t *testing.T) {
	transport, _ := newBoundSSU2Transport(t)
	defer transport.Close()

	oldListener := transport.listener
	oldAddr := transport.Addr()
	require.NotNil(t, oldAddr)

	newIdentity := testutil.CreateSignedTestRouterInfo(t, map[string]string{}, nil)
	require.NotNil(t, newIdentity)

	require.NoError(t, transport.SetIdentity(*newIdentity),
		"SetIdentity on a bound transport must succeed by updating in place")

	// Same socket and same listener object: no rebind, no recreation.
	assert.Same(t, oldListener, transport.listener, "the listener must not be replaced")
	assert.Equal(t, oldAddr.String(), transport.Addr().String(),
		"the listening port must be preserved")

	got, err := transport.identity.IdentHash()
	require.NoError(t, err)
	want, err := newIdentity.IdentHash()
	require.NoError(t, err)
	assert.Equal(t, want, got, "transport identity must be the new RouterInfo")

	updated := transport.config.Load().SSU2Config
	require.NotNil(t, updated)
	assert.Equal(t, want, updated.RouterHash, "the listener config must carry the new router hash")
}

// TestSetIdentity_PreservesIntroKey pins the property that makes an in-place
// update safe here. IntroKey and the obfuscation settings are loaded from
// persistent storage after the listener is constructed, so they live on the
// shared config pointer rather than being derived from the identity. A fresh
// config that dropped them would clear the listener's inbound header protector
// and disable ChaCha obfuscation for new sessions.
func TestSetIdentity_PreservesIntroKey(t *testing.T) {
	transport, _ := newBoundSSU2Transport(t)
	defer transport.Close()

	before := transport.config.Load().SSU2Config
	require.Len(t, before.IntroKey, 32, "precondition: intro key configured")
	require.True(t, before.EnableChaChaObfuscation, "precondition: obfuscation enabled")
	require.NotEmpty(t, before.ObfuscationIV, "precondition: obfuscation IV configured")

	newIdentity := testutil.CreateSignedTestRouterInfo(t, map[string]string{}, nil)
	require.NoError(t, transport.SetIdentity(*newIdentity))

	after := transport.config.Load().SSU2Config
	require.NotNil(t, after)

	assert.Equal(t, before.IntroKey, after.IntroKey,
		"the persistent intro key must survive an identity update")
	assert.Equal(t, before.ObfuscationIV, after.ObfuscationIV,
		"the persistent obfuscation IV must survive an identity update")
	assert.True(t, after.EnableChaChaObfuscation)

	// Only the identity-derived material changes.
	assert.NotEqual(t, before.RouterHash, after.RouterHash,
		"the router hash must change with the identity")
}

// TestSetIdentity_KeepsNATManagersAlive is the regression test for the
// degradation the old implementation caused: it called stopNATManagers before a
// rebind that always failed, so one SetIdentity call permanently nil-ed the
// relay, peer-test, hole-punch and key-rotation managers. GetIntroKey reads
// through the key rotation manager, so losing it also silently removed the
// intro key from every published RouterInfo.
func TestSetIdentity_KeepsNATManagersAlive(t *testing.T) {
	transport, _ := newBoundSSU2Transport(t)
	defer transport.Close()

	require.NotNil(t, transport.keyRotationManager, "precondition")
	require.Len(t, transport.GetIntroKey(), 32, "precondition: intro key publishable")

	newIdentity := testutil.CreateSignedTestRouterInfo(t, map[string]string{}, nil)
	require.NoError(t, transport.SetIdentity(*newIdentity))

	assert.NotNil(t, transport.keyRotationManager,
		"an identity update must not tear down the key rotation manager")
	assert.Len(t, transport.GetIntroKey(), 32,
		"the intro key must remain publishable in RouterInfo after an update")

	// The listener is still serving, so the transport is still usable.
	assert.NotNil(t, transport.listener)
}

func TestSetIdentity_RejectsUnusableIdentity(t *testing.T) {
	transport, _ := newBoundSSU2Transport(t)
	defer transport.Close()

	oldListener := transport.listener
	oldHash := transport.config.Load().SSU2Config.RouterHash

	err := transport.SetIdentity(router_info.RouterInfo{})
	assert.Error(t, err, "an identity with no RouterInfo must be rejected")

	assert.Same(t, oldListener, transport.listener,
		"a rejected update must leave the listener alone")
	assert.Equal(t, oldHash, transport.config.Load().SSU2Config.RouterHash,
		"a rejected update must leave the config alone")
	// The failure path must not have destroyed the managers either.
	assert.NotNil(t, transport.keyRotationManager,
		"a rejected update must leave the NAT managers running")
}
