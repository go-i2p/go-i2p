// Tests for SetIdentity on a REAL bound transport.
//
// These are the regression tests for the bug the previous SetIdentity
// implementations had: they tried to acquire a second socket on the same port,
// which can never succeed because the old listener must stay open for the swap
// to be atomic. Every existing test used mock or nil listeners and discarded
// the error (`_ = err`), so the method was unconditionally broken on any bound
// transport and no test noticed.

package ntcp2

import (
	"testing"

	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetIdentity_BoundTransportUpdatesInPlace(t *testing.T) {
	transport := createTransportPB2(t)
	defer transport.cancel()

	oldListener := transport.listener
	oldAddr := transport.Addr()
	require.NotNil(t, oldListener, "transport must have a bound listener")
	require.NotNil(t, oldAddr)

	newIdentity := testutil.CreateSignedTestRouterInfo(t, map[string]string{}, nil)
	require.NotNil(t, newIdentity)

	// The keystone assertion: this used to fail with
	// "bind: address already in use", even on a host with working NAT.
	require.NoError(t, transport.SetIdentity(*newIdentity),
		"SetIdentity on a bound transport must succeed by updating in place")

	// Same socket: the identity update must not rebind.
	assert.Same(t, oldListener, transport.listener, "the listener must not be replaced")
	assert.Equal(t, oldAddr.String(), transport.Addr().String(),
		"the listening port must be preserved")

	// New identity is live on the transport.
	got, err := transport.identity.IdentHash()
	require.NoError(t, err)
	want, err := newIdentity.IdentHash()
	require.NoError(t, err)
	assert.Equal(t, want, got, "transport identity must be the new RouterInfo")

	// And published to the listener, so new handshakes use it.
	updated := transport.config.Load().Config
	require.NotNil(t, updated)
	assert.Equal(t, want, updated.BobRouterHash,
		"the listener config must carry the new router hash")
}

// TestSetIdentity_PreservesRuntimeConfig pins the property that makes an
// in-place update safe: the responder config keeps its keys and obfuscation IV,
// which are loaded from persistent storage rather than derived from the
// identity. Losing them would break outbound and inbound handshakes.
func TestSetIdentity_PreservesRuntimeConfig(t *testing.T) {
	transport := createTransportPB2(t)
	defer transport.cancel()

	before := transport.config.Load().Config
	require.Len(t, before.StaticKey, 32, "precondition: static key configured")
	require.Len(t, before.ObfuscationIV, obfuscationIVSize, "precondition: obfuscation IV configured")

	newIdentity := testutil.CreateSignedTestRouterInfo(t, map[string]string{}, nil)
	require.NoError(t, transport.SetIdentity(*newIdentity))

	after := transport.config.Load().Config
	require.NotNil(t, after)

	// The static key and IV are persistent per working directory, so they must
	// survive an identity change untouched.
	assert.Equal(t, before.StaticKey, after.StaticKey,
		"the persistent static key must survive an identity update")
	assert.Equal(t, before.ObfuscationIV, after.ObfuscationIV,
		"the persistent obfuscation IV must survive an identity update")

	// Only the identity-derived field changes.
	assert.NotEqual(t, before.BobRouterHash, after.BobRouterHash,
		"the router hash must change with the identity")
}

// TestSetIdentity_KeepsListenerAcceptable verifies the transport is still
// usable after an update: the accept loop must not have lost its listener.
func TestSetIdentity_KeepsListenerAcceptable(t *testing.T) {
	transport := createTransportPB2(t)
	defer transport.cancel()

	newIdentity := testutil.CreateSignedTestRouterInfo(t, map[string]string{}, nil)
	require.NoError(t, transport.SetIdentity(*newIdentity))

	assert.NotNil(t, transport.listener, "listener must remain installed after the update")

	// A second update must also succeed (idempotence, not a one-shot path).
	second := testutil.CreateSignedTestRouterInfo(t, map[string]string{}, nil)
	require.NoError(t, transport.SetIdentity(*second),
		"SetIdentity must be repeatable")
	assert.NotNil(t, transport.listener)
}

// TestSetIdentity_RejectsUnusableIdentity documents behaviour for an empty
// RouterInfo: the identity hash cannot be derived, so nothing is changed.
func TestSetIdentity_RejectsUnusableIdentity(t *testing.T) {
	transport := createTransportPB2(t)
	defer transport.cancel()

	oldListener := transport.listener
	oldHash := transport.config.Load().Config.BobRouterHash

	err := transport.SetIdentity(router_info.RouterInfo{})
	assert.Error(t, err, "an identity with no RouterInfo must be rejected")

	assert.Same(t, oldListener, transport.listener,
		"a rejected update must leave the listener alone")
	assert.Equal(t, oldHash, transport.config.Load().Config.BobRouterHash,
		"a rejected update must leave the config alone")
}

// TestSetIdentity_MockListenerIsSkippedNotFatal covers the fallback in
// applyListenerIdentity: a listener that does not implement the identity-update
// capability must not make SetIdentity fail. The transport-level identity and
// config are still published, so the accept loop keeps working.
func TestSetIdentity_MockListenerIsSkippedNotFatal(t *testing.T) {
	transport := createTransportPB2(t)
	defer transport.cancel()

	newIdentity := testutil.CreateSignedTestRouterInfo(t, map[string]string{}, nil)
	require.NotNil(t, newIdentity)

	// Swap the real listener for a mock that lacks UpdateIdentity.
	transport.listener = newMockListener(newAcceptMockConn("10.0.0.9:9009"))

	require.NoError(t, transport.SetIdentity(*newIdentity),
		"a listener without identity support must be skipped, not fatal")

	want, err := newIdentity.IdentHash()
	require.NoError(t, err)
	assert.Equal(t, want, transport.config.Load().Config.BobRouterHash,
		"the transport config must still be updated")
	assert.NotNil(t, transport.listener, "the listener must remain installed")
}
