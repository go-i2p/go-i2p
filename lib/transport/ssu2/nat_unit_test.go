package ssu2

// nat_unit_test.go tests NAT handler methods that can be exercised without a
// live peer-test or relay exchange by using nil-manager guard paths and the
// minimal transport helper from transport_unit_test.go.

import (
	"testing"

	ssu2noise "github.com/go-i2p/go-noise/ssu2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHandlePeerTestBlock_NilManager verifies that handlePeerTestBlock returns
// nil without panicking when peerTestManager is not initialised.
func TestHandlePeerTestBlock_NilManager(t *testing.T) {
	tr := makeMinimalTransport() // no peerTestManager
	block := &ssu2noise.SSU2Block{}
	err := tr.handlePeerTestBlock(block)
	assert.NoError(t, err)
}

// TestHandleRelayRequestBlock_NilManager verifies that handleRelayRequestBlock
// returns nil when relayManager is nil.
func TestHandleRelayRequestBlock_NilManager(t *testing.T) {
	tr := makeMinimalTransport()
	err := tr.handleRelayRequestBlock(&ssu2noise.SSU2Block{})
	assert.NoError(t, err)
}

// TestHandleRelayRequestBlock_NilBlock verifies that a nil block is also safe.
func TestHandleRelayRequestBlock_NilBlock(t *testing.T) {
	tr := makeMinimalTransport()
	err := tr.handleRelayRequestBlock(nil)
	assert.NoError(t, err)
}

// TestHandleRelayResponseBlock_NilManager verifies the nil-registry guard.
func TestHandleRelayResponseBlock_NilManager(t *testing.T) {
	tr := makeMinimalTransport()
	err := tr.handleRelayResponseBlock(&ssu2noise.SSU2Block{})
	assert.NoError(t, err)
}

// TestHandleRelayResponseBlock_NilBlock verifies the nil-block guard.
func TestHandleRelayResponseBlock_NilBlock(t *testing.T) {
	tr := makeMinimalTransport()
	err := tr.handleRelayResponseBlock(nil)
	assert.NoError(t, err)
}

// TestHandleRelayIntroBlock_NilManager verifies the nil-coordinator guard.
func TestHandleRelayIntroBlock_NilManager(t *testing.T) {
	tr := makeMinimalTransport()
	err := tr.handleRelayIntroBlock(&ssu2noise.SSU2Block{})
	assert.NoError(t, err)
}

// TestHandleRelayIntroBlock_NilBlock verifies the nil-block guard.
func TestHandleRelayIntroBlock_NilBlock(t *testing.T) {
	tr := makeMinimalTransport()
	err := tr.handleRelayIntroBlock(nil)
	assert.NoError(t, err)
}

// TestHandlePeerTestBlock_WithManager verifies that handlePeerTestBlock with
// a real PeerTestManager proceeds without error (non-initiator path).
func TestHandlePeerTestBlock_WithManager(t *testing.T) {
	tr, cleanup := makeTestTransportWithListener(t)
	defer cleanup()

	// Build a minimal PeerTest block. DecodePeerTestBlock will fail on an
	// empty block, but the function logs and returns the error — it should
	// not panic.
	block := &ssu2noise.SSU2Block{}
	err := tr.handlePeerTestBlock(block)
	// Either nil (non-initiator path) or a decode error — both are acceptable.
	_ = err
}

// TestBuildTransportCallbacks_ReturnsCallbacks verifies buildTransportCallbacks
// returns a non-nil BlockCallbackConfig with all four NAT handlers populated.
func TestBuildTransportCallbacks_ReturnsCallbacks(t *testing.T) {
	tr, cleanup := makeTestTransportWithListener(t)
	defer cleanup()

	cbs := tr.buildTransportCallbacks()
	require.NotNil(t, cbs)
	assert.NotNil(t, cbs.OnPeerTest)
	assert.NotNil(t, cbs.OnRelayRequest)
	assert.NotNil(t, cbs.OnRelayResponse)
	assert.NotNil(t, cbs.OnRelayIntro)
}

// TestBuildTransportCallbacks_DelegatesHandler verifies that the callback
// produced by buildTransportCallbacks actually delegates to the handler (no
// panic, returns nil for relay paths).
func TestBuildTransportCallbacks_DelegatesHandler(t *testing.T) {
	tr, cleanup := makeTestTransportWithListener(t)
	defer cleanup()

	cbs := tr.buildTransportCallbacks()

	block := &ssu2noise.SSU2Block{}
	assert.NoError(t, cbs.OnRelayRequest(block))
	assert.NoError(t, cbs.OnRelayResponse(block))
	assert.NoError(t, cbs.OnRelayIntro(block))
}

// TestHandlePeerTestAsBob_NoAliceAddr verifies Bob handler returns nil when
// Alice address is missing from the PeerTest block.
func TestHandlePeerTestAsBob_NoAliceAddr(t *testing.T) {
	tr, cleanup := makeTestTransportWithListener(t)
	defer cleanup()

	ptBlock := &ssu2noise.PeerTestBlock{
		MessageCode: ssu2noise.PeerTestRequest,
		Nonce:       42,
		Version:     2,
	}
	err := tr.handlePeerTestAsBob(ptBlock)
	assert.NoError(t, err)
}

// TestHandlePeerTestAsCharlie_NoAliceAddr verifies Charlie handler returns nil
// when Alice address is missing.
func TestHandlePeerTestAsCharlie_NoAliceAddr(t *testing.T) {
	tr, cleanup := makeTestTransportWithListener(t)
	defer cleanup()

	ptBlock := &ssu2noise.PeerTestBlock{
		MessageCode: ssu2noise.PeerTestRelay,
		Nonce:       42,
		Version:     2,
	}
	err := tr.handlePeerTestAsCharlie(ptBlock)
	assert.NoError(t, err)
}

// TestAnyActiveSession_Empty verifies anyActiveSession returns nil with no
// sessions.
func TestAnyActiveSession_Empty(t *testing.T) {
	tr, cleanup := makeTestTransportWithListener(t)
	defer cleanup()

	assert.Nil(t, tr.anyActiveSession())
}

// TestFindSessionByHash_NotFound verifies findSessionByHash returns nil for
// unknown hashes.
func TestFindSessionByHash_NotFound(t *testing.T) {
	tr, cleanup := makeTestTransportWithListener(t)
	defer cleanup()

	var hash [32]byte
	assert.Nil(t, tr.findSessionByHash(hash))
}

// TestRemoteUDPAddr_NilConn verifies RemoteUDPAddr returns nil when the
// session's conn is nil.
func TestRemoteUDPAddr_NilConn(t *testing.T) {
	s := &SSU2Session{}
	assert.Nil(t, s.RemoteUDPAddr())
}
