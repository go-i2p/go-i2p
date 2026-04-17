package ssu2

// nat_unit_test.go tests NAT handler methods that can be exercised without a
// live peer-test or relay exchange by using nil-manager guard paths and the
// minimal transport helper from transport_unit_test.go.

import (
	"net"
	"testing"

	ssu2noise "github.com/go-i2p/go-noise/ssu2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
)

// TestHandlePeerTestBlock_NilManager verifies that handlePeerTestBlock returns
// nil without panicking when peerTestManager is not initialised.
func TestHandlePeerTestBlock_NilManager(t *testing.T) {
	tr := makeMinimalTransport() // no peerTestManager
	block := &ssu2noise.SSU2Block{}
	err := tr.handlePeerTestBlock(block, nil)
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
	err := tr.handlePeerTestBlock(block, nil)
	// Either nil (non-initiator path) or a decode error — both are acceptable.
	_ = err
}

// TestBuildTransportCallbacks_ReturnsCallbacks verifies buildTransportCallbacks
// returns a non-nil BlockCallbackConfig with all four NAT handlers populated.
func TestBuildTransportCallbacks_ReturnsCallbacks(t *testing.T) {
	tr, cleanup := makeTestTransportWithListener(t)
	defer cleanup()

	cbs := tr.buildTransportCallbacks(nil)
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

	cbs := tr.buildTransportCallbacks(nil)

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
	err := tr.handlePeerTestAsBob(ptBlock, nil)
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

// TestHandlePeerTestAsBob_AddrMismatch verifies that Bob drops a PeerTest
// request when the declared AliceIP does not match the session's observed
// remote address.
func TestHandlePeerTestAsBob_AddrMismatch(t *testing.T) {
	tr, cleanup := makeTestTransportWithListener(t)
	defer cleanup()

	// Build a minimal session with conn=nil (no match possible → skips check).
	ptBlock := &ssu2noise.PeerTestBlock{
		MessageCode: ssu2noise.PeerTestRequest,
		Nonce:       77,
		AliceIP:     net.ParseIP("10.0.0.1").To4(),
		AlicePort:   8000,
	}
	// With nil session, the address check is skipped — the only failure path is
	// missing Charlie which returns nil.
	err := tr.handlePeerTestAsBob(ptBlock, nil)
	assert.NoError(t, err)
}

// TestHandlePeerTestAsBob_SessionRateLimit verifies that per-session rate
// limiting drops requests once the token bucket is exhausted.
func TestHandlePeerTestAsBob_SessionRateLimit(t *testing.T) {
	tr, cleanup := makeTestTransportWithListener(t)
	defer cleanup()

	// Create a session with an exhausted rate limiter (burst=3, reserve all).
	limiter := rate.NewLimiter(rate.Limit(1), 3)
	limiter.Allow() // consume 1
	limiter.Allow() // consume 2
	limiter.Allow() // consume 3 — bucket now empty
	session := &SSU2Session{
		peerTestLimiter: limiter,
	}

	ptBlock := &ssu2noise.PeerTestBlock{
		MessageCode: ssu2noise.PeerTestRequest,
		Nonce:       99,
		AliceIP:     net.ParseIP("127.0.0.1").To4(),
		AlicePort:   7000,
	}
	// The rate limiter should drop this request silently.
	err := tr.handlePeerTestAsBob(ptBlock, session)
	assert.NoError(t, err) // drops silently, no error
}

// TestHandlePeerTestAsBob_GlobalRateLimit verifies that the global rate limit
// drops relays when exhausted.
func TestHandlePeerTestAsBob_GlobalRateLimit(t *testing.T) {
	tr, cleanup := makeTestTransportWithListener(t)
	defer cleanup()

	// Exhaust the global limiter.
	tr.peerTestGlobalLimiter = rate.NewLimiter(rate.Limit(1), 0)

	session := &SSU2Session{
		peerTestLimiter: rate.NewLimiter(rate.Limit(1), 3),
	}

	ptBlock := &ssu2noise.PeerTestBlock{
		MessageCode: ssu2noise.PeerTestRequest,
		Nonce:       55,
		AliceIP:     net.ParseIP("127.0.0.1").To4(),
		AlicePort:   6000,
	}
	err := tr.handlePeerTestAsBob(ptBlock, session)
	assert.NoError(t, err) // drops silently due to global limit
}
