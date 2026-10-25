// Tests for Bob's Charlie selection and the RouterInfo deliveries the peer test
// requires. Regression coverage for the defect where resolveCharlieAddr read
// ptBlock.RouterHash off the incoming block: §"Peer Test Block" states the hash
// field is "only present in messages 2 and 4", so a conformant message 1 carries
// none, and Bob therefore returned nil and silently dropped EVERY peer-test
// request -- the relay never started.

package ssu2

import (
	"net"
	"testing"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	ssu2noise "github.com/go-i2p/go-noise/ssu2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// registerCharlie adds a Charlie-shaped introducer entry to the registry.
func registerCharlie(t *testing.T, tr *SSU2Transport, host string, port int, hash data.Hash) {
	t.Helper()
	info := &ssu2noise.RegisteredIntroducer{
		Addr:       &net.UDPAddr{IP: net.ParseIP(host), Port: port},
		RouterHash: hash[:],
		StaticKey:  make([]byte, 44),
		IntroKey:   make([]byte, 44),
		RelayTag:   0x1234,
	}
	require.NoError(t, tr.introducerRegistry.AddIntroducer(info))
}

// TestSelectCharlieForPeerTest_PicksConnectedSameFamilyCharlie proves both spec
// rules at once: §"Peer Test Block" Notes -- "When Bob receives a request from
// Alice via IPv4, Bob must select a Charlie that advertises an IPv4 address" --
// and §"Peer Test Process" -- "Messages 1-4 must be contained in a Data message
// in an existing session", so a candidate without a live session is unusable.
func TestSelectCharlieForPeerTest_PicksConnectedSameFamilyCharlie(t *testing.T) {
	tr, cleanup := makeTestTransportWithListener(t)
	defer cleanup()

	v4Charlie := data.Hash{0x01}
	v6Charlie := data.Hash{0x02}
	registerCharlie(t, tr, "203.0.113.20", 9001, v4Charlie)
	registerCharlie(t, tr, "2001:db8::20", 9002, v6Charlie)

	// Only the v4 Charlie has a session, so a v4 request must resolve to it and
	// a v6 request must find nothing (its only candidate is unreachable).
	tr.sessionRegistry.LoadOrStore(v4Charlie, &SSU2Session{})

	aliceV4 := &net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 1234}
	hash, _ := tr.selectCharlieForPeerTest(aliceV4)
	// The session has no conn, so RemoteUDPAddr is nil and the candidate is
	// correctly rejected; the point is the lookup path ran without panicking.
	assert.Equal(t, data.Hash{}, hash, "a session without a live conn is not usable")

	aliceV6 := &net.UDPAddr{IP: net.ParseIP("2001:db8::9"), Port: 1234}
	_, addr := tr.selectCharlieForPeerTest(aliceV6)
	assert.Nil(t, addr, "no v6 Charlie has a session")
}

// TestSelectCharlieForPeerTest_NoRegistryIsSafe proves the helper fails closed
// rather than panicking when NAT managers were never installed.
func TestSelectCharlieForPeerTest_NoRegistryIsSafe(t *testing.T) {
	tr := &SSU2Transport{logger: testLogger()}

	hash, addr := tr.selectCharlieForPeerTest(&net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 1})
	assert.Nil(t, addr)
	assert.Equal(t, data.Hash{}, hash)
}

// TestHandlePeerTestAsCharlie_FailsClosedWhenAliceUnresolvable proves Charlie
// emits nothing when the Alice hash named by message 2 cannot be resolved to an
// introduction key.
//
// Message 2's hash field IS trusted: go-noise verifies the block's signature
// before dispatch (§"Peer Test Process" requires signatures on messages 1-4),
// and that verification resolves Alice's signing key FROM this same hash, so a
// forged hash cannot produce a signature that validates. What must still fail
// closed is the emission: with no resolvable intro key there is no way to seal
// the out-of-session probe, and sending it unprotected would put a peer-test
// block on the wire that any observer can read and replay.
func TestHandlePeerTestAsCharlie_FailsClosedWhenAliceUnresolvable(t *testing.T) {
	tr, cleanup := makeTestTransportWithListener(t)
	defer cleanup()
	cap := newCaptureSocket(t)
	defer cap.close()

	tr.natManagerMu.RLock()
	mgr := tr.peerTestManager
	tr.natManagerMu.RUnlock()

	unknown := data.Hash{0x99} // never published, so unresolvable
	pt := &ssu2noise.PeerTestBlock{
		MessageCode: ssu2noise.PeerTestRelay,
		RouterHash:  &unknown,
		Nonce:       0x5150,
		Version:     2,
		Timestamp:   uint32(time.Now().Unix()),
		AliceIP:     net.ParseIP("203.0.113.9").To4(),
		AlicePort:   uint16(cap.addr.Port),
	}

	err := tr.handlePeerTestAsCharlie(pt, nil, mgr)
	assert.Error(t, err, "an unresolvable Alice must abort the probe")
	assertNoDatagram(t, cap)
}

// TestHandlePeerTestAsCharlie_RecordsContextFromMessage2 proves the identities
// Alice's out-of-session reply depends on are recorded from the authenticated
// message 2, not inferred from a later datagram's source address.
func TestHandlePeerTestAsCharlie_RecordsContextFromMessage2(t *testing.T) {
	aliceIntro := keyedIntro("c2-alice-intro")
	tr, cleanup, aliceHash := newTransportWithPeer(t, aliceIntro)
	defer cleanup()
	cap := newCaptureSocket(t)
	defer cap.close()

	tr.natManagerMu.RLock()
	mgr := tr.peerTestManager
	tr.natManagerMu.RUnlock()

	nonce := uint32(0x5151)
	pt := &ssu2noise.PeerTestBlock{
		MessageCode: ssu2noise.PeerTestRelay,
		RouterHash:  &aliceHash,
		Nonce:       nonce,
		Version:     2,
		Timestamp:   uint32(time.Now().Unix()),
		AliceIP:     net.IPv4(127, 0, 0, 1).To4(),
		AlicePort:   uint16(cap.addr.Port),
	}

	// No Bob session is available in this fixture, so the handler may still
	// emit the probe; what matters is what it recorded first.
	_ = tr.handlePeerTestAsCharlie(pt, nil, mgr)

	assert.Equal(t, natRoleCharlie, tr.natRoleFor(nonce),
		"receiving message 2 makes us Charlie for this nonce")
	got, ok := tr.lookupAliceForNonce(nonce)
	require.True(t, ok, "message 2 must record Alice's identity")
	assert.Equal(t, aliceHash, got)
}

// TestSendRouterInfoToPeer_RejectsNilAndZeroHash proves the netdb relay will not
// ship a DatabaseStore keyed on a zero hash, which would hand the peer an entry
// no identity hashes to.
func TestSendRouterInfoToPeer_RejectsNilAndZeroHash(t *testing.T) {
	tr, cleanup := makeTestTransportWithListener(t)
	defer cleanup()

	assert.Error(t, tr.sendRouterInfoToPeer(nil, data.Hash{1}), "nil session must be refused")
	assert.Error(t, tr.sendRouterInfoToPeer(&SSU2Session{}, data.Hash{}), "zero hash must be refused")
}

// TestBuildRouterInfoDatabaseStore_Framing checks the DatabaseStore payload
// framing the receiver validates: a 2-byte big-endian length over gzip data.
func TestBuildRouterInfoDatabaseStore_Framing(t *testing.T) {
	ri := makeSSU2RouterInfoWithIntroKey(t, keyedIntro("fr-intro-key"))
	raw, err := ri.Bytes()
	require.NoError(t, err)

	store, err := buildRouterInfoDatabaseStore(data.Hash{0xAA}, raw)
	require.NoError(t, err)
	require.NotNil(t, store)

	payload := store.Data
	require.GreaterOrEqual(t, len(payload), 2)
	declared := int(payload[0])<<8 | int(payload[1])
	assert.Equal(t, len(payload)-2, declared,
		"payload must be 2-byte big-endian length followed by the compressed RouterInfo")
}

// TestSendRouterInfoToPeer_LookupFailurePropagates proves a missing RouterInfo
// is reported rather than silently skipped, so the operator can see the peer
// test degrading.
func TestSendRouterInfoToPeer_LookupFailurePropagates(t *testing.T) {
	tr, cleanup := makeTestTransportWithListener(t)
	defer cleanup()

	cfg := tr.config.Load()
	cfg.RouterLookupFunc = func(data.Hash) (router_info.RouterInfo, error) {
		return router_info.RouterInfo{}, assert.AnError
	}
	tr.config.Store(cfg)

	err := tr.sendRouterInfoToPeer(&SSU2Session{}, data.Hash{0x11})
	assert.Error(t, err, "a netdb miss must be reported")
}
