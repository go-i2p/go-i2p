// C13 tests: SSU2 out-of-session (intro-key protected) NAT-traversal messages.
//
// Covers both halves of the finding:
//   - EMISSION: peer-test message 5 and the Hole Punch must be genuine type-7 /
//     type-11 long-header messages, sealed under the RECEIVER's introduction key
//     with the nonce-derived connection IDs, and openable by that receiver.
//     Previously both went out as a cleartext 16-byte Data header, which is not
//     a valid SSU2 message of any type.
//   - CORRELATION: an inbound message of either kind must be bound to a
//     transaction we started before anything in it is acted on, because the
//     intro key it is sealed with is published in the netdb and therefore
//     authenticates nobody.

package ssu2

import (
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"

	i2pbase64 "github.com/go-i2p/common/base64"
	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_address"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/testutil"
	ssu2noise "github.com/go-i2p/go-noise/ssu2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeSSU2RouterInfoWithIntroKey builds a signed RouterInfo whose SSU2 address
// advertises introKey in the "i" option, so ExtractSSU2IntroKey resolves it and
// peerIntroKey can find it through RouterLookupFunc.
func makeSSU2RouterInfoWithIntroKey(t testing.TB, introKey []byte) router_info.RouterInfo {
	t.Helper()
	require.Len(t, introKey, 32)

	addrCfg := &testutil.RouterAddressConfig{
		Cost:       3,
		Expiration: time.Now().Add(24 * time.Hour),
		Transport:  "SSU2",
		Options: map[string]string{
			router_address.HOST_OPTION_KEY:                  "203.0.113.7",
			router_address.PORT_OPTION_KEY:                  "12345",
			router_address.INITIALIZATION_VECTOR_OPTION_KEY: i2pbase64.EncodeToString(introKey),
		},
	}
	return *testutil.CreateSignedTestRouterInfo(t, map[string]string{}, addrCfg)
}

// captureSocket is a real UDP socket the senders can address, so an emitted
// datagram can be read back and inspected without a peer implementation.
type captureSocket struct {
	conn *net.UDPConn
	addr *net.UDPAddr
}

func newCaptureSocket(t testing.TB) *captureSocket {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	la := pc.LocalAddr().(*net.UDPAddr)
	return &captureSocket{conn: pc, addr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: la.Port}}
}

func (c *captureSocket) close() { _ = c.conn.Close() }

// read waits for one datagram and returns its bytes.
func (c *captureSocket) read(t testing.TB) []byte {
	t.Helper()
	require.NoError(t, c.conn.SetReadDeadline(time.Now().Add(2*time.Second)))
	buf := make([]byte, 2048)
	n, _, err := c.conn.ReadFrom(buf)
	require.NoError(t, err, "expected a datagram on the capture socket")
	return append([]byte(nil), buf[:n]...)
}

// newTransportWithPeer wires a transport whose RouterLookupFunc resolves
// peerHash to a RouterInfo advertising peerIntroKey.
func newTransportWithPeer(t *testing.T, peerIntroKey []byte) (*SSU2Transport, func(), data.Hash) {
	t.Helper()
	tr, cleanup := makeTestTransportWithListener(t)

	ri := makeSSU2RouterInfoWithIntroKey(t, peerIntroKey)
	hash, err := ri.IdentHash()
	require.NoError(t, err)

	cfg := tr.config.Load()
	cfg.RouterLookupFunc = func(h data.Hash) (router_info.RouterInfo, error) {
		if h == hash {
			return ri, nil
		}
		return router_info.RouterInfo{}, assert.AnError
	}
	tr.config.Store(cfg)
	return tr, cleanup, hash
}

// TestSendPeerTestProbe_SpecShapeAndOpensAtAlice asserts message 5 is a real
// out-of-session Peer Test message: type 7, 32-byte long header, nonce-derived
// connection IDs, and a payload only Alice's intro key can open.
func TestSendPeerTestProbe_SpecShapeAndOpensAtAlice(t *testing.T) {
	aliceIntro := keyedIntro("alice-intro-1")
	tr, cleanup, aliceHash := newTransportWithPeer(t, aliceIntro)
	defer cleanup()
	cap := newCaptureSocket(t)
	defer cap.close()

	nonce := uint32(0xdeadbeef)
	relay := &ssu2noise.PeerTestBlock{
		MessageCode: ssu2noise.PeerTestRelay,
		Nonce:       nonce,
		Version:     2,
		Timestamp:   uint32(time.Now().Unix()),
		AlicePort:   uint16(cap.addr.Port),
		AliceIP:     net.IPv4(127, 0, 0, 1).To4(),
	}

	require.NoError(t, tr.sendPeerTestProbeToAlice(relay, cap.addr, aliceHash))
	sent := cap.read(t)

	// ssu2.rst "Peer Test (Type 7)": "Size: 48 + payload size."
	assert.GreaterOrEqual(t, len(sent), ssu2noise.LongHeaderSize+16,
		"all SSU2 messages carry a 32-byte header plus an AEAD tag")

	packet, blocks, err := ssu2noise.OpenIntroKeyMessage(aliceIntro, sent)
	require.NoError(t, err, "Alice must be able to open the probe under her own intro key")
	require.NotNil(t, packet)
	assert.Equal(t, uint8(ssu2noise.MessageTypePeerTest), packet.MessageType,
		"header type must be 7")

	// Connection IDs derived from the nonce, unswapped for 5/7 (Charlie->Alice).
	// OpenIntroKeyMessage hands back the CLEARTTEXT header (the AEAD's
	// associated data), so the IDs are read straight off it.
	gotDest, gotSrc := connIDsFromHeader(t, packet.Header)
	wantDest, wantSrc := ssu2noise.NonceConnectionIDs(nonce)
	assert.Equal(t, wantDest, gotDest)
	assert.Equal(t, wantSrc, gotSrc)

	pt := requireSinglePeerTestBlock(t, blocks)
	assert.Equal(t, ssu2noise.PeerTestProbe, pt.MessageCode, "payload must carry message code 5")
	assert.Equal(t, nonce, pt.Nonce)
	// "Peer Test Block": the hash field is "only present in messages 2 and 4".
	assert.Nil(t, pt.RouterHash, "an out-of-session probe must not carry a hash field")
	// Alice's endpoint lives in the signed data and must be carried over.
	assert.Equal(t, uint16(cap.addr.Port), pt.AlicePort)
	assert.Equal(t, []byte(net.IPv4(127, 0, 0, 1).To4()), []byte(pt.AliceIP))
	assert.True(t, containsBlockType(blocks, ssu2noise.BlockTypeDateTime),
		"payload must include a DateTime block")
}

// TestSendHolePunch_SpecShapeAndOpensAtAlice asserts the Hole Punch is a type-11
// message carrying DateTime + Address + the same RelayResponse Bob forwards.
func TestSendHolePunch_SpecShapeAndOpensAtAlice(t *testing.T) {
	aliceIntro := keyedIntro("alice-intro-2")
	tr, cleanup, aliceHash := newTransportWithPeer(t, aliceIntro)
	defer cleanup()
	cap := newCaptureSocket(t)
	defer cap.close()

	nonce := uint32(0x0b0b0b0b)
	intro := &ssu2noise.RelayIntroBlock{Nonce: nonce, Version: 2}
	// An accepted RelayResponse (code 0) MUST carry Charlie's signature, and
	// the encoder fails closed without it -- so the fixture signs it the way
	// buildRelayResponse does in production.
	_, charlieKey := testutil.CreateSignedTestRouterInfoAndKey(t, map[string]string{}, nil)
	require.NotNil(t, charlieKey)
	charliePriv := *charlieKey
	bobHash := data.Hash{0xB0, 0xB}
	timestamp := uint32(time.Now().Unix())
	sig, err := ssu2noise.SignRelayResponse(
		charliePriv, bobHash, nonce, timestamp, 2,
		29000, net.ParseIP("198.51.100.4").To4(),
	)
	require.NoError(t, err)
	resp := &ssu2noise.RelayResponseBlock{
		Code:        0,
		Nonce:       nonce,
		Timestamp:   timestamp,
		Version:     2,
		CharliePort: 29000,
		CharlieIP:   net.ParseIP("198.51.100.4").To4(),
		Signature:   sig,
		Token:       []byte{1, 2, 3, 4, 5, 6, 7, 8},
	}

	require.NoError(t, tr.sendHolePunchToAlice(intro, cap.addr, aliceHash, resp))
	sent := cap.read(t)

	packet, blocks, err := ssu2noise.OpenIntroKeyMessage(aliceIntro, sent)
	require.NoError(t, err)
	assert.Equal(t, uint8(ssu2noise.MessageTypeHolePunch), packet.MessageType,
		"header type must be 11")

	gotDest, gotSrc := connIDsFromHeader(t, packet.Header)
	wantDest, wantSrc := ssu2noise.NonceConnectionIDs(nonce)
	assert.Equal(t, wantDest, gotDest)
	assert.Equal(t, wantSrc, gotSrc)

	assert.True(t, containsBlockType(blocks, ssu2noise.BlockTypeDateTime))
	assert.True(t, containsBlockType(blocks, ssu2noise.BlockTypeAddress),
		"Hole Punch payload requires an Address block")

	decoded, err := findRelayResponseBlock(blocks)
	require.NoError(t, err, "Hole Punch must carry the RelayResponse block")
	assert.Equal(t, nonce, decoded.Nonce)
	assert.Equal(t, resp.Token, decoded.Token,
		"the session token Alice must use lives inside the block, not the header")
}

// TestSendPeerTestProbe_FailsClosedWithoutLookup proves no unprotected traffic
// leaves when the receiver's intro key cannot be resolved.
func TestSendPeerTestProbe_FailsClosedWithoutLookup(t *testing.T) {
	tr, cleanup := makeTestTransportWithListener(t)
	defer cleanup()
	cap := newCaptureSocket(t)
	defer cap.close()

	relay := &ssu2noise.PeerTestBlock{
		MessageCode: ssu2noise.PeerTestRelay,
		Nonce:       1234,
		Version:     2,
		Timestamp:   uint32(time.Now().Unix()),
		AliceIP:     net.IPv4(127, 0, 0, 1).To4(),
		AlicePort:   uint16(cap.addr.Port),
	}
	err := tr.sendPeerTestProbeToAlice(relay, cap.addr, data.Hash{1})
	assert.Error(t, err, "no RouterLookupFunc means the intro key is unresolvable")
	assertNoDatagram(t, cap)
}

// TestSendHolePunch_FailsClosedWithoutIntroKey covers the same gate on the
// hole-punch sender.
func TestSendHolePunch_FailsClosedWithoutIntroKey(t *testing.T) {
	tr, cleanup := makeTestTransportWithListener(t)
	defer cleanup()
	cap := newCaptureSocket(t)
	defer cap.close()

	err := tr.sendHolePunchToAlice(
		&ssu2noise.RelayIntroBlock{Nonce: 7, Version: 2},
		cap.addr, data.Hash{2},
		&ssu2noise.RelayResponseBlock{Code: 0, Nonce: 7, CharlieIP: net.ParseIP("198.51.100.4").To4(), CharliePort: 1},
	)
	assert.Error(t, err)
	assertNoDatagram(t, cap)
}

// TestPeerIntroKey_ResolvesFromSSU2Address checks the netdb lookup path.
func TestPeerIntroKey_ResolvesFromSSU2Address(t *testing.T) {
	intro := keyedIntro("xyzzy-intro")
	tr, cleanup, hash := newTransportWithPeer(t, intro)
	defer cleanup()

	got, err := tr.peerIntroKey(hash)
	require.NoError(t, err)
	assert.Equal(t, intro, got)
}

// --- nonce context store ---

func TestNatNonceStore_RemembersAndExpires(t *testing.T) {
	tr, cleanup := makeTestTransportWithListener(t)
	defer cleanup()

	const nonce = uint32(0x1234)
	alice := data.Hash{0xAA}
	charlie := data.Hash{0xBB}
	bob := data.Hash{0xCC}

	tr.setNatRole(nonce, natRoleBob)
	tr.rememberAliceForNonce(nonce, alice)
	tr.rememberCharlieForNonce(nonce, charlie)
	tr.rememberBobForNonce(nonce, bob)

	assert.Equal(t, natRoleBob, tr.natRoleFor(nonce))
	for name, lookup := range map[string]func(uint32) (data.Hash, bool){
		"alice":   tr.lookupAliceForNonce,
		"charlie": tr.lookupCharlieForNonce,
		"bob":     tr.lookupBobForNonce,
	} {
		_, ok := lookup(nonce)
		assert.True(t, ok, "%s context must be recorded", name)
	}

	// First writer wins: a role established by an authenticated message must
	// not be re-assigned by a later, weaker signal.
	tr.setNatRole(nonce, natRoleCharlie)
	assert.Equal(t, natRoleBob, tr.natRoleFor(nonce))

	// Nonce 0 is never a valid test nonce; storing against it must be ignored
	// rather than creating a catch-all entry every unsolicited message hits.
	tr.rememberAliceForNonce(0, alice)
	_, ok := tr.lookupAliceForNonce(0)
	assert.False(t, ok, "nonce 0 must not be usable as a context key")

	tr.natContexts.remove(nonce)
	_, ok = tr.lookupAliceForNonce(nonce)
	assert.False(t, ok)
}

func TestNatNonceStore_LookupReturnsCopy(t *testing.T) {
	tr, cleanup := makeTestTransportWithListener(t)
	defer cleanup()

	tr.rememberAliceForNonce(7, data.Hash{0x11})
	c := tr.natContexts.lookup(7)
	require.NotNil(t, c)
	c.aliceHash = data.Hash{0x99}
	c.aliceKnown = false

	again := tr.natContexts.lookup(7)
	require.NotNil(t, again)
	assert.True(t, again.aliceKnown, "returned context must be a copy, not shared state")
	assert.Equal(t, data.Hash{0x11}, again.aliceHash)
}

func TestNatNonceStore_Expires(t *testing.T) {
	store := &natNonceStore{}
	store.mutate(11, func(c *natTestContext) { c.aliceKnown = true })
	require.NotNil(t, store.lookup(11))

	// Force expiry without waiting out the real TTL.
	store.mu.Lock()
	store.entries[11].expiresAt = time.Now().Add(-time.Second)
	store.mu.Unlock()
	assert.Nil(t, store.lookup(11))
}

// --- inbound correlation ---

// TestHandleOutOfSession_UnsolicitedNonceDropped proves the binding gate: an
// out-of-session message whose nonce we never started must be rejected before
// any of its contents is used.
func TestHandleOutOfSession_UnsolicitedNonceDropped(t *testing.T) {
	tr, cleanup := makeTestTransportWithListener(t)
	defer cleanup()

	nonce := uint32(0xfeedface)
	dest, src := ssu2noise.NonceConnectionIDs(nonce)
	pt := &ssu2noise.PeerTestBlock{
		MessageCode: ssu2noise.PeerTestProbe,
		Nonce:       nonce,
		Version:     2,
		Timestamp:   uint32(time.Now().Unix()),
		AliceIP:     net.ParseIP("203.0.113.9").To4(),
		AlicePort:   12345,
	}
	encoded, err := ssu2noise.EncodePeerTestBlock(pt)
	require.NoError(t, err)

	before := len(tr.natStateCache.observations)

	// Must not panic and must not record anything.
	tr.handleOutOfSessionMessage(ssu2noise.OutOfSessionMessage{
		Type:         ssu2noise.MessageTypePeerTest,
		DestConnID:   dest,
		SourceConnID: src,
		Blocks:       []*ssu2noise.SSU2Block{ssu2noise.NewDateTimeBlock(), encoded},
		From:         &net.UDPAddr{IP: net.ParseIP("198.51.100.9"), Port: 40000},
	})

	assert.Nil(t, tr.peerTestManager.GetTest(nonce),
		"an unsolicited probe must not create or complete a test")
	assert.Len(t, tr.natStateCache.observations, before,
		"an unsolicited probe must not poison the address-observation cache")
}

// TestHandleOutOfSessionPeerTest_HeaderBlockNonceMismatchRejected proves a
// message cannot claim one nonce in its header and another in its payload.
func TestHandleOutOfSessionPeerTest_HeaderBlockNonceMismatchRejected(t *testing.T) {
	tr, cleanup := makeTestTransportWithListener(t)
	defer cleanup()

	headerNonce := uint32(0x1111)
	blockNonce := uint32(0x2222)
	dest, src := ssu2noise.NonceConnectionIDs(headerNonce)
	tr.setNatRole(blockNonce, natRoleAlice) // make the block nonce "known"

	pt := &ssu2noise.PeerTestBlock{
		MessageCode: ssu2noise.PeerTestProbe,
		Nonce:       blockNonce,
		Version:     2,
		Timestamp:   uint32(time.Now().Unix()),
		AliceIP:     net.ParseIP("203.0.113.9").To4(),
		AlicePort:   12345,
	}
	encoded, err := ssu2noise.EncodePeerTestBlock(pt)
	require.NoError(t, err)

	err = tr.handleOutOfSessionPeerTest(ssu2noise.OutOfSessionMessage{
		Type:         ssu2noise.MessageTypePeerTest,
		DestConnID:   dest,
		SourceConnID: src,
		Blocks:       []*ssu2noise.SSU2Block{ssu2noise.NewDateTimeBlock(), encoded},
		From:         &net.UDPAddr{IP: net.ParseIP("198.51.100.9"), Port: 40000},
	})
	require.Error(t, err, "header and block must agree on the nonce")
	assert.Contains(t, err.Error(), "header nonce")
}

// TestHandleOutOfSessionHolePunch_UnknownNonceRejected proves the Hole Punch
// path cannot inject a relay response for a relay we never requested.
func TestHandleOutOfSessionHolePunch_UnknownNonceRejected(t *testing.T) {
	tr, cleanup := makeTestTransportWithListener(t)
	defer cleanup()

	nonce := uint32(0x9999)
	dest, src := ssu2noise.NonceConnectionIDs(nonce)
	// A Bob rejection (code 1-63) carries no signature per §"RelayResponse"
	// field layout, which keeps this fixture about the correlation gate rather
	// than the codec.
	resp := &ssu2noise.RelayResponseBlock{
		Code:  2,
		Nonce: nonce,
	}
	encoded, err := ssu2noise.EncodeRelayResponse(resp)
	require.NoError(t, err)

	err = tr.handleOutOfSessionHolePunch(ssu2noise.OutOfSessionMessage{
		Type:         ssu2noise.MessageTypeHolePunch,
		DestConnID:   dest,
		SourceConnID: src,
		Blocks:       []*ssu2noise.SSU2Block{ssu2noise.NewDateTimeBlock(), encoded},
		From:         &net.UDPAddr{IP: net.ParseIP("198.51.100.9"), Port: 40000},
	})
	require.Error(t, err, "no pending relay request => reject")
	assert.Contains(t, err.Error(), "unsolicited")
}

// TestApplyHolePunchSourceEndpoint covers the spec's symmetric-NAT rule.
func TestApplyHolePunchSourceEndpoint(t *testing.T) {
	reported := &ssu2noise.RelayResponseBlock{
		Code:        0,
		CharliePort: 29000,
		CharlieIP:   net.ParseIP("198.51.100.4").To4(),
	}
	from := &net.UDPAddr{IP: net.ParseIP("198.51.100.4"), Port: 31111}

	got := applyHolePunchSourceEndpoint(reported, from)
	require.NotSame(t, reported, got, "must return an adjusted copy")
	assert.Equal(t, uint16(31111), got.CharliePort, "UDP source port wins over the reported port")
	assert.Equal(t, uint16(29000), reported.CharliePort, "the original block must not be mutated")

	// Same port: nothing to correct.
	same := &ssu2noise.RelayResponseBlock{Code: 0, CharliePort: 31111, CharlieIP: from.IP.To4()}
	assert.Same(t, same, applyHolePunchSourceEndpoint(same, from))

	// A rejection carries no endpoint and must be left alone.
	rej := &ssu2noise.RelayResponseBlock{Code: 2}
	assert.Same(t, rej, applyHolePunchSourceEndpoint(rej, from))
}

// --- verifier wiring (the C13 blocking defect) ---

// TestMergeBlockCallbacks_WiresAllSignatureVerifiers guards the defect that
// made the whole peer-test and relay path non-functional: the transport
// implemented PeerTest / RelayRequest / RelayResponse verifiers, but
// mergeBlockCallbacks copied only the RelayIntro one, so go-noise's fail-closed
// dispatch rejected every signed block with VERIFIER_MISSING before its handler
// ever ran.
func TestMergeBlockCallbacks_WiresAllSignatureVerifiers(t *testing.T) {
	cbs := ssu2noise.DataHandlerCallbacks{}
	cfg := &BlockCallbackConfig{
		VerifyPeerTestSignature:      func(*ssu2noise.PeerTestBlock) error { return nil },
		VerifyRelayRequestSignature:  func(*ssu2noise.RelayRequestBlock) error { return nil },
		VerifyRelayResponseSignature: func(*ssu2noise.RelayResponseBlock) error { return nil },
		VerifyRelayIntroSignature:    func(*ssu2noise.RelayIntroBlock) error { return nil },
	}
	mergeBlockCallbacks(&cbs, cfg)

	assert.NotNil(t, cbs.VerifyPeerTestSignature)
	assert.NotNil(t, cbs.VerifyRelayRequestSignature)
	assert.NotNil(t, cbs.VerifyRelayResponseSignature)
	assert.NotNil(t, cbs.VerifyRelayIntroSignature)
}

// TestBuildTransportCallbacks_ExportsVerifiers checks the transport actually
// supplies them, not just that the merge honours them.
func TestBuildTransportCallbacks_ExportsVerifiers(t *testing.T) {
	tr, cleanup := makeTestTransportWithListener(t)
	defer cleanup()

	cfg := tr.buildTransportCallbacks(nil)
	require.NotNil(t, cfg)
	assert.NotNil(t, cfg.VerifyPeerTestSignature)
	assert.NotNil(t, cfg.VerifyRelayRequestSignature)
	assert.NotNil(t, cfg.VerifyRelayResponseSignature)
	assert.NotNil(t, cfg.VerifyRelayIntroSignature)
}

// TestVerifyPeerTestSignature_Msg1SignedByAliceVerifies is an end-to-end oracle
// for the role-aware verifier: a message 1 Alice genuinely signs must verify.
// Before the fix the verifier used senderHash for every code and the wrong
// bhash, so a correct signature could never validate.
func TestVerifyPeerTestSignature_Msg1SignedByAliceVerifies(t *testing.T) {
	aliceRIPtr, aliceKey := testutil.CreateSignedTestRouterInfoAndKey(t, map[string]string{}, nil)
	aliceRI := *aliceRIPtr
	aliceHash, err := aliceRI.IdentHash()
	require.NoError(t, err)

	tr, cleanup := makeTestTransportWithListener(t)
	defer cleanup()
	cfg := tr.config.Load()
	cfg.RouterLookupFunc = func(h data.Hash) (router_info.RouterInfo, error) {
		if h == aliceHash {
			return aliceRI, nil
		}
		return router_info.RouterInfo{}, assert.AnError
	}
	tr.config.Store(cfg)

	nonce := uint32(0xabcd)
	timestamp := uint32(time.Now().Unix())
	aliceIP := net.ParseIP("203.0.113.9").To4()

	sig, err := ssu2noise.SignPeerTest(
		*aliceKey,
		tr.getOurIdentityHash(), nil, 2, nonce, timestamp, 12345, aliceIP,
	)
	require.NoError(t, err)

	block := &ssu2noise.PeerTestBlock{
		MessageCode: ssu2noise.PeerTestRequest,
		Nonce:       nonce,
		Version:     2,
		Timestamp:   timestamp,
		AlicePort:   12345,
		AliceIP:     aliceIP,
		Signature:   sig,
	}
	require.NoError(t, tr.verifyPeerTestSignature(block, aliceHash),
		"a genuine Alice message 1 must verify")

	// Tampering must be caught.
	block.Timestamp++
	assert.Error(t, tr.verifyPeerTestSignature(block, aliceHash),
		"a modified timestamp must break the signature")
}

// TestVerifyPeerTestSignature_Msg3NeedsAliceContext proves the fail-closed path
// for the message whose signed data includes a hash that is NOT on the wire.
func TestVerifyPeerTestSignature_Msg3NeedsAliceContext(t *testing.T) {
	charlieRIPtr, charlieKey := testutil.CreateSignedTestRouterInfoAndKey(t, map[string]string{}, nil)
	charlieRI := *charlieRIPtr
	charlieHash, err := charlieRI.IdentHash()
	require.NoError(t, err)

	tr, cleanup := makeTestTransportWithListener(t)
	defer cleanup()
	cfg := tr.config.Load()
	cfg.RouterLookupFunc = func(h data.Hash) (router_info.RouterInfo, error) {
		if h == charlieHash {
			return charlieRI, nil
		}
		return router_info.RouterInfo{}, assert.AnError
	}
	tr.config.Store(cfg)

	nonce := uint32(0xbeef)
	timestamp := uint32(time.Now().Unix())
	aliceIP := net.ParseIP("203.0.113.9").To4()
	aliceHash := data.Hash{0xA1, 0xce}

	// Charlie signs the agreement with bhash = Bob (us) and ahash = Alice.
	sig, err := ssu2noise.SignPeerTest(
		*charlieKey,
		tr.getOurIdentityHash(), &aliceHash, 2, nonce, timestamp, 12345, aliceIP,
	)
	require.NoError(t, err)

	block := &ssu2noise.PeerTestBlock{
		MessageCode: ssu2noise.PeerTestResponse,
		Nonce:       nonce,
		Version:     2,
		Timestamp:   timestamp,
		AlicePort:   12345,
		AliceIP:     aliceIP,
		Signature:   sig,
	}

	// No context yet: the Alice hash cannot be reconstructed, so reject.
	assert.Error(t, tr.verifyPeerTestSignature(block, charlieHash),
		"message 3 must fail closed without an authenticated Alice context")

	// Once message 1 supplied it, the same block verifies.
	tr.rememberAliceForNonce(nonce, aliceHash)
	require.NoError(t, tr.verifyPeerTestSignature(block, charlieHash))
}

// --- helpers ---

// connIDsFromHeader reads the destination and source connection IDs out of a
// 32-byte cleartext long header (bytes 0-7 and 16-23).
func connIDsFromHeader(t testing.TB, header []byte) (dest, src uint64) {
	t.Helper()
	require.GreaterOrEqual(t, len(header), ssu2noise.LongHeaderSize)
	return binary.BigEndian.Uint64(header[0:8]), binary.BigEndian.Uint64(header[16:24])
}

func keyedIntro(label string) []byte {
	b := make([]byte, 32)
	copy(b, label)
	for i := len(label); i < 32; i++ {
		b[i] = byte(i)
	}
	return b
}

func containsBlockType(blocks []*ssu2noise.SSU2Block, typ uint8) bool {
	for _, b := range blocks {
		if b != nil && b.Type == typ {
			return true
		}
	}
	return false
}

func requireSinglePeerTestBlock(t *testing.T, blocks []*ssu2noise.SSU2Block) *ssu2noise.PeerTestBlock {
	t.Helper()
	pt, err := findPeerTestBlock(blocks)
	require.NoError(t, err)
	return pt
}

// assertNoDatagram confirms the capture socket received nothing.
func assertNoDatagram(t *testing.T, cap *captureSocket) {
	t.Helper()
	require.NoError(t, cap.conn.SetReadDeadline(time.Now().Add(150*time.Millisecond)))
	buf := make([]byte, 2048)
	_, _, err := cap.conn.ReadFrom(buf)
	if err == nil {
		t.Fatal("expected no datagram to be written")
	}
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("expected a read timeout, got %v", err)
	}
}

// --- W7: mandatory DateTime skew validation (§"Replay Prevention") ---

// dateTimeBlockAt builds a DateTime block carrying the given unix seconds.
func dateTimeBlockAt(unixSeconds uint32) *ssu2noise.SSU2Block {
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, unixSeconds)
	return ssu2noise.NewSSU2Block(ssu2noise.BlockTypeDateTime, data)
}

// TestHandleOutOfSessionPeerTest_StaleDateTimeRejected proves the replay gate:
// ssu2.rst line 4036-4039 requires out-of-session Peer Test messages to carry a
// DateTime block and requires both Alice and Bob to validate it against a
// +/- 2 minute skew. A replayed message carries the ORIGINAL nonce, so the
// nonce-correlation gate alone cannot stop it.
func TestHandleOutOfSessionPeerTest_StaleDateTimeRejected(t *testing.T) {
	tr, cleanup := makeTestTransportWithListener(t)
	defer cleanup()

	nonce := uint32(0xabcd)
	dest, src := ssu2noise.NonceConnectionIDs(nonce)
	tr.setNatRole(nonce, natRoleAlice)

	pt := &ssu2noise.PeerTestBlock{
		MessageCode: ssu2noise.PeerTestProbe,
		Nonce:       nonce,
		Version:     2,
		Timestamp:   uint32(time.Now().Add(-10 * time.Minute).Unix()),
		AliceIP:     net.ParseIP("203.0.113.9").To4(),
		AlicePort:   12345,
	}
	encoded, err := ssu2noise.EncodePeerTestBlock(pt)
	require.NoError(t, err)

	before := len(tr.natStateCache.observations)
	err = tr.handleOutOfSessionPeerTest(ssu2noise.OutOfSessionMessage{
		Type:         ssu2noise.MessageTypePeerTest,
		DestConnID:   dest,
		SourceConnID: src,
		Blocks:       []*ssu2noise.SSU2Block{dateTimeBlockAt(pt.Timestamp), encoded},
		From:         &net.UDPAddr{IP: net.ParseIP("198.51.100.9"), Port: 40000},
	})
	require.Error(t, err, "a DateTime block 10 minutes stale must be rejected")
	assert.Contains(t, err.Error(), "skew")
	assert.Nil(t, tr.peerTestManager.GetTest(nonce),
		"a replayed probe must not create or complete a test")
	assert.Len(t, tr.natStateCache.observations, before,
		"a replayed probe must not poison the address-observation cache")
}

// TestHandleOutOfSessionPeerTest_MissingDateTimeRejected proves the "must
// contain DateTime blocks" half of the same spec sentence.
func TestHandleOutOfSessionPeerTest_MissingDateTimeRejected(t *testing.T) {
	tr, cleanup := makeTestTransportWithListener(t)
	defer cleanup()

	nonce := uint32(0xabce)
	dest, src := ssu2noise.NonceConnectionIDs(nonce)
	tr.setNatRole(nonce, natRoleAlice)

	pt := &ssu2noise.PeerTestBlock{
		MessageCode: ssu2noise.PeerTestProbe,
		Nonce:       nonce,
		Version:     2,
		Timestamp:   uint32(time.Now().Unix()),
		AliceIP:     net.ParseIP("203.0.113.9").To4(),
		AlicePort:   12345,
	}
	encoded, err := ssu2noise.EncodePeerTestBlock(pt)
	require.NoError(t, err)

	err = tr.handleOutOfSessionPeerTest(ssu2noise.OutOfSessionMessage{
		Type:         ssu2noise.MessageTypePeerTest,
		DestConnID:   dest,
		SourceConnID: src,
		Blocks:       []*ssu2noise.SSU2Block{encoded},
		From:         &net.UDPAddr{IP: net.ParseIP("198.51.100.9"), Port: 40000},
	})
	require.Error(t, err, "a Peer Test message without a DateTime block must be rejected")
	assert.Contains(t, err.Error(), "missing required DateTime block")
}

// TestHandleOutOfSessionPeerTest_FreshDateTimeAccepted is the positive control:
// a current timestamp passes the new gate and reaches the correlation logic.
func TestHandleOutOfSessionPeerTest_FreshDateTimeAccepted(t *testing.T) {
	tr, cleanup := makeTestTransportWithListener(t)
	defer cleanup()

	nonce := uint32(0xabcdf)
	dest, src := ssu2noise.NonceConnectionIDs(nonce)
	tr.setNatRole(nonce, natRoleAlice)

	now := uint32(time.Now().Unix())
	pt := &ssu2noise.PeerTestBlock{
		MessageCode: ssu2noise.PeerTestProbe,
		Nonce:       nonce,
		Version:     2,
		Timestamp:   now,
		AliceIP:     net.ParseIP("203.0.113.9").To4(),
		AlicePort:   12345,
	}
	encoded, err := ssu2noise.EncodePeerTestBlock(pt)
	require.NoError(t, err)

	err = tr.handleOutOfSessionPeerTest(ssu2noise.OutOfSessionMessage{
		Type:         ssu2noise.MessageTypePeerTest,
		DestConnID:   dest,
		SourceConnID: src,
		Blocks:       []*ssu2noise.SSU2Block{dateTimeBlockAt(now), encoded},
		From:         &net.UDPAddr{IP: net.ParseIP("198.51.100.9"), Port: 40000},
	})
	require.NoError(t, err, "a fresh, correlated probe must pass validation")
}

// TestHandleOutOfSessionHolePunch_StaleDateTimeRejected proves the same gate on
// the Hole Punch path. The pending relay request is registered so the ONLY
// reason for rejection is the stale DateTime, not the correlation gate.
func TestHandleOutOfSessionHolePunch_StaleDateTimeRejected(t *testing.T) {
	tr, cleanup := makeTestTransportWithListener(t)
	defer cleanup()

	nonce := uint32(0xbeef)
	dest, src := ssu2noise.NonceConnectionIDs(nonce)
	pending := &pendingRelayResponse{ch: make(chan *ssu2noise.RelayResponseBlock, 1)}
	tr.pendingRelayResponses.Store(nonce, pending)

	stale := uint32(time.Now().Add(-10 * time.Minute).Unix())
	// A Charlie-rejection (code 64-127 is Charlie; 1-63 is Bob) carries no
	// endpoint or signature, which keeps this fixture about the DateTime gate.
	resp := &ssu2noise.RelayResponseBlock{
		Code:  2,
		Nonce: nonce,
	}
	encoded, err := ssu2noise.EncodeRelayResponse(resp)
	require.NoError(t, err)

	err = tr.handleOutOfSessionHolePunch(ssu2noise.OutOfSessionMessage{
		Type:         ssu2noise.MessageTypeHolePunch,
		DestConnID:   dest,
		SourceConnID: src,
		Blocks:       []*ssu2noise.SSU2Block{dateTimeBlockAt(stale), encoded},
		From:         &net.UDPAddr{IP: net.ParseIP("198.51.100.9"), Port: 40000},
	})
	require.Error(t, err, "a Hole Punch 10 minutes stale must be rejected")
	assert.Contains(t, err.Error(), "skew")
	select {
	case got := <-pending.ch:
		t.Fatalf("a replayed hole punch must not deliver a relay response, got %v", got)
	default:
	}
}
