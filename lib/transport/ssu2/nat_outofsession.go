package ssu2

import (
	cryptorand "crypto/rand"
	"net"
	"time"

	"github.com/go-i2p/go-i2p/lib/transport"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/util/logutil"
	ssu2noise "github.com/go-i2p/go-noise/ssu2"
	"github.com/samber/oops"
)

// Out-of-session NAT-traversal messages (SSU2 spec: ssu2.rst).
//
// ssu2.rst §"Peer Test Process" and §"Relay Process" put three emissions
// outside any session:
//
//	Peer Test message 5   Charlie -> Alice   type 7   keys = Alice's intro key
//	Peer Test message 6   Alice   -> Charlie type 7   keys = Charlie's intro key
//	Peer Test message 7   Charlie -> Alice   type 7   keys = Alice's intro key
//	Hole Punch            Charlie -> Alice   type 11  keys = Alice's intro key
//
// Each is a 32-byte long header whose header AND payload keys are the
// RECEIVER's introduction key, with the payload ChaCha20-Poly1305-sealed over
// the cleartext header as associated data, and connection IDs derived from the
// 4-byte test/relay nonce:
//
//	dest = ((nonce << 32) | nonce)
//	src  = ^dest
//
// Messages 1-4 of the peer test and the RelayRequest / RelayIntro /
// RelayResponse blocks stay in-session as Data-message blocks (that path already
// uses WriteBlocks). Only the emissions below are out-of-session.
//
// Previously these were sent through (*SSU2Conn).SendToAddress as a cleartext
// 16-byte Data header, which is not a valid SSU2 message of any type: all SSU2
// messages are at least 40 bytes with an AEAD-sealed payload, and a type-6
// header would direct the receiver to decrypt with session keys it does not
// share with the sender. They are now built by the shared intro-key message
// builder in go-noise.

// peerIntroKey resolves a peer's 32-byte SSU2 introduction key from its router
// hash via the configured RouterLookupFunc.
//
// The intro key is published in the peer's RouterInfo SSU2 address "i"
// parameter, which is exactly what makes these messages addressable without a
// session. Fails if no lookup is configured or the peer publishes no SSU2
// address with an intro key; callers must then drop the emission rather than
// send anything unprotected.
func (t *SSU2Transport) peerIntroKey(hash data.Hash) ([]byte, error) {
	cfg := t.config.Load()
	if cfg.RouterLookupFunc == nil {
		return nil, oops.Errorf("RouterLookupFunc not configured: cannot resolve intro key for %x", hash[:4])
	}
	ri, err := cfg.RouterLookupFunc(hash)
	if err != nil {
		return nil, oops.Wrapf(err, "netdb lookup failed for %x", hash[:4])
	}
	introKey, err := ExtractSSU2IntroKey(ri)
	if err != nil {
		return nil, oops.Wrapf(err, "no SSU2 intro key for %x", hash[:4])
	}
	return introKey, nil
}

// ourListener returns the active listener, or nil when the transport has no
// socket to send on (not started, or mid SetIdentity swap).
func (t *SSU2Transport) outOfSessionListener() *ssu2noise.SSU2Listener {
	t.identityMu.RLock()
	defer t.identityMu.RUnlock()
	return t.listener
}

// sendPeerTestProbeToAlice sends peer-test message 5 (PeerTestProbe) directly to
// Alice as an out-of-session Peer Test message (type 7) sealed under Alice's
// introduction key.
//
// Payload per ssu2.rst §"Peer Test (Type 7)" for messages 5-7:
// DateTime block, Address block (required for 6 and 7 only), Peer Test block,
// optional Padding. Signature is optional here and omitted, matching i2pd's
// out-of-session probe.
func (t *SSU2Transport) sendPeerTestProbeToAlice(ptBlock *ssu2noise.PeerTestBlock, aliceAddr *net.UDPAddr, aliceHash data.Hash) error {
	listener := t.outOfSessionListener()
	if listener == nil {
		return oops.Errorf("no listener: cannot send PeerTest probe")
	}
	introKey, err := t.peerIntroKey(aliceHash)
	if err != nil {
		return oops.Wrapf(err, "PeerTest probe to Alice")
	}

	// The Peer Test block always carries the signed data, and §"Peer Test Block"
	// puts Alice's port and IP inside it (asz/AlicePort/AliceIP). Regenerating
	// the block with a fresh timestamp is allowed by §"Peer Test Process", but
	// the endpoint fields must be carried over: EncodePeerTestBlock rejects a
	// block with no Alice IP, and Alice needs them to confirm the probe
	// describes her own test.
	probeBlock := &ssu2noise.PeerTestBlock{
		MessageCode: ssu2noise.PeerTestProbe,
		Code:        ptBlock.Code,
		Nonce:       ptBlock.Nonce,
		Version:     ptBlock.Version,
		Timestamp:   transport.RoundUnixSeconds(time.Now()),
		AlicePort:   ptBlock.AlicePort,
		AliceIP:     append([]byte(nil), ptBlock.AliceIP...),
	}
	encoded, err := ssu2noise.EncodePeerTestBlock(probeBlock)
	if err != nil {
		return oops.Wrapf(err, "PeerTest probe: encode block")
	}

	dest, src := ssu2noise.NonceConnectionIDs(ptBlock.Nonce)
	spec := &ssu2noise.IntroKeyMessageSpec{
		MessageType:  ssu2noise.MessageTypePeerTest,
		DestConnID:   dest,
		SourceConnID: src,
		Blocks: []*ssu2noise.SSU2Block{
			ssu2noise.NewDateTimeBlock(),
			encoded,
		},
	}
	if err := listener.SendIntroKeyMessage(introKey, spec, aliceAddr); err != nil {
		return oops.Wrapf(err, "PeerTest probe: send to Alice")
	}
	t.logger.WithFields(map[string]interface{}{
		"nonce":       ptBlock.Nonce,
		"alice_addr":  aliceAddr.String(),
		"alice_hash":  logutil.HashPrefixPlain(aliceHash),
		"dest_connid": dest,
	}).Debug("PeerTest: sent message 5 probe to Alice (out-of-session, intro-key sealed)")
	return nil
}

// sendHolePunchToAlice sends the Hole Punch message (type 11) directly to Alice
// as an out-of-session message sealed under Alice's introduction key.
//
// Payload per ssu2.rst §"Hole Punch (Type 11)": DateTime block, Address block,
// Relay Response block, optional Padding. The header token is random and ignored
// by Alice ("Alice should ignore the token in the header. The token to be used
// in the Session Request is in the Relay Response block.").
//
// resp is the already-built (and signed) RelayResponse the transport also
// forwards to Bob; carrying the identical block here is what lets Alice connect
// to Charlie with the right token, and what the coordinator verifies when the
// message arrives.
func (t *SSU2Transport) sendHolePunchToAlice(intro *ssu2noise.RelayIntroBlock, aliceAddr *net.UDPAddr, aliceHash data.Hash, resp *ssu2noise.RelayResponseBlock) error {
	listener := t.outOfSessionListener()
	if listener == nil {
		return oops.Errorf("no listener: cannot send HolePunch")
	}
	introKey, err := t.peerIntroKey(aliceHash)
	if err != nil {
		return oops.Wrapf(err, "hole-punch: resolve Alice intro key")
	}

	blocks := []*ssu2noise.SSU2Block{
		ssu2noise.NewDateTimeBlock(),
		ssu2noise.NewAddressBlockForAddr(aliceAddr),
	}
	if resp != nil {
		encoded, err := ssu2noise.EncodeRelayResponse(resp)
		if err != nil {
			return oops.Wrapf(err, "hole-punch: encode RelayResponse for HolePunch")
		}
		blocks = append(blocks, encoded)
	}

	dest, src := ssu2noise.NonceConnectionIDs(intro.Nonce)
	token := make([]byte, ssu2noise.TokenSize)
	if _, err := cryptorand.Read(token); err != nil {
		return oops.Wrapf(err, "hole-punch: generate header token")
	}

	spec := &ssu2noise.IntroKeyMessageSpec{
		MessageType:  ssu2noise.MessageTypeHolePunch,
		DestConnID:   dest,
		SourceConnID: src,
		Token:        token,
		Blocks:       blocks,
	}
	if err := listener.SendIntroKeyMessage(introKey, spec, aliceAddr); err != nil {
		return oops.Wrapf(err, "hole-punch: send HolePunch to Alice")
	}
	t.logger.WithFields(map[string]interface{}{
		"nonce":      intro.Nonce,
		"alice_addr": aliceAddr.String(),
	}).Debug("hole-punch: sent HolePunch message to Alice (out-of-session, intro-key sealed)")
	return nil
}
