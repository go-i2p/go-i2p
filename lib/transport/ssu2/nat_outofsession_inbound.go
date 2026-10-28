package ssu2

import (
	"encoding/binary"
	"net"
	"time"

	"github.com/go-i2p/go-i2p/lib/transport"

	i2ped25519 "github.com/go-i2p/crypto/ed25519"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/util/logutil"
	ssu2noise "github.com/go-i2p/go-noise/ssu2"
	"github.com/samber/oops"
)

// Inbound handling for intro-key protected out-of-session messages.
//
// The listener de-obfuscates and AEAD-opens these and hands them here (see
// go-noise ssu2/server/outofsession_inbound.go). Two families arrive:
//
//	Peer Test message (type 7)  codes 5 and 7 to us as Alice, code 6 to us as Charlie
//	Hole Punch    (type 11)     Charlie -> us as Alice
//
// THE SECURITY RULE that shapes all of this: the introduction key these
// messages are sealed with is PUBLISHED IN THE NETDB. ssu2.rst
// §"Introduction Key" is explicit -- "Any party knowing Bob's intro key, which
// is published in the network database, can send him an encrypted message." A
// successful AEAD open therefore proves only that the sender read our
// RouterInfo. It authenticates nobody and binds to nothing.
//
// Consequently every path below must, before acting on any field of a message:
//
//  1. Correlate the message with a transaction WE started, via the nonce
//     encoded in the header connection IDs (§"Peer Test (Type 7)": "The two
//     connection IDs are derived from the test nonce"). An uncorrelated message
//     is unsolicited and dropped.
//  2. Attribute its signature to a router whose identity we learned from the
//     AUTHENTICATED in-session half of the same transaction (t.natContexts),
//     and verify it. Where a signature is absent and optional, the message may
//     only be used to observe reachability -- never to adopt an address, a
//     token, or an identity claim.
//
// Nothing here treats msg.From as proof of who sent the message. It is used
// only as a reachability observation, which is exactly what ssu2.rst
// §"Relay Process" intends when it tells Alice to prefer the UDP source port
// over the reported one.

// handleOutOfSessionMessage dispatches one opened out-of-session message by its
// header type byte. Runs on a listener packet worker, so it must not block.
func (t *SSU2Transport) handleOutOfSessionMessage(msg ssu2noise.OutOfSessionMessage) {
	switch msg.Type {
	case ssu2noise.MessageTypePeerTest:
		if err := t.handleOutOfSessionPeerTest(msg); err != nil {
			t.logger.WithFields(map[string]interface{}{
				"error":       err,
				"dest_connid": msg.DestConnID,
				"from":        msg.From.String(),
			}).Debug("PeerTest: dropped out-of-session message")
		}
	case ssu2noise.MessageTypeHolePunch:
		if err := t.handleOutOfSessionHolePunch(msg); err != nil {
			t.logger.WithFields(map[string]interface{}{
				"error":       err,
				"dest_connid": msg.DestConnID,
				"from":        msg.From.String(),
			}).Debug("HolePunch: dropped out-of-session message")
		}
	default:
		// Retry (9) and TokenRequest (10) are consumed inside the listener
		// (go-noise ssu2/server/retry.go, processTokenRequest) and never reach
		// this handler with any other type. Dropping quietly keeps a hostile
		// datagram from generating log volume.
		t.logger.WithField("messageType", msg.Type).
			Debug("ssu2: unhandled out-of-session message type")
	}
}

// defaultOutOfSessionMaxSkew is the fallback DateTime window used when the
// transport config leaves MaxClockSkew unset. ssu2.rst §"Replay Prevention"
// recommends "±2 minutes" and go-noise's config defaults to 120s; a
// hand-built config with a zero value must not silently disable the check.
const defaultOutOfSessionMaxSkew = 2 * time.Minute

// outOfSessionMaxSkew returns the DateTime skew window for out-of-session
// messages, honouring the configured MaxClockSkew with the spec's 2-minute
// recommendation as the floor when it is unset.
func (t *SSU2Transport) outOfSessionMaxSkew() time.Duration {
	if cfg := t.config.Load(); cfg != nil && cfg.SSU2Config != nil && cfg.MaxClockSkew > 0 {
		return cfg.MaxClockSkew
	}
	return defaultOutOfSessionMaxSkew
}

// validateOutOfSessionDateTime enforces the mandatory DateTime replay check on
// an intro-key protected out-of-session message.
//
// ssu2.rst §"Replay Prevention" (line 4036-4039): "Token Request, Retry,
// Session Request, Session Created, Hole Punch, and out-of-session Peer Test
// messages must contain DateTime blocks. Both Alice and Bob validate that the
// time for these messages is within a valid skew (recommended +/- 2 minutes)."
//
// The check is load-bearing here precisely because these messages are NOT
// authenticated: the seal key is our published introduction key, readable by
// anyone in the NetDB (see the security rule at the top of this file). Without
// a freshness gate, anyone who captured a single valid Peer Test 5/6/7 or Hole
// Punch datagram could replay it forever -- re-triggering replies, refreshing
// reachability observations, or re-delivering a relay response. The nonce
// correlation gate below does not help against replay, because a replay carries
// the original, still-known nonce.
//
// go-noise does not perform this check on the out-of-session path: it only
// validates DateTime skew for Session Request, Retry
// (ssu2/session/conn_handshake.go:966) and Token Request
// (ssu2/server/listener.go:731), and hands PeerTest/HolePunch payloads to the
// registered callback untouched. So it is enforced here, in go-i2p's dispatch.
func (t *SSU2Transport) validateOutOfSessionDateTime(blocks []*ssu2noise.SSU2Block, kind string) error {
	dateTime := ssu2noise.FindBlockByType(blocks, ssu2noise.BlockTypeDateTime)
	if dateTime == nil {
		return oops.Errorf("%s: missing required DateTime block", kind)
	}
	if len(dateTime.Data) < 4 {
		return oops.Errorf("%s: DateTime block too short: %d bytes", kind, len(dateTime.Data))
	}
	peer := time.Unix(int64(binary.BigEndian.Uint32(dateTime.Data[:4])), 0)
	skew := time.Since(peer)
	if skew < 0 {
		skew = -skew
	}
	if max := t.outOfSessionMaxSkew(); skew > max {
		return oops.Errorf("%s: DateTime skew %s exceeds maximum %s", kind, skew, max)
	}
	return nil
}

// handleOutOfSessionPeerTest processes a type-7 Peer Test message carrying
// peer-test code 5, 6 or 7.
func (t *SSU2Transport) handleOutOfSessionPeerTest(msg ssu2noise.OutOfSessionMessage) error {
	if err := t.validateOutOfSessionDateTime(msg.Blocks, "PeerTest"); err != nil {
		return err
	}
	ptBlock, err := findPeerTestBlock(msg.Blocks)
	if err != nil {
		return oops.Wrapf(err, "PeerTest message")
	}

	// Which connection ID holds the nonce depends on the direction: §"Peer Test
	// (Type 7)" -- "For messages 5 and 7 sent from Charlie to Alice, the
	// Destination Connection ID is two copies of the 4-byte big-endian test
	// nonce ... For message 6 sent from Alice to Charlie, swap the two
	// connection IDs."
	nonce := msg.DestConnID >> 32
	if ptBlock.MessageCode == ssu2noise.PeerTestReply {
		nonce = msg.SourceConnID >> 32
	}
	if uint32(nonce) != ptBlock.Nonce {
		// The header and the block disagree about which test this is. The
		// header is what we correlate on, so a mismatch means forgery or
		// corruption.
		return oops.Errorf("PeerTest msg %d: header nonce %d != block nonce %d",
			ptBlock.MessageCode, uint32(nonce), ptBlock.Nonce)
	}

	// Correlation gate (rule 1): we must be a participant in a test with this
	// nonce. Without it the message is unsolicited.
	if t.natRoleFor(ptBlock.Nonce) == natRoleUnknown {
		return oops.Errorf("PeerTest msg %d: no test context for nonce %d (unsolicited)",
			ptBlock.MessageCode, ptBlock.Nonce)
	}

	// Signature gate (rule 2). §"Peer Test Process" makes the 5-7 signatures
	// optional, but when one is present it MUST be verified: an unverifiable
	// signature is never treated as valid.
	if err := t.verifyPeerTestSignature(ptBlock, data.Hash{}); err != nil {
		return oops.Wrapf(err, "PeerTest msg %d signature", ptBlock.MessageCode)
	}

	switch ptBlock.MessageCode {
	case ssu2noise.PeerTestProbe: // 5: Charlie -> Alice
		return t.handlePeerTestProbeAsAlice(ptBlock, msg)
	case ssu2noise.PeerTestConfirmation: // 7: Charlie -> Alice
		return t.handlePeerTestConfirmationAsAlice(ptBlock, msg)
	case ssu2noise.PeerTestReply: // 6: Alice -> Charlie
		return t.handlePeerTestReplyAsCharlie(ptBlock, msg)
	default:
		return oops.Errorf("PeerTest: unexpected message code %d out-of-session", ptBlock.MessageCode)
	}
}

// handlePeerTestProbeAsAlice handles message 5, Charlie's direct probe.
//
// Its arrival is itself the useful observation: it proves Charlie can reach our
// external address, which is what the peer test exists to determine. We then
// answer with message 6, which opens our own firewall toward Charlie so that his
// message 7 can arrive.
func (t *SSU2Transport) handlePeerTestProbeAsAlice(ptBlock *ssu2noise.PeerTestBlock, msg ssu2noise.OutOfSessionMessage) error {
	t.recordPeerTestObservation(ptBlock)

	// §"Peer Test Process": "When message 5 arrives before message 4, Alice
	// cannot immediately send message 6, because she does not yet have
	// Charlie's intro key to encrypt the header." So Charlie's identity is a
	// hard prerequisite, and it comes from the in-session message 4 we already
	// verified -- never from this datagram.
	charlieHash, ok := t.lookupCharlieForNonce(ptBlock.Nonce)
	if !ok {
		t.logger.WithField("nonce", ptBlock.Nonce).
			Debug("PeerTest msg 5: no Charlie identity yet (message 4 not processed); not replying")
		return nil
	}

	// Reply to the endpoint the probe came from: this address has demonstrably
	// reached us, which is the whole point of messages 5-7.
	return t.sendPeerTestReplyToCharlie(ptBlock, charlieHash, msg.From)
}

// handlePeerTestConfirmationAsAlice handles message 7, Charlie's confirmation.
// It completes the test; nothing is sent back.
func (t *SSU2Transport) handlePeerTestConfirmationAsAlice(ptBlock *ssu2noise.PeerTestBlock, msg ssu2noise.OutOfSessionMessage) error {
	t.recordPeerTestObservation(ptBlock)
	t.natContexts.remove(ptBlock.Nonce)
	t.logger.WithFields(map[string]interface{}{
		"nonce": ptBlock.Nonce,
		"from":  msg.From.String(),
	}).Debug("PeerTest: received out-of-session confirmation (message 7)")
	return nil
}

// handlePeerTestReplyAsCharlie handles message 6, Alice's reply to our probe.
func (t *SSU2Transport) handlePeerTestReplyAsCharlie(ptBlock *ssu2noise.PeerTestBlock, msg ssu2noise.OutOfSessionMessage) error {
	// We need Alice's identity to resolve her intro key for message 7. The
	// verifier above required it from the authenticated message 2 whenever this
	// message was signed.
	aliceHash, ok := t.lookupAliceForNonce(ptBlock.Nonce)
	if !ok {
		return oops.Errorf("PeerTest msg 6: no Alice identity for nonce %d", ptBlock.Nonce)
	}

	// Alice's reachability is confirmed the moment her reply arrives from the
	// address we probed.
	t.recordPeerTestObservation(ptBlock)

	return t.sendPeerTestConfirmationToAlice(ptBlock, aliceHash, msg.From)
}

// recordPeerTestObservation feeds an out-of-session peer-test message into the
// same confirmation logic the in-session path uses.
//
// The address inside the block is NOT adopted from an out-of-session message:
// it is our own claimed address echoed back, and the datagram is unauthenticated
// apart from the public intro key. What is meaningful is the fact of arrival.
// handlePeerTestAsAlice already enforces the nonce-belongs-to-us check that
// protects the address-confirmation cache from poisoning (RD-1), so we route
// through it instead of duplicating the gate.
func (t *SSU2Transport) recordPeerTestObservation(ptBlock *ssu2noise.PeerTestBlock) {
	t.natManagerMu.RLock()
	mgr := t.peerTestManager
	t.natManagerMu.RUnlock()
	if mgr == nil {
		return
	}
	if err := t.handlePeerTestAsAlice(ptBlock, mgr); err != nil {
		t.logger.WithField("error", err).Debug("PeerTest: out-of-session observation not recorded")
	}
}

// sendPeerTestReplyToCharlie sends message 6 (Alice -> Charlie), out-of-session
// under Charlie's introduction key.
//
// §"Peer Test Process": "Message 6 may contain the same signed data as sent in
// messages 1 and 2, or it may be regenerated with a new timestamp. Signature is
// optional." We regenerate with a fresh timestamp and sign it, because an
// unsigned out-of-session message gives an observer nothing to attribute and
// costs us nothing to avoid. The signed-data recipe for the request half uses
// bhash = Bob and NO Alice hash (§"Signatures": the Alice hash is "Only used in
// the signature for messages 3 and 4").
func (t *SSU2Transport) sendPeerTestReplyToCharlie(ptBlock *ssu2noise.PeerTestBlock, charlieHash data.Hash, charlieAddr *net.UDPAddr) error {
	listener := t.outOfSessionListener()
	if listener == nil {
		return oops.Errorf("no listener: cannot send PeerTest reply")
	}
	if charlieAddr == nil {
		return oops.Errorf("PeerTest msg 6: no Charlie endpoint")
	}
	introKey, err := t.peerIntroKey(charlieHash)
	if err != nil {
		return oops.Wrapf(err, "PeerTest msg 6")
	}
	bobHash, ok := t.lookupBobForNonce(ptBlock.Nonce)
	if !ok {
		return oops.Errorf("PeerTest msg 6: no Bob identity for nonce %d", ptBlock.Nonce)
	}

	reply := &ssu2noise.PeerTestBlock{
		MessageCode: ssu2noise.PeerTestReply,
		Nonce:       ptBlock.Nonce,
		Version:     ptBlock.Version,
		Timestamp:   transport.RoundUnixSeconds(time.Now()),
		AlicePort:   ptBlock.AlicePort,
		AliceIP:     append([]byte(nil), ptBlock.AliceIP...),
	}
	if err := t.signPeerTestBlock(reply, bobHash, nil); err != nil {
		// Signing needs our own key; without it we can still send, since the
		// signature is optional for messages 5-7. Log and continue unsigned.
		t.logger.WithField("error", err).Debug("PeerTest msg 6: signing unavailable, sending unsigned")
	}

	encoded, err := ssu2noise.EncodePeerTestBlock(reply)
	if err != nil {
		return oops.Wrapf(err, "PeerTest msg 6: encode block")
	}

	// Message 6 swaps the nonce-derived connection IDs.
	dest, src := ssu2noise.NonceConnectionIDs(ptBlock.Nonce)
	spec := &ssu2noise.IntroKeyMessageSpec{
		MessageType:  ssu2noise.MessageTypePeerTest,
		DestConnID:   src,
		SourceConnID: dest,
		Blocks: []*ssu2noise.SSU2Block{
			ssu2noise.NewDateTimeBlock(),
			// §"Peer Test (Type 7)" payload list: the Address block is
			// "required for messages 6 and 7", and it carries the endpoint of
			// the peer this message is addressed to.
			ssu2noise.NewAddressBlockForAddr(charlieAddr),
			encoded,
		},
	}
	if err := listener.SendIntroKeyMessage(introKey, spec, charlieAddr); err != nil {
		return oops.Wrapf(err, "PeerTest msg 6: send to Charlie")
	}
	t.logger.WithFields(map[string]interface{}{
		"nonce":        ptBlock.Nonce,
		"charlie_addr": charlieAddr.String(),
		"charlie_hash": logutil.HashPrefixPlain(charlieHash),
	}).Debug("PeerTest: sent message 6 reply to Charlie (out-of-session, intro-key sealed)")
	return nil
}

// sendPeerTestConfirmationToAlice sends message 7 (Charlie -> Alice) under
// Alice's introduction key, confirming the exchange.
//
// Like messages 3 and 4 this carries the agreement half's signed data, so bhash
// = Bob and ahash = Alice (§"Signatures").
func (t *SSU2Transport) sendPeerTestConfirmationToAlice(ptBlock *ssu2noise.PeerTestBlock, aliceHash data.Hash, aliceAddr *net.UDPAddr) error {
	listener := t.outOfSessionListener()
	if listener == nil {
		return oops.Errorf("no listener: cannot send PeerTest confirmation")
	}
	if aliceAddr == nil {
		return oops.Errorf("PeerTest msg 7: no Alice endpoint")
	}
	introKey, err := t.peerIntroKey(aliceHash)
	if err != nil {
		return oops.Wrapf(err, "PeerTest msg 7")
	}
	bobHash, ok := t.lookupBobForNonce(ptBlock.Nonce)
	if !ok {
		return oops.Errorf("PeerTest msg 7: no Bob identity for nonce %d", ptBlock.Nonce)
	}

	confirm := &ssu2noise.PeerTestBlock{
		MessageCode: ssu2noise.PeerTestConfirmation,
		Nonce:       ptBlock.Nonce,
		Version:     ptBlock.Version,
		Timestamp:   transport.RoundUnixSeconds(time.Now()),
		AlicePort:   ptBlock.AlicePort,
		AliceIP:     append([]byte(nil), ptBlock.AliceIP...),
	}
	// For message 7 the ahash in the signed data is ALICE's hash (she is the
	// other party), while bhash is Bob's.
	if err := t.signPeerTestBlock(confirm, bobHash, &aliceHash); err != nil {
		t.logger.WithField("error", err).Debug("PeerTest msg 7: signing unavailable, sending unsigned")
	}

	encoded, err := ssu2noise.EncodePeerTestBlock(confirm)
	if err != nil {
		return oops.Wrapf(err, "PeerTest msg 7: encode block")
	}

	dest, src := ssu2noise.NonceConnectionIDs(ptBlock.Nonce)
	spec := &ssu2noise.IntroKeyMessageSpec{
		MessageType:  ssu2noise.MessageTypePeerTest,
		DestConnID:   dest,
		SourceConnID: src,
		Blocks: []*ssu2noise.SSU2Block{
			ssu2noise.NewDateTimeBlock(),
			ssu2noise.NewAddressBlockForAddr(aliceAddr),
			encoded,
		},
	}
	if err := listener.SendIntroKeyMessage(introKey, spec, aliceAddr); err != nil {
		return oops.Wrapf(err, "PeerTest msg 7: send to Alice")
	}
	t.logger.WithFields(map[string]interface{}{
		"nonce":      ptBlock.Nonce,
		"alice_addr": aliceAddr.String(),
	}).Debug("PeerTest: sent message 7 confirmation to Alice (out-of-session, intro-key sealed)")
	return nil
}

// signPeerTestBlock signs a peer-test block with our own router signing key.
// aliceHash is nil for the request half (messages 1, 2, 6) and Alice's hash for
// the agreement half (messages 3, 4, 5, 7), per §"Signatures".
func (t *SSU2Transport) signPeerTestBlock(block *ssu2noise.PeerTestBlock, bobHash data.Hash, aliceHash *data.Hash) error {
	signingKey := t.keystore.GetSigningPrivateKey()
	if signingKey == nil {
		return oops.Errorf("signing key unavailable")
	}
	sig, err := ssu2noise.SignPeerTest(
		i2ped25519.Ed25519PrivateKey(signingKey.Bytes()),
		bobHash, aliceHash,
		block.Version, block.Nonce, block.Timestamp,
		block.AlicePort, block.AliceIP,
	)
	if err != nil {
		return oops.Wrapf(err, "sign peer test block")
	}
	block.Signature = sig
	return nil
}

// handleOutOfSessionHolePunch processes a type-11 Hole Punch.
//
// Per ssu2.rst §"Relay Process" step 5, Charlie sends this straight to Alice
// after accepting the introduction. Its payload carries the same Relay Response
// block Bob forwards, and §"Hole Punch (Type 11)" says the header token is
// random and ignored -- the real token is inside that block.
//
// Because the block hands Alice both an address and a session token, acting on
// it without binding would let anyone who read our RouterInfo redirect our
// connection attempts. So the binding is strict: the nonce must match a relay
// request WE sent and are still waiting on.
func (t *SSU2Transport) handleOutOfSessionHolePunch(msg ssu2noise.OutOfSessionMessage) error {
	if err := t.validateOutOfSessionDateTime(msg.Blocks, "HolePunch"); err != nil {
		return err
	}
	// §"Hole Punch" uses the same nonce-derived connection IDs as messages
	// 5/7 (Charlie -> Alice), so the nonce is in the destination ID.
	nonce := uint32(msg.DestConnID >> 32)

	v, ok := t.pendingRelayResponses.Load(nonce)
	if !ok {
		return oops.Errorf("HolePunch: no pending relay request for nonce %d (unsolicited)", nonce)
	}
	pending, ok := v.(*pendingRelayResponse)
	if !ok || pending.consumed.Load() {
		return oops.Errorf("HolePunch: relay request for nonce %d already resolved", nonce)
	}

	respBlock, err := findRelayResponseBlock(msg.Blocks)
	if err != nil {
		return oops.Wrapf(err, "HolePunch")
	}
	if respBlock.Nonce != nonce {
		return oops.Errorf("HolePunch: block nonce %d != header nonce %d", respBlock.Nonce, nonce)
	}

	// Verify Charlie's signature before the token or address is used by
	// anything. The sender identity handed to the verifier is Bob -- the peer we
	// actually asked for the introduction -- taken from the pending request we
	// created ourselves, so it cannot be influenced by the attacker's datagram.
	// verifyRelayResponseSignature then resolves the real signer (Charlie) from
	// the nonce context, also ours.
	if pending.bobHash == (data.Hash{}) {
		return oops.Errorf("HolePunch: relay request for nonce %d has no Bob identity", nonce)
	}
	valid, err := t.verifyRelayResponseSignature(respBlock, pending.bobHash)
	if err != nil {
		return oops.Wrapf(err, "HolePunch: RelayResponse signature")
	}
	if !valid {
		return oops.Errorf("HolePunch: RelayResponse signature verification did not succeed")
	}

	// Apply the spec's symmetric-NAT rule to the response BEFORE anything
	// consumes it: §"Relay Process" Response Handling says "Alice should check
	// the UDP source port of the Hole Punch message, and use that if it is
	// different than the reported port." Charlie's reported endpoint is only
	// reachable from inside his own NAT; the source address of the datagram he
	// actually sent is the endpoint that can answer us. The dialer builds
	// Charlie's address straight from this block, so correcting it here is what
	// makes the relayed connection work.
	//
	// The IP is taken from the source address too, but only when it agrees with
	// the reported address family -- a source IP that contradicts a verified
	// signature would mean the forwarder and the signer disagree, and the
	// signature is the thing we trust for identity.
	respBlock = applyHolePunchSourceEndpoint(respBlock, msg.From)

	// Hand the response to the dialing goroutine. It now has a verified token
	// and endpoint for Charlie.
	select {
	case pending.ch <- respBlock:
		pending.consumed.Store(true)
	default:
		// Already resolved in-session; the Hole Punch and Bob's forwarded
		// RelayResponse may arrive in either order.
	}
	t.logger.WithFields(map[string]interface{}{
		"nonce":     nonce,
		"from":      msg.From.String(),
		"charlie":   logutil.HashPrefixPlain(pending.charlieHash),
		"code":      respBlock.Code,
		"src_port":  msg.From.Port,
		"resp_port": respBlock.CharliePort,
	}).Debug("HolePunch: verified out-of-session relay response delivered to waiter")
	return nil
}

// applyHolePunchSourceEndpoint returns a copy of resp whose Charlie endpoint is
// the UDP source address of the Hole Punch that carried it, when the reported
// port differs (symmetric NAT). The original block is left untouched so the
// in-session copy Bob forwards still matches the signature bytes.
func applyHolePunchSourceEndpoint(resp *ssu2noise.RelayResponseBlock, from *net.UDPAddr) *ssu2noise.RelayResponseBlock {
	if from == nil || resp == nil {
		return resp
	}
	// Only an accepted response carries Charlie's endpoint. A rejection has
	// csz = 0 and no endpoint at all, so its zero fields must be left alone
	// rather than "corrected" to our source address.
	if resp.Code != 0 {
		return resp
	}
	if int(resp.CharliePort) == from.Port {
		return resp
	}
	adjusted := *resp
	adjusted.CharliePort = uint16(from.Port)
	adjusted.CharlieIP = nil
	if from.IP != nil {
		if v4 := from.IP.To4(); v4 != nil {
			adjusted.CharlieIP = v4
		} else if v6 := from.IP.To16(); v6 != nil && len(from.IP) == net.IPv6len {
			adjusted.CharlieIP = v6
		}
	}
	return &adjusted
}

// findPeerTestBlock returns the first decoded Peer Test block in a block list.
func findPeerTestBlock(blocks []*ssu2noise.SSU2Block) (*ssu2noise.PeerTestBlock, error) {
	for _, b := range blocks {
		if b == nil || b.Type != ssu2noise.BlockTypePeerTest {
			continue
		}
		pt, err := ssu2noise.DecodePeerTestBlock(b)
		if err != nil {
			return nil, oops.Wrapf(err, "decode PeerTest block")
		}
		return pt, nil
	}
	return nil, oops.Errorf("no PeerTest block in message")
}

// findRelayResponseBlock returns the first decoded Relay Response block.
func findRelayResponseBlock(blocks []*ssu2noise.SSU2Block) (*ssu2noise.RelayResponseBlock, error) {
	for _, b := range blocks {
		if b == nil || b.Type != ssu2noise.BlockTypeRelayResponse {
			continue
		}
		resp, err := ssu2noise.DecodeRelayResponse(b)
		if err != nil {
			return nil, oops.Wrapf(err, "decode RelayResponse block")
		}
		return resp, nil
	}
	return nil, oops.Errorf("no RelayResponse block in message")
}
