package ssu2

import (
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"net"
	"strconv"
	"sync/atomic"
	"time"

	i2pbase64 "github.com/go-i2p/common/base64"
	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	nattraversal "github.com/go-i2p/go-nat-listener"
	ssu2noise "github.com/go-i2p/go-noise/ssu2"
	"github.com/samber/oops"
)

// NAT-PMP/UPnP port-map retry timing constants.
const (
	// natRetryInitial is the initial wait before the first retry attempt.
	natRetryInitial = 30 * time.Second
	// natRetryMax caps the exponential back-off between retry attempts.
	natRetryMax = 30 * time.Minute
)

// initNATManagers allocates and wires the PeerTestManager, RelayManager,
// IntroducerRegistry, and HolePunchCoordinator on a freshly started transport.
// Must be called after t.listener is initialised.
func initNATManagers(t *SSU2Transport) {
	t.relayManager = ssu2noise.NewRelayManager(t.listener)
	t.introducerRegistry = ssu2noise.NewIntroducerRegistry(3)
	t.holePunchCoord = ssu2noise.NewHolePunchCoordinator(t.relayManager)
	t.peerTestManager = ssu2noise.NewPeerTestManager(t.listener)
	if t.natStateCache == nil {
		t.natStateCache = &natState{}
	}
	t.loadNATState()
	t.startNATCleanup()
	t.startNATPortMapRetry()
}

// buildTransportCallbacks returns a BlockCallbackConfig whose handlers delegate
// to the transport's NAT managers. The session parameter is used by the
// PeerTest handler to enforce per-session rate limits and source validation.
// Sessions call this to supplement their own local callbacks (termination,
// clock validation).
func (t *SSU2Transport) buildTransportCallbacks(session *SSU2Session) *BlockCallbackConfig {
	return &BlockCallbackConfig{
		OnPeerTest: func(block *ssu2noise.SSU2Block) error {
			return t.handlePeerTestBlock(block, session)
		},
		OnRelayRequest: func(block *ssu2noise.SSU2Block) error {
			return t.handleRelayRequestBlock(block, session)
		},
		OnRelayResponse: func(block *ssu2noise.SSU2Block) error {
			return t.handleRelayResponseBlock(block)
		},
		OnRelayIntro: func(block *ssu2noise.SSU2Block) error {
			return t.handleRelayIntroBlock(block, session)
		},
	}
}

// handlePeerTestBlock processes an incoming PeerTest block, dispatching by
// message code to support Alice (initiator), Bob (relay), and Charlie
// (responder) roles in the SSU2 peer test protocol.
func (t *SSU2Transport) handlePeerTestBlock(block *ssu2noise.SSU2Block, session *SSU2Session) error {
	if t.peerTestManager == nil {
		return nil
	}
	ptBlock, err := ssu2noise.DecodePeerTestBlock(block)
	if err != nil {
		t.logger.WithField("error", err).Warn("failed to decode PeerTest block")
		return err
	}
	switch ptBlock.MessageCode {
	case ssu2noise.PeerTestRequest:
		return t.handlePeerTestAsBob(ptBlock, session)
	case ssu2noise.PeerTestRelay:
		return t.handlePeerTestAsCharlie(ptBlock)
	default:
		return t.handlePeerTestAsAlice(ptBlock)
	}
}

// handlePeerTestAsAlice processes a PeerTest response/probe/result directed at
// the test initiator (Alice). It reconstructs the observed external address
// and completes the pending test. If 2+ PeerTest observations agree on the
// same external address within peerTestObservationWindow, the republish
// callback is invoked so the new address can be published to the netdb.
func (t *SSU2Transport) handlePeerTestAsAlice(ptBlock *ssu2noise.PeerTestBlock) error {
	nonce := ptBlock.Nonce
	var externalAddr *net.UDPAddr
	if len(ptBlock.AliceIP) > 0 {
		externalAddr = &net.UDPAddr{
			IP:   net.IP(ptBlock.AliceIP),
			Port: int(ptBlock.AlicePort),
		}
	}
	result := &ssu2noise.TestResult{
		ExternalAddr: externalAddr,
		Reachable:    externalAddr != nil,
	}
	if completeErr := t.peerTestManager.CompleteTest(nonce, result); completeErr != nil {
		t.logger.Debug("PeerTest complete (non-initiator path)")
	}
	// Record observation for majority-confirmation logic (D3).
	if externalAddr != nil && t.natStateCache != nil {
		confirmed := t.natStateCache.recordObservation(externalAddr.String())
		if confirmed != "" && confirmed != t.natStateCache.getExternal() {
			t.reachMetrics.peerTestConfirmed.Add(1)
			t.logger.WithField("external_addr", confirmed).
				Info("PeerTest: external address confirmed by multiple observations")
			t.natStateCache.set(ssu2noise.NATCone, confirmed)
			t.saveNATState()
			if fn, ok := t.peerTestRepublish.Load().(func()); ok && fn != nil {
				t.reachMetrics.publishedAddrChanged.Add(1)
				go fn()
			}
		}
	}
	return nil
}

// parsePeerTestAliceAddr extracts Alice's UDP address from a PeerTest block.
// Returns nil if no address is declared.
func parsePeerTestAliceAddr(ptBlock *ssu2noise.PeerTestBlock) *net.UDPAddr {
	if len(ptBlock.AliceIP) == 0 {
		return nil
	}
	return &net.UDPAddr{
		IP:   net.IP(ptBlock.AliceIP),
		Port: int(ptBlock.AlicePort),
	}
}

// validateBobAliceAddress checks that the declared AliceIP in the PeerTest
// block matches the session's observed remote address. Returns false if a
// mismatch is detected (relay-forwarder spoofing attempt).
func (t *SSU2Transport) validateBobAliceAddress(session *SSU2Session, aliceAddr *net.UDPAddr) bool {
	if session == nil {
		return true
	}
	observed := session.RemoteUDPAddr()
	if observed == nil {
		return true
	}
	if observed.IP.Equal(aliceAddr.IP) && observed.Port == aliceAddr.Port {
		return true
	}
	t.logger.WithFields(map[string]interface{}{
		"declared": aliceAddr.String(),
		"observed": observed.String(),
	}).Warn("PeerTest Bob: AliceIP mismatch, dropping")
	return false
}

// checkBobRateLimits checks per-session and global PeerTest rate limits.
// Returns false if any limit is exceeded.
func (t *SSU2Transport) checkBobRateLimits(session *SSU2Session) bool {
	if session != nil && !session.peerTestLimiter.Allow() {
		t.logger.Debug("PeerTest Bob: per-session rate limit exceeded, dropping")
		return false
	}
	if t.peerTestGlobalLimiter != nil && !t.peerTestGlobalLimiter.Allow() {
		t.logger.Debug("PeerTest Bob: global rate limit exceeded, dropping")
		return false
	}
	return true
}

// handlePeerTestAsBob processes a PeerTest request where we act as Bob (relay).
// It validates that Alice's declared address matches the session's observed
// remote address to prevent source-address spoofing, enforces per-session and
// global rate limits, then forwards a PeerTestRelay to Charlie.
func (t *SSU2Transport) handlePeerTestAsBob(ptBlock *ssu2noise.PeerTestBlock, session *SSU2Session) error {
	aliceAddr := parsePeerTestAliceAddr(ptBlock)
	if aliceAddr == nil {
		t.logger.Debug("PeerTest Bob: missing Alice address, ignoring")
		return nil
	}
	if !t.validateBobAliceAddress(session, aliceAddr) {
		return nil
	}
	if !t.checkBobRateLimits(session) {
		return nil
	}
	charlieAddr := t.resolveCharlieAddr(ptBlock)
	if charlieAddr == nil {
		t.logger.Debug("PeerTest Bob: cannot resolve Charlie address, ignoring")
		return nil
	}
	if _, err := t.peerTestManager.CreateRelayTest(ptBlock.Nonce, aliceAddr, charlieAddr); err != nil {
		t.logger.WithField("error", err).Debug("PeerTest Bob: failed to create relay test")
		return nil
	}
	return t.forwardPeerTestToCharlie(ptBlock, charlieAddr)
}

// resolveCharlieAddr looks up Charlie's SSU2 address from the RouterHash in
// the PeerTest block. Returns nil if the hash is absent or the address cannot
// be resolved.
func (t *SSU2Transport) resolveCharlieAddr(ptBlock *ssu2noise.PeerTestBlock) *net.UDPAddr {
	if ptBlock.RouterHash == nil {
		return nil
	}
	session := t.findSessionByHash(*ptBlock.RouterHash)
	if session == nil {
		return nil
	}
	return session.RemoteUDPAddr()
}

// forwardPeerTestToCharlie builds a PeerTestRelay block and sends it to
// Charlie via an existing session.
func (t *SSU2Transport) forwardPeerTestToCharlie(ptBlock *ssu2noise.PeerTestBlock, charlieAddr *net.UDPAddr) error {
	session := t.findSessionByAddr(charlieAddr)
	if session == nil {
		t.logger.Debug("PeerTest Bob: no session to Charlie for relay")
		return nil
	}
	relayBlock := &ssu2noise.PeerTestBlock{
		MessageCode: ssu2noise.PeerTestRelay,
		Nonce:       ptBlock.Nonce,
		Version:     ptBlock.Version,
		Timestamp:   ptBlock.Timestamp,
		AlicePort:   ptBlock.AlicePort,
		AliceIP:     ptBlock.AliceIP,
		Signature:   ptBlock.Signature,
	}
	encoded, err := ssu2noise.EncodePeerTestBlock(relayBlock)
	if err != nil {
		return oops.Wrapf(err, "PeerTest Bob: encode relay block")
	}
	return session.WriteBlocks([]*ssu2noise.SSU2Block{encoded})
}

// handlePeerTestAsCharlie processes a PeerTestRelay where we act as Charlie
// (responder). We record the test and send a direct probe to Alice.
func (t *SSU2Transport) handlePeerTestAsCharlie(ptBlock *ssu2noise.PeerTestBlock) error {
	var aliceAddr *net.UDPAddr
	if len(ptBlock.AliceIP) > 0 {
		aliceAddr = &net.UDPAddr{
			IP:   net.IP(ptBlock.AliceIP),
			Port: int(ptBlock.AlicePort),
		}
	}
	if aliceAddr == nil {
		t.logger.Debug("PeerTest Charlie: missing Alice address, ignoring")
		return nil
	}
	if err := t.peerTestManager.CreateResponderTest(ptBlock.Nonce, aliceAddr, nil); err != nil {
		t.logger.WithField("error", err).Debug("PeerTest Charlie: failed to create responder test")
		return nil
	}
	return t.sendProbeToAlice(ptBlock, aliceAddr)
}

// sendProbeToAlice sends a PeerTestProbe directly to Alice so she can observe
// connectivity from a third party (Charlie). Uses an existing session's
// underlying connection to send to Alice's address.
func (t *SSU2Transport) sendProbeToAlice(ptBlock *ssu2noise.PeerTestBlock, aliceAddr *net.UDPAddr) error {
	probeBlock := &ssu2noise.PeerTestBlock{
		MessageCode: ssu2noise.PeerTestProbe,
		Nonce:       ptBlock.Nonce,
		Version:     ptBlock.Version,
		Timestamp:   uint32(time.Now().Unix()),
	}
	encoded, err := ssu2noise.EncodePeerTestBlock(probeBlock)
	if err != nil {
		return oops.Wrapf(err, "PeerTest Charlie: encode probe block")
	}
	session := t.anyActiveSession()
	if session == nil || session.conn == nil {
		t.logger.Debug("PeerTest Charlie: no active session to send probe")
		return nil
	}
	return session.conn.SendToAddress(encoded, aliceAddr)
}

// anyActiveSession returns the first active SSU2Session, or nil if none exist.
func (t *SSU2Transport) anyActiveSession() *SSU2Session {
	var found *SSU2Session
	t.sessions.Range(func(_, value interface{}) bool {
		s, ok := value.(*SSU2Session)
		if ok && s.conn != nil {
			found = s
			return false
		}
		return true
	})
	return found
}

// handleRelayRequestBlock processes a RelayRequest from Alice (we are Bob).
// It enforces a per-Alice-session rate limit, decodes the request, and
// forwards a RelayIntro to Charlie via the session associated with the relay
// tag. Signature verification is deferred until the transport gains netdb
// access for Alice's Ed25519 signing key (tracked as a known gap).
func (t *SSU2Transport) handleRelayRequestBlock(block *ssu2noise.SSU2Block, session *SSU2Session) error {
	if t.relayManager == nil || block == nil {
		return nil
	}
	// Rate-limit per Alice session using the same token bucket as PeerTest.
	if session != nil && !session.peerTestLimiter.Allow() {
		t.logger.Debug("RelayRequest: per-session rate limit exceeded, dropping")
		return nil
	}
	req, err := ssu2noise.DecodeRelayRequest(block)
	if err != nil {
		t.logger.WithField("error", err).Warn("failed to decode RelayRequest")
		return nil
	}
	return t.forwardRelayIntro(req)
}

// forwardRelayIntro looks up the relay tag target (Charlie), builds a
// RelayIntro block, and writes it to Charlie's session.
// Rejects when no relay tag is registered for the requested tag value or when
// there is no active session to Charlie.
// Note: caps=B check on Charlie requires netdb RouterInfo lookup; relay tag
// registration serves as a local proxy for introducer capability.
func (t *SSU2Transport) forwardRelayIntro(req *ssu2noise.RelayRequestBlock) error {
	tag := t.relayManager.GetRelayTag(req.RelayTag)
	if tag == nil {
		t.logger.WithField("relay_tag", req.RelayTag).Warn("RelayRequest rejected: unknown or expired relay tag")
		return nil
	}
	session := t.findSessionByAddr(tag.ForAddr)
	if session == nil {
		t.logger.WithField("charlie_addr", tag.ForAddr).Warn("RelayRequest rejected: no active session to Charlie")
		return nil
	}
	intro := buildRelayIntro(req)
	encoded, err := ssu2noise.EncodeRelayIntro(intro)
	if err != nil {
		return err
	}
	return session.WriteBlocks([]*ssu2noise.SSU2Block{encoded})
}

// buildRelayIntro constructs a RelayIntroBlock from a RelayRequest.
func buildRelayIntro(req *ssu2noise.RelayRequestBlock) *ssu2noise.RelayIntroBlock {
	return &ssu2noise.RelayIntroBlock{
		Nonce:         req.Nonce,
		AliceRelayTag: req.RelayTag,
		Timestamp:     req.Timestamp,
		Version:       req.Version,
		AlicePort:     req.AlicePort,
		AliceIP:       req.AliceIP,
		Signature:     req.Signature,
	}
}

// handleRelayResponseBlock processes a RelayResponse (we are Alice).
// If a dialViaIntroducer goroutine is waiting for this nonce it is notified;
// otherwise the response is logged and discarded.
func (t *SSU2Transport) handleRelayResponseBlock(block *ssu2noise.SSU2Block) error {
	if t.relayManager == nil || block == nil {
		return nil
	}
	resp, err := ssu2noise.DecodeRelayResponse(block)
	if err != nil {
		t.logger.WithField("error", err).Warn("failed to decode RelayResponse")
		return nil
	}

	t.logger.WithField("code", resp.Code).Debug("relay response received")

	// Deliver to any waiting dialViaIntroducer call.
	if ch, ok := t.pendingRelayResponses.Load(resp.Nonce); ok {
		responseCh := ch.(chan *ssu2noise.RelayResponseBlock)
		select {
		case responseCh <- resp:
		default:
			// channel already has a value (duplicate delivery); ignore
		}
	}
	return nil
}

// handleRelayIntroBlock processes a RelayIntro (we are Charlie). It decodes
// the intro, sends a HolePunch to Alice, and sends a RelayResponse back to
// Bob so Bob can forward it to Alice. bobSession is the session from which
// the RelayIntro arrived.
func (t *SSU2Transport) handleRelayIntroBlock(block *ssu2noise.SSU2Block, bobSession *SSU2Session) error {
	if t.holePunchCoord == nil || block == nil {
		return nil
	}
	intro, err := ssu2noise.DecodeRelayIntro(block)
	if err != nil {
		t.logger.WithField("error", err).Warn("failed to decode RelayIntro")
		return nil
	}
	return t.initiateHolePunch(intro, bobSession)
}

// initiateHolePunch starts a hole-punch towards Alice based on a RelayIntro,
// sends a HolePunch datagram to Alice, and sends a RelayResponse to Bob.
// bobSession carries Bob's session (from which the RelayIntro arrived).
func (t *SSU2Transport) initiateHolePunch(intro *ssu2noise.RelayIntroBlock, bobSession *SSU2Session) error {
	aliceAddr := &net.UDPAddr{
		IP:   net.IP(intro.AliceIP),
		Port: int(intro.AlicePort),
	}
	if bobSession == nil {
		t.logger.Debug("hole-punch: no Bob session provided, skipping")
		return nil
	}
	bobAddr := bobSession.RemoteUDPAddr()
	if bobAddr != nil {
		if _, err := t.holePunchCoord.InitiateHolePunch(aliceAddr, bobAddr, intro.AliceRelayTag); err != nil {
			t.logger.WithField("error", err).Debug("hole-punch coordinator registration failed (non-fatal)")
		}
	}
	t.sendHolePunchToAlice(intro, aliceAddr)
	if err := t.sendRelayResponseToBob(bobSession, intro); err != nil {
		t.logger.WithField("error", err).Warn("failed to send RelayResponse to Bob")
		return err
	}
	t.logger.WithField("alice_addr", aliceAddr).Debug("hole-punch initiated towards Alice")
	return nil
}

// sendHolePunchToAlice sends a best-effort HolePunch UDP datagram to Alice.
// Uses the same wire format as RelayIntro (block type 9; the receiver ignores
// the type byte for UDP hole-punch purposes). Non-fatal on failure.
func (t *SSU2Transport) sendHolePunchToAlice(intro *ssu2noise.RelayIntroBlock, aliceAddr *net.UDPAddr) {
	session := t.anyActiveSession()
	if session == nil || session.conn == nil {
		t.logger.Debug("hole-punch: no active session available to send from")
		return
	}
	encoded, err := ssu2noise.EncodeRelayIntro(intro)
	if err != nil {
		t.logger.WithField("error", err).Debug("hole-punch: encode block failed")
		return
	}
	if err := session.conn.SendToAddress(encoded, aliceAddr); err != nil {
		t.logger.WithField("error", err).Debug("hole-punch: send to Alice failed")
	}
}

// sendRelayResponseToBob signs and sends a RelayResponse (code=0) to Bob so
// that Bob can forward it to Alice. Alice uses Charlie's IP/Port and token to
// send the SSU2 SessionRequest directly to us.
func (t *SSU2Transport) sendRelayResponseToBob(bobSession *SSU2Session, intro *ssu2noise.RelayIntroBlock) error {
	charlieIP, charliePort, err := t.localIPPort()
	if err != nil {
		return oops.Wrapf(err, "hole-punch: local address")
	}
	signingKey := t.keystore.GetSigningPrivateKey()
	if signingKey == nil {
		return oops.Errorf("hole-punch: signing key unavailable")
	}
	token := make([]byte, 8)
	if _, err := cryptorand.Read(token); err != nil {
		return oops.Wrapf(err, "hole-punch: token generation")
	}
	var bobHash data.Hash
	if ssu2Addr, ok := bobSession.conn.RemoteAddr().(*ssu2noise.SSU2Addr); ok {
		bobHash = ssu2Addr.RouterHash()
	}
	timestamp := uint32(time.Now().Unix())
	ed25519Key := ed25519.PrivateKey(signingKey.Bytes())
	sig, err := ssu2noise.SignRelayResponse(ed25519Key, bobHash, intro.Nonce, timestamp, intro.Version, charliePort, charlieIP)
	if err != nil {
		return oops.Wrapf(err, "hole-punch: sign RelayResponse")
	}
	resp := &ssu2noise.RelayResponseBlock{
		Code: 0, Nonce: intro.Nonce, Timestamp: timestamp,
		Version: intro.Version, CharliePort: charliePort, CharlieIP: charlieIP,
		Signature: sig, Token: token,
	}
	encoded, err := ssu2noise.EncodeRelayResponse(resp)
	if err != nil {
		return oops.Wrapf(err, "hole-punch: encode RelayResponse")
	}
	return bobSession.WriteBlocks([]*ssu2noise.SSU2Block{encoded})
}

// InitiateNATDetection starts a peer-test as Alice against the specified Bob
// address. Returns the test nonce so the caller can correlate the result.
func (t *SSU2Transport) InitiateNATDetection(bobAddr *net.UDPAddr) (uint32, error) {
	if t.peerTestManager == nil {
		return 0, ErrTransportNotStarted
	}
	return t.peerTestManager.InitiatePeerTest(bobAddr)
}

// GetNATType returns the NAT type determined from the most recent peer-test
// result for the given address. Returns NATUnknown if no result is available.
func (t *SSU2Transport) GetNATType(peerAddr *net.UDPAddr) ssu2noise.NATType {
	if t.peerTestManager == nil {
		return ssu2noise.NATUnknown
	}
	result := t.peerTestManager.GetResult(peerAddr)
	if result == nil {
		return ssu2noise.NATUnknown
	}
	return t.peerTestManager.DetermineNATType(result)
}

// GetCachedNATType returns the most recently cached NAT type from the
// transport-level cache. Returns NATUnknown if the cache is empty or expired
// (30-minute TTL).
func (t *SSU2Transport) GetCachedNATType() ssu2noise.NATType {
	natType, valid := t.natStateCache.get()
	if !valid {
		return ssu2noise.NATUnknown
	}
	return natType
}

// GetCachedExternalAddr returns the external address string confirmed by
// PeerTest observations (or by NAT-PMP/UPnP mapping). Returns "" when no
// confirmed external address is available yet.
func (t *SSU2Transport) GetCachedExternalAddr() string {
	if t.natStateCache == nil {
		return ""
	}
	return t.natStateCache.getExternal()
}

// GetExternalAddr returns the external UDP address detected from the most
// recent peer-test result. Returns nil if no result is available.
func (t *SSU2Transport) GetExternalAddr(peerAddr *net.UDPAddr) *net.UDPAddr {
	if t.peerTestManager == nil {
		return nil
	}
	result := t.peerTestManager.GetResult(peerAddr)
	if result == nil {
		return nil
	}
	return result.ExternalAddr
}

// RegisterIntroducer adds an introducer to the registry for inclusion in our
// published RouterInfo. Up to 3 introducers are maintained per the I2P spec.
func (t *SSU2Transport) RegisterIntroducer(intro *ssu2noise.RegisteredIntroducer) error {
	if t.introducerRegistry == nil {
		return ErrTransportNotStarted
	}
	return t.introducerRegistry.AddIntroducer(intro)
}

// GetIntroducers returns the current set of registered introducers that
// should be published in the router's RouterInfo.
func (t *SSU2Transport) GetIntroducers() []*ssu2noise.RegisteredIntroducer {
	if t.introducerRegistry == nil {
		return nil
	}
	return t.introducerRegistry.GetIntroducers()
}

// RemoveIntroducerByAddr removes a previously-registered introducer by its
// UDP address. No-op when the registry is uninitialised or the address is
// nil. Used by the router's hidden-mode introducer selector to drop
// disconnected peers (PLAN.md Track C2).
func (t *SSU2Transport) RemoveIntroducerByAddr(addr *net.UDPAddr) {
	if t.introducerRegistry == nil || addr == nil {
		return
	}
	t.introducerRegistry.RemoveIntroducer(addr)
}

// IntroducerFromRouterInfo builds a RegisteredIntroducer for ri using this
// transport's relay-tag allocator. Exported for use by the router-level
// introducer selector; returns the same value that RegisterIntroducer would
// accept. Allocates a relay tag as a side effect — the caller must register
// the result (or discard it) to avoid leaking allocations.
func (t *SSU2Transport) IntroducerFromRouterInfo(ri router_info.RouterInfo) (*ssu2noise.RegisteredIntroducer, error) {
	if t.relayManager == nil {
		return nil, ErrTransportNotStarted
	}
	return t.createIntroducerFromRouterInfo(ri)
}

// AllocateRelayTag allocates a relay tag for the given peer address so that
// this router can act as an introducer for that peer.
func (t *SSU2Transport) AllocateRelayTag(addr *net.UDPAddr) (uint32, error) {
	if t.relayManager == nil {
		return 0, ErrTransportNotStarted
	}
	return t.relayManager.AllocateRelayTag(addr)
}

// StartNATDetection spawns a background goroutine that performs SSU2 peer
// testing to determine our NAT type. candidates must contain at least two
// SSU2-capable RouterInfos: the first is Bob (relay peer), the second is
// Charlie (responder peer).
//
// On NAT types that require introducers (Restricted or Symmetric), up to three
// candidates are registered in the IntroducerRegistry and republish (if non-nil)
// is invoked so the caller can re-publish the updated RouterInfo.
//
// The goroutine is tracked in the transport WaitGroup and exits cleanly when
// the transport context is cancelled.
func (t *SSU2Transport) StartNATDetection(candidates []router_info.RouterInfo, republish func()) {
	if len(candidates) < 2 {
		t.logger.Warn("NAT detection skipped: need at least 2 SSU2-capable peers")
		return
	}
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		t.runNATDetection(candidates, republish)
	}()
}

// runNATDetection carries out the NAT detection sequence inside a goroutine.
func (t *SSU2Transport) runNATDetection(candidates []router_info.RouterInfo, republish func()) {
	// Extract peer addresses and establish session
	session, nonce, err := t.initiatePeerTest(candidates)
	if err != nil {
		t.logger.WithError(err).Warn("NAT detection: failed to initiate peer test")
		return
	}

	// Send PeerTest request to Bob
	charlieHash, err := candidates[1].IdentHash()
	if err != nil {
		t.logger.WithError(err).Warn("NAT detection: failed to get Charlie hash")
		return
	}
	if err := t.sendPeerTestRequest(session, nonce, charlieHash); err != nil {
		t.logger.WithError(err).Warn("NAT detection: failed to send PeerTest request")
		return
	}

	// Await response and handle result
	t.awaitPeerTestResult(nonce, candidates, republish)
}

// initiatePeerTest sets up the peer test by extracting addresses and establishing a session.
func (t *SSU2Transport) initiatePeerTest(candidates []router_info.RouterInfo) (*SSU2Session, uint32, error) {
	bobRI := candidates[0]

	bobAddr, err := ExtractSSU2Addr(bobRI)
	if err != nil {
		return nil, 0, oops.Wrapf(err, "failed to get Bob address")
	}

	// Register the test nonce
	nonce, err := t.InitiateNATDetection(bobAddr)
	if err != nil {
		return nil, 0, oops.Wrapf(err, "failed to register peer test nonce")
	}

	// Establish a session with Bob
	session, err := t.GetSession(bobRI)
	if err != nil {
		return nil, 0, oops.Wrapf(err, "failed to get session to Bob")
	}
	ssu2Session, ok := session.(*SSU2Session)
	if !ok {
		return nil, 0, oops.Errorf("session is not *SSU2Session")
	}

	return ssu2Session, nonce, nil
}

// sendPeerTestRequest builds and sends a PeerTest message to Bob.
func (t *SSU2Transport) sendPeerTestRequest(session *SSU2Session, nonce uint32, charlieHash data.Hash) error {
	ptBlock := &ssu2noise.PeerTestBlock{
		MessageCode: ssu2noise.PeerTestRequest,
		Nonce:       nonce,
		RouterHash:  &charlieHash,
		Version:     2,
		Timestamp:   uint32(time.Now().Unix()),
	}
	encoded, err := ssu2noise.EncodePeerTestBlock(ptBlock)
	if err != nil {
		return oops.Wrapf(err, "failed to encode PeerTest block")
	}
	if err := session.WriteBlocks([]*ssu2noise.SSU2Block{encoded}); err != nil {
		return oops.Wrapf(err, "failed to send PeerTest request")
	}
	t.logger.Debug("NAT detection: sent PeerTest request to Bob, awaiting Charlie probe")
	return nil
}

// awaitPeerTestResult polls for test completion and handles the NAT type result.
func (t *SSU2Transport) awaitPeerTestResult(nonce uint32, candidates []router_info.RouterInfo, republish func()) {
	const pollInterval = 2 * time.Second
	const timeout = 60 * time.Second

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	poll := time.NewTicker(pollInterval)
	defer poll.Stop()

	for t.pollPeerTestOnce(timer, poll, nonce, candidates, republish) {
	}
}

// pollPeerTestOnce handles one iteration of the peer test polling loop.
// Returns true to continue polling, false when done.
func (t *SSU2Transport) pollPeerTestOnce(timer *time.Timer, poll *time.Ticker, nonce uint32, candidates []router_info.RouterInfo, republish func()) bool {
	select {
	case <-t.ctx.Done():
		return false
	case <-timer.C:
		t.handlePeerTestTimeout(candidates, republish)
		return false
	case <-poll.C:
		return !t.checkPeerTestComplete(nonce, candidates, republish)
	}
}

// handlePeerTestTimeout handles the case where peer test timed out.
func (t *SSU2Transport) handlePeerTestTimeout(candidates []router_info.RouterInfo, republish func()) {
	t.logger.Debug("NAT detection: timed out waiting for peer test result")
	// Register candidates as introducers as a best-effort fallback
	t.registerIntroducers(candidates, republish)
}

// checkPeerTestComplete checks if the peer test is complete and processes the result.
// Returns true if the test is complete (success or failure), false if still pending.
func (t *SSU2Transport) checkPeerTestComplete(nonce uint32, candidates []router_info.RouterInfo, republish func()) bool {
	test := t.peerTestManager.GetTest(nonce)
	if test == nil || test.State != ssu2noise.TestComplete {
		return false
	}
	natType := t.classifyNATType(test)
	t.logger.WithField("nat_type", natType.String()).Info("NAT detection: peer test complete")

	// Cache result with TTL and persist to disk.
	var extStr string
	if test.ExternalAddr != nil {
		extStr = test.ExternalAddr.String()
	}
	t.natStateCache.set(natType, extStr)
	t.saveNATState()

	if natType == ssu2noise.NATRestricted || natType == ssu2noise.NATSymmetric {
		t.registerIntroducers(candidates, republish)
	} else if natType == ssu2noise.NATCone && extStr != "" && republish != nil {
		// Full-cone NAT with a detected external address: republish immediately
		// so the correct public IP is advertised without waiting for the next
		// periodic republish interval.
		republish()
	}
	return true
}

// classifyNATType determines the NAT type from a completed test.
func (t *SSU2Transport) classifyNATType(test *ssu2noise.PeerTest) ssu2noise.NATType {
	return t.peerTestManager.DetermineNATType(&ssu2noise.TestResult{
		ExternalAddr: test.ExternalAddr,
		Reachable:    test.Reachable,
		NATType:      test.NATType,
	})
}

// registerIntroducers attempts to register up to three candidates from
// candidates as introducers in the IntroducerRegistry and calls republish.
func (t *SSU2Transport) registerIntroducers(candidates []router_info.RouterInfo, republish func()) {
	registered := 0
	for _, ri := range candidates {
		if registered >= 3 {
			break
		}
		if t.tryRegisterIntroducer(ri) {
			registered++
		}
	}
	if registered > 0 {
		t.logger.WithField("introducer_count", registered).Info("NAT detection: registered introducers")
		if republish != nil {
			republish()
		}
	}
}

// tryRegisterIntroducer attempts to create and register an introducer from a RouterInfo.
// Returns true if registration succeeded.
func (t *SSU2Transport) tryRegisterIntroducer(ri router_info.RouterInfo) bool {
	intro, err := t.createIntroducerFromRouterInfo(ri)
	if err != nil {
		return false
	}
	return t.RegisterIntroducer(intro) == nil
}

// createIntroducerFromRouterInfo extracts SSU2 address and identity, allocates a relay tag,
// and builds a RegisteredIntroducer. StaticKey and IntroKey are populated from
// the peer's SSU2 RouterAddress and base64-encoded as required by
// ssu2noise.IntroducerRegistry validation (44-byte base64 of 32-byte raw keys).
func (t *SSU2Transport) createIntroducerFromRouterInfo(ri router_info.RouterInfo) (*ssu2noise.RegisteredIntroducer, error) {
	addr, err := ExtractSSU2Addr(ri)
	if err != nil {
		return nil, err
	}
	h, err := ri.IdentHash()
	if err != nil {
		return nil, err
	}
	staticRaw, err := extractRemoteStaticKey(ri)
	if err != nil {
		return nil, oops.Wrapf(err, "extract static key for introducer")
	}
	introRaw, err := ExtractSSU2IntroKey(ri)
	if err != nil {
		return nil, oops.Wrapf(err, "extract intro key for introducer")
	}
	hBytes := h.Bytes()
	tag, err := t.AllocateRelayTag(addr)
	if err != nil {
		return nil, err
	}
	return &ssu2noise.RegisteredIntroducer{
		Addr:       addr,
		RouterHash: hBytes[:],
		StaticKey:  []byte(i2pbase64.EncodeToString(staticRaw)),
		IntroKey:   []byte(i2pbase64.EncodeToString(introRaw)),
		RelayTag:   tag,
		AddedAt:    time.Now(),
		LastSeen:   time.Now(),
	}, nil
}

// maybeAutoInitiatePeerTest fires a best-effort PeerTest towards a newly
// connected peer for the first startupPeerTestMax connections. This
// implements the D3 startup probe: 3 peers report our external address so
// the majority-confirmation logic can confirm and republish it.
func (t *SSU2Transport) maybeAutoInitiatePeerTest(remote net.Addr) {
	const startupPeerTestMax = 3
	if t.peerTestManager == nil {
		return
	}
	if atomic.AddInt32(&t.startupPeerTestCount, 1) > startupPeerTestMax {
		atomic.AddInt32(&t.startupPeerTestCount, -1) // don't overflow
		return
	}
	udpAddr, ok := remote.(*net.UDPAddr)
	if !ok {
		// Try SSU2Addr unwrapping.
		if ssu2a, ok2 := remote.(*ssu2noise.SSU2Addr); ok2 {
			if u := ssu2a.UnderlyingAddr(); u != nil {
				udpAddr, _ = u.(*net.UDPAddr)
			}
		}
	}
	if udpAddr == nil {
		return
	}
	go func() {
		if _, err := t.peerTestManager.InitiatePeerTest(udpAddr); err != nil {
			t.logger.WithField("error", err).Debug("startup PeerTest initiation failed (non-fatal)")
		}
	}()
}

// startNATPortMapRetry launches a background goroutine that periodically
// re-attempts UPnP/NAT-PMP port mapping using exponential back-off
// (initial 30 s, doubling each failure, capped at 30 min). On success the
// external address is logged at INFO level and the goroutine exits. Each
// failed attempt is logged at DEBUG level together with the gateway address
// to allow diagnostic correlation. The goroutine exits when t.ctx is
// cancelled (i.e., when the transport is closed).
func (t *SSU2Transport) startNATPortMapRetry() {
	if t.config == nil {
		return
	}
	// Extract the internal port from the currently bound address.
	_, portStr, err := net.SplitHostPort(t.config.ListenerAddress)
	if err != nil {
		return
	}
	internalPort, err := strconv.Atoi(portStr)
	if err != nil || internalPort <= 0 {
		return
	}
	// Don't run on loopback.
	host, _, _ := net.SplitHostPort(t.config.ListenerAddress)
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return
	}

	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		backoff := natRetryInitial
		for {
			select {
			case <-t.ctx.Done():
				return
			case <-time.After(backoff):
			}

			mapCtx, mapCancel := context.WithTimeout(t.ctx, 5*time.Second)
			mapper, err := nattraversal.NewPortMapperContext(mapCtx)
			mapCancel()
			if err != nil {
				t.reachMetrics.natMappingFailure.Add(1)
				t.logger.WithFields(map[string]interface{}{
					"error":   err,
					"backoff": backoff.String(),
				}).Debug("NAT-PMP/UPnP port mapper unavailable; will retry")
				if backoff < natRetryMax {
					backoff *= 2
					if backoff > natRetryMax {
						backoff = natRetryMax
					}
				}
				continue
			}

			gwIP, err := mapper.GetExternalIP()
			t.logger.WithFields(map[string]interface{}{
				"gateway": gwIP,
				"port":    internalPort,
			}).Debug("NAT-PMP retry: attempting port mapping")

			_, err = mapper.MapPort("udp", internalPort, 1*time.Hour)
			if err != nil {
				t.reachMetrics.natMappingFailure.Add(1)
				t.logger.WithFields(map[string]interface{}{
					"error":   err,
					"gateway": gwIP,
					"backoff": backoff.String(),
				}).Debug("NAT-PMP port mapping failed; will retry")
				if backoff < natRetryMax {
					backoff *= 2
					if backoff > natRetryMax {
						backoff = natRetryMax
					}
				}
				continue
			}
			t.reachMetrics.natMappingSuccess.Add(1)
			extIP, _ := mapper.GetExternalIP()
			t.logger.WithFields(map[string]interface{}{
				"external_ip":   extIP,
				"internal_port": internalPort,
			}).Info("NAT-PMP/UPnP port mapping succeeded")
			return // success — no need to retry further
		}
	}()
}
