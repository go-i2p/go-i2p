package ssu2

import (
	"fmt"
	"net"
	"time"

	"github.com/go-i2p/common/router_info"
	ssu2noise "github.com/go-i2p/go-noise/ssu2"
)

// initNATManagers allocates and wires the PeerTestManager, RelayManager,
// IntroducerRegistry, and HolePunchCoordinator on a freshly started transport.
// Must be called after t.listener is initialised.
func initNATManagers(t *SSU2Transport) {
	t.relayManager = ssu2noise.NewRelayManager(t.listener)
	t.introducerRegistry = ssu2noise.NewIntroducerRegistry(3)
	t.holePunchCoord = ssu2noise.NewHolePunchCoordinator(t.relayManager)
	t.peerTestManager = ssu2noise.NewPeerTestManager(t.listener)
}

// buildTransportCallbacks returns a BlockCallbackConfig whose handlers delegate
// to the transport's NAT managers. Sessions call this to supplement their own
// local callbacks (termination, clock validation).
func (t *SSU2Transport) buildTransportCallbacks() *BlockCallbackConfig {
	return &BlockCallbackConfig{
		OnPeerTest: func(block *ssu2noise.SSU2Block) error {
			return t.handlePeerTestBlock(block)
		},
		OnRelayRequest: func(block *ssu2noise.SSU2Block) error {
			return t.handleRelayRequestBlock(block)
		},
		OnRelayResponse: func(block *ssu2noise.SSU2Block) error {
			return t.handleRelayResponseBlock(block)
		},
		OnRelayIntro: func(block *ssu2noise.SSU2Block) error {
			return t.handleRelayIntroBlock(block)
		},
	}
}

// handlePeerTestBlock processes an incoming PeerTest block and stores the
// result for NAT-type determination.
func (t *SSU2Transport) handlePeerTestBlock(block *ssu2noise.SSU2Block) error {
	if t.peerTestManager == nil {
		return nil
	}
	ptBlock, err := ssu2noise.DecodePeerTestBlock(block)
	if err != nil {
		t.logger.WithField("error", err).Warn("failed to decode PeerTest block")
		return err
	}
	nonce := ptBlock.Nonce
	// Reconstruct the observed external address from AliceIP + AlicePort when available.
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
		// Test may not exist if we are acting as relay/responder; ignore.
		t.logger.WithField("nonce", nonce).Debug("PeerTest complete (non-initiator path)")
	}
	return nil
}

// handleRelayRequestBlock processes a RelayRequest from Alice (we are Bob).
// It decodes the request, validates the relay tag, and forwards a RelayIntro
// to Charlie via the session associated with the relay tag.
func (t *SSU2Transport) handleRelayRequestBlock(block *ssu2noise.SSU2Block) error {
	if t.relayManager == nil || block == nil {
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
func (t *SSU2Transport) forwardRelayIntro(req *ssu2noise.RelayRequestBlock) error {
	tag := t.relayManager.GetRelayTag(req.RelayTag)
	if tag == nil {
		t.logger.WithField("relay_tag", req.RelayTag).Warn("relay tag not found")
		return nil
	}
	intro := buildRelayIntro(req)
	session := t.findSessionByAddr(tag.ForAddr)
	if session == nil {
		t.logger.Warn("no session to relay target")
		return nil
	}
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
// It decodes the response and completes the pending hole-punch session
// when the relay was successful.
func (t *SSU2Transport) handleRelayResponseBlock(block *ssu2noise.SSU2Block) error {
	if t.relayManager == nil || block == nil {
		return nil
	}
	resp, err := ssu2noise.DecodeRelayResponse(block)
	if err != nil {
		t.logger.WithField("error", err).Warn("failed to decode RelayResponse")
		return nil
	}
	if resp.Code != 0 {
		t.logger.WithField("status", resp.Code).Debug("relay response indicates failure")
		return nil
	}
	t.logger.WithField("nonce", resp.Nonce).Debug("relay response success")
	return nil
}

// handleRelayIntroBlock processes a RelayIntro (we are Charlie). It decodes
// the intro and initiates a hole-punch towards Alice using the coordinates
// embedded in the block.
func (t *SSU2Transport) handleRelayIntroBlock(block *ssu2noise.SSU2Block) error {
	if t.holePunchCoord == nil || block == nil {
		return nil
	}
	intro, err := ssu2noise.DecodeRelayIntro(block)
	if err != nil {
		t.logger.WithField("error", err).Warn("failed to decode RelayIntro")
		return nil
	}
	return t.initiateHolePunch(intro)
}

// initiateHolePunch starts a hole-punch towards Alice based on a RelayIntro.
func (t *SSU2Transport) initiateHolePunch(intro *ssu2noise.RelayIntroBlock) error {
	aliceAddr := &net.UDPAddr{
		IP:   net.IP(intro.AliceIP),
		Port: int(intro.AlicePort),
	}
	_, err := t.holePunchCoord.InitiateHolePunch(aliceAddr, nil, intro.AliceRelayTag)
	if err != nil {
		t.logger.WithField("error", err).Warn("hole-punch initiation failed")
		return err
	}
	t.logger.WithField("alice_addr", aliceAddr).Debug("hole-punch initiated towards Alice")
	return nil
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
	charlieHashBytes := charlieHash.Bytes()
	if err := t.sendPeerTestRequest(session, nonce, charlieHashBytes[:]); err != nil {
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
		return nil, 0, fmt.Errorf("failed to get Bob address: %w", err)
	}

	// Register the test nonce
	nonce, err := t.InitiateNATDetection(bobAddr)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to register peer test nonce: %w", err)
	}

	// Establish a session with Bob
	session, err := t.GetSession(bobRI)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get session to Bob: %w", err)
	}
	ssu2Session, ok := session.(*SSU2Session)
	if !ok {
		return nil, 0, fmt.Errorf("session is not *SSU2Session")
	}

	return ssu2Session, nonce, nil
}

// sendPeerTestRequest builds and sends a PeerTest message to Bob.
func (t *SSU2Transport) sendPeerTestRequest(session *SSU2Session, nonce uint32, charlieHash []byte) error {
	ptBlock := &ssu2noise.PeerTestBlock{
		MessageCode: ssu2noise.PeerTestRequest,
		Nonce:       nonce,
		RouterHash:  charlieHash[:],
		Version:     2,
		Timestamp:   uint32(time.Now().Unix()),
	}
	encoded, err := ssu2noise.EncodePeerTestBlock(ptBlock)
	if err != nil {
		return fmt.Errorf("failed to encode PeerTest block: %w", err)
	}
	if err := session.WriteBlocks([]*ssu2noise.SSU2Block{encoded}); err != nil {
		return fmt.Errorf("failed to send PeerTest request: %w", err)
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

	for {
		select {
		case <-t.ctx.Done():
			return
		case <-timer.C:
			t.handlePeerTestTimeout(candidates, republish)
			return
		case <-poll.C:
			if t.checkPeerTestComplete(nonce, candidates, republish) {
				return
			}
		}
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
	if natType == ssu2noise.NATRestricted || natType == ssu2noise.NATSymmetric {
		t.registerIntroducers(candidates, republish)
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
		addr, err := ExtractSSU2Addr(ri)
		if err != nil {
			continue
		}
		h, err := ri.IdentHash()
		if err != nil {
			continue
		}
		hBytes := h.Bytes()
		tag, err := t.AllocateRelayTag(addr)
		if err != nil {
			continue
		}
		intro := &ssu2noise.RegisteredIntroducer{
			Addr:       addr,
			RouterHash: hBytes[:],
			RelayTag:   tag,
			AddedAt:    time.Now(),
			LastSeen:   time.Now(),
		}
		if err := t.RegisterIntroducer(intro); err == nil {
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
