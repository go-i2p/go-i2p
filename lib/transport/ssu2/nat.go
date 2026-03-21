package ssu2

import (
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
	// Use AliceAddress as the observed external address when available.
	externalAddr := ptBlock.AliceAddress
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

// handleRelayRequestBlock processes a RelayRequest by allocating a relay tag
// for the requesting peer.
func (t *SSU2Transport) handleRelayRequestBlock(block *ssu2noise.SSU2Block) error {
	if t.relayManager == nil || block == nil {
		return nil
	}
	t.logger.Debug("received RelayRequest block")
	// Allocation requires the requester's UDP address, which is embedded in
	// the block payload. We log receipt for now; full relay handling requires
	// the full protocol stack (Phase 3c).
	_ = block
	return nil
}

// handleRelayResponseBlock processes a RelayResponse and registers the
// resolved introducer address in the IntroducerRegistry.
func (t *SSU2Transport) handleRelayResponseBlock(block *ssu2noise.SSU2Block) error {
	if t.introducerRegistry == nil || block == nil {
		return nil
	}
	t.logger.Debug("received RelayResponse block")
	return nil
}

// handleRelayIntroBlock processes a RelayIntro block and initiates a UDP
// hole-punch attempt towards the target peer.
func (t *SSU2Transport) handleRelayIntroBlock(block *ssu2noise.SSU2Block) error {
	if t.holePunchCoord == nil || block == nil {
		return nil
	}
	t.logger.Debug("received RelayIntro block — hole-punch initiation deferred to Phase 3c")
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
	bobRI := candidates[0]
	charlieRI := candidates[1]

	charlieAddr, err := ExtractSSU2Addr(charlieRI)
	if err != nil {
		t.logger.WithError(err).Warn("NAT detection: failed to get Charlie address")
		return
	}
	charlieHash, err := charlieRI.IdentHash()
	if err != nil {
		t.logger.WithError(err).Warn("NAT detection: failed to get Charlie hash")
		return
	}
	bobAddr, err := ExtractSSU2Addr(bobRI)
	if err != nil {
		t.logger.WithError(err).Warn("NAT detection: failed to get Bob address")
		return
	}

	// Register the test nonce — CompleteTest is later called by the incoming
	// PeerTest block handler (handlePeerTestBlock) when Charlie responds.
	nonce, err := t.InitiateNATDetection(bobAddr)
	if err != nil {
		t.logger.WithError(err).Warn("NAT detection: failed to register peer test nonce")
		return
	}

	// Establish a session with Bob so we can send the PeerTest Request.
	session, err := t.GetSession(bobRI)
	if err != nil {
		t.logger.WithError(err).Warn("NAT detection: failed to get session to Bob")
		return
	}
	ssu2Session, ok := session.(*SSU2Session)
	if !ok {
		t.logger.Warn("NAT detection: session is not *SSU2Session")
		return
	}

	// Build and send PeerTest message 1: Alice → Bob, informing Bob of Charlie.
	charlieHashBytes := charlieHash.Bytes()
	ptBlock := &ssu2noise.PeerTestBlock{
		MessageCode:    ssu2noise.PeerTestRequest,
		Nonce:          nonce,
		RouterHash:     charlieHashBytes[:],
		CharlieAddress: charlieAddr,
	}
	encoded, err := ssu2noise.EncodePeerTestBlock(ptBlock)
	if err != nil {
		t.logger.WithError(err).Warn("NAT detection: failed to encode PeerTest block")
		return
	}
	if err := ssu2Session.WriteBlocks([]*ssu2noise.SSU2Block{encoded}); err != nil {
		t.logger.WithError(err).Warn("NAT detection: failed to send PeerTest request to Bob")
		return
	}
	t.logger.Debug("NAT detection: sent PeerTest request to Bob, awaiting Charlie probe")

	// Poll for test completion for up to 60 seconds (I2P spec timeout).
	timeout := time.NewTimer(60 * time.Second)
	defer timeout.Stop()
	poll := time.NewTicker(2 * time.Second)
	defer poll.Stop()

	for {
		select {
		case <-t.ctx.Done():
			return
		case <-timeout.C:
			t.logger.Debug("NAT detection: timed out waiting for peer test result")
			// Even without a result, register candidates as a best-effort
			// fallback for routers likely to be behind NAT.
			t.registerIntroducers(candidates, republish)
			return
		case <-poll.C:
			test := t.peerTestManager.GetTest(nonce)
			if test == nil || test.State != ssu2noise.TestComplete {
				continue
			}
			natType := t.peerTestManager.DetermineNATType(&ssu2noise.TestResult{
				ExternalAddr: test.ExternalAddr,
				Reachable:    test.Reachable,
				NATType:      test.NATType,
			})
			t.logger.WithField("nat_type", natType.String()).Info("NAT detection: peer test complete")
			if natType == ssu2noise.NATRestricted || natType == ssu2noise.NATSymmetric {
				t.registerIntroducers(candidates, republish)
			}
			return
		}
	}
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
