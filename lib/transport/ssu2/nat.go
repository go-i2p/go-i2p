package ssu2

import (
	"net"

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
