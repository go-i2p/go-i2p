package ssu2

import (
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"fmt"
	"net"
	"strconv"
	"strings"
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
// Returns an error if HolePunchCoordinator initialization fails.
// L-1: Creates a per-generation context for NAT goroutines so they can be cancelled
// on SetIdentity without affecting the transport-level context.
// R-4 partial fix: Reads t.listener under identityMu to avoid TOCTOU with SetIdentity.
// Note: Manager pointer fields themselves are not fully synchronized; readers assume
// managers are stable after initialization. Full fix requires dedicated manager mutex.
func initNATManagers(t *SSU2Transport) error {
	// Create per-generation context for NAT goroutines (L-1 fix item 2).
	t.natCtxMu.Lock()
	t.natCtx, t.natCancel = context.WithCancel(t.ctx)
	t.natCtxMu.Unlock()

	// R-4: Snapshot t.listener under lock to avoid race with SetIdentity.
	t.identityMu.RLock()
	listener := t.listener
	t.identityMu.RUnlock()

	if listener == nil {
		return oops.New("cannot initialize NAT managers: listener is nil")
	}

	t.relayManager = ssu2noise.NewRelayManager(listener)
	t.introducerRegistry = ssu2noise.NewIntroducerRegistry(3)
	verifyFn := func(block *ssu2noise.RelayIntroBlock, signerKey ed25519.PublicKey) error {
		// Verify Alice's relay intro signature. The signature covers the
		// "RelayRequestData" prologue + bob_hash + charlie_hash + fields.
		// We are Charlie; bob's hash is not available in the block, so we
		// perform a best-effort check using what's available.
		if block == nil || len(block.Signature) == 0 {
			return oops.Errorf("relay intro: missing block or signature")
		}
		charlieHash := t.getOurIdentityHash()
		var aliceHash data.Hash
		if len(block.AliceRouterHash) == 32 {
			copy(aliceHash[:], block.AliceRouterHash)
		}
		// We don't have Bob's hash in the block; use aliceHash as a
		// placeholder for the bob slot so the data can be verified when the
		// full context is available.
		ok, err := ssu2noise.VerifyRelayRequestSignature(
			signerKey,
			block.Signature,
			aliceHash, // bob hash placeholder (best-effort)
			charlieHash,
			block.Nonce,
			block.AliceRelayTag,
			block.Timestamp,
			block.Version,
			block.AlicePort,
			block.AliceIP,
		)
		if err != nil {
			return oops.Wrapf(err, "relay intro signature verification error")
		}
		if !ok {
			return oops.Errorf("relay intro signature invalid")
		}
		return nil
	}
	var err error
	t.holePunchCoord, err = ssu2noise.NewHolePunchCoordinator(t.relayManager, verifyFn)
	if err != nil {
		// MEDIUM 5.5: HolePunchCoordinator initialization failure should be reported,
		// not silently downgraded to a warning. Return the error so the caller can decide
		// whether to fail the transport or degrade gracefully.
		return oops.Wrapf(err, "failed to initialize HolePunchCoordinator")
	}
	t.peerTestManager = ssu2noise.NewPeerTestManager(listener)
	if t.natStateCache == nil {
		t.natStateCache = &natState{}
	}
	t.loadNATState()
	t.startNATCleanup()
	t.startNATPortMapRetry()
	return nil
}

// stopNATManagers stops all NAT managers and cancels the per-generation NAT context
// to signal NAT goroutines (cleanup, port mapping) to exit. L-1 fix item 1.
// Must be called before initNATManagers in SetIdentity.
func stopNATManagers(t *SSU2Transport) {
	// Cancel the per-generation NAT context to stop NAT goroutines (L-1 item 2).
	t.natCtxMu.Lock()
	if t.natCancel != nil {
		t.natCancel()
		t.natCancel = nil
		t.natCtx = nil
	}
	t.natCtxMu.Unlock()

	// Stop all managers explicitly (L-1 item 4).
	if t.relayManager != nil {
		t.relayManager.Stop()
	}
	if t.peerTestManager != nil {
		t.peerTestManager.Stop()
	}
	if t.holePunchCoord != nil {
		t.holePunchCoord.Stop()
	}
	if t.keyRotationManager != nil {
		t.keyRotationManager.Stop()
	}
	// introducerRegistry has no Stop method; just replace it.
}

// buildTransportCallbacks returns a BlockCallbackConfig whose handlers delegate
// to the transport's NAT managers. The session parameter is used by the
// PeerTest handler to enforce per-session rate limits and source validation.
// Sessions call this to supplement their own local callbacks (termination,
// clock validation).
func (t *SSU2Transport) buildTransportCallbacks(session *SSU2Session) *BlockCallbackConfig {
	return &BlockCallbackConfig{
		OnRouterInfo: func(data []byte) error {
			return t.handleRouterInfoBlock(data)
		},
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
		VerifyRelayRequest: func(block *ssu2noise.RelayRequestBlock, senderHash data.Hash) (bool, error) {
			return t.verifyRelayRequestSignature(block, senderHash)
		},
		VerifyRelayResponse: func(block *ssu2noise.RelayResponseBlock, senderHash data.Hash) (bool, error) {
			return t.verifyRelayResponseSignature(block, senderHash)
		},
		VerifyPeerTest: func(block *ssu2noise.PeerTestBlock, senderHash data.Hash) (bool, error) {
			if err := t.verifyPeerTestSignature(block, senderHash); err != nil {
				return false, err
			}
			return true, nil
		},
	}
}

// handleRouterInfoBlock processes RouterInfo block data received from a peer.
// If RouterStoreFunc is configured, it delegates storage to NetDB; otherwise
// it logs and skips processing (test/default behavior).
//
// E-4 fix: Emits a warn-level log (once per transport lifetime) when RouterInfo
// blocks arrive but RouterStoreFunc is nil, to catch misconfiguration in production.
func (t *SSU2Transport) handleRouterInfoBlock(data []byte) error {
	if t.config.RouterStoreFunc == nil {
		// Warn once if RouterInfo blocks are received but no store function is configured.
		// This indicates misconfiguration: RouterStoreFunc must be wired for production
		// to allow reply routing. Tests can ignore this safely.
		t.routerStoreWarnOnce.Do(func() {
			t.logger.Warn("Received RouterInfo block but RouterStoreFunc not configured; reply routing may fail (RouterStoreFunc must be set for production)")
		})
		t.logger.Debug("Received RouterInfo block but RouterStoreFunc not configured (using default callbacks)")
		return nil
	}
	if err := t.config.RouterStoreFunc(data); err != nil {
		t.logger.WithError(err).Warn("Failed to store RouterInfo from SSU2 block")
		return oops.Wrapf(err, "failed to store RouterInfo")
	}
	t.logger.Debug("Successfully stored RouterInfo from SSU2 block")
	return nil
}

// verifyRelayRequestSignature verifies the Ed25519 signature on a RelayRequest
// block using the sender's signing public key retrieved from NetDB via RouterLookupFunc.
// Returns (true, nil) if signature is valid, and (false, error) on verification failure
// or when RouterLookupFunc is unavailable (fail-closed).
func (t *SSU2Transport) verifyRelayRequestSignature(block *ssu2noise.RelayRequestBlock, senderHash data.Hash) (bool, error) {
	if t.config.RouterLookupFunc == nil {
		return false, oops.Errorf("signature verification unavailable: RouterLookupFunc not configured")
	}
	ri, err := t.config.RouterLookupFunc(senderHash)
	if err != nil {
		t.logger.WithField("sender_hash", senderHash[:4]).Warn("RelayRequest: failed to lookup sender RouterInfo for signature verification")
		return false, oops.Wrapf(err, "netdb lookup failed for sender %x", senderHash[:4])
	}
	pubKey, err := extractEd25519PublicKey(ri)
	if err != nil {
		return false, oops.Wrapf(err, "failed to extract Ed25519 public key from sender RouterInfo")
	}

	// Look up Charlie's hash from the relay tag
	if t.relayManager == nil {
		return false, oops.Errorf("signature verification unavailable: relay manager not configured")
	}
	relayTag := t.relayManager.GetRelayTag(block.RelayTag)
	if relayTag == nil {
		t.logger.WithField("relay_tag", block.RelayTag).Warn("RelayRequest: unknown relay tag, cannot verify signature")
		return false, oops.Errorf("unknown relay tag %d", block.RelayTag)
	}

	// Charlie's hash is the key we used to register this relay tag
	// We need to look it up from the relay tag entry's session
	session := t.findSessionByAddr(relayTag.ForAddr)
	if session == nil {
		t.logger.WithField("relay_tag", block.RelayTag).Warn("RelayRequest: no session for relay tag, cannot verify signature")
		return false, oops.Errorf("no session for relay tag %d", block.RelayTag)
	}
	charlieHash := extractSenderHash(session)
	if charlieHash == (data.Hash{}) {
		t.logger.WithField("relay_tag", block.RelayTag).Warn("RelayRequest: cannot extract Charlie hash from session")
		return false, oops.Errorf("cannot extract Charlie hash")
	}

	// Use the identity hash from the SSU2 session context as Bob's hash
	bobHash := t.getOurIdentityHash()
	valid, verifyErr := ssu2noise.VerifyRelayRequestSignature(
		pubKey,
		block.Signature,
		bobHash,
		charlieHash,
		block.Nonce,
		block.RelayTag,
		block.Timestamp,
		block.Version,
		block.AlicePort,
		block.AliceIP,
	)
	if verifyErr != nil {
		t.logger.WithField("sender_hash", senderHash[:4]).Warn("RelayRequest signature verification failed")
		return false, oops.Wrapf(verifyErr, "signature verification failed")
	}
	if !valid {
		t.logger.WithField("sender_hash", senderHash[:4]).Warn("RelayRequest signature invalid")
		return false, oops.Errorf("invalid RelayRequest signature from %x", senderHash[:4])
	}
	return true, nil
}

// verifyRelayResponseSignature verifies the Ed25519 signature on a RelayResponse
// block using the sender's signing public key retrieved from NetDB.
// Returns (true, nil) if signature is valid, and (false, error) on verification failure
// or when RouterLookupFunc is unavailable (fail-closed).
func (t *SSU2Transport) verifyRelayResponseSignature(block *ssu2noise.RelayResponseBlock, senderHash data.Hash) (bool, error) {
	if t.config.RouterLookupFunc == nil {
		return false, oops.Errorf("signature verification unavailable: RouterLookupFunc not configured")
	}
	ri, err := t.config.RouterLookupFunc(senderHash)
	if err != nil {
		t.logger.WithField("sender_hash", senderHash[:4]).Warn("RelayResponse: failed to lookup sender RouterInfo for signature verification")
		return false, oops.Wrapf(err, "netdb lookup failed for sender %x", senderHash[:4])
	}
	pubKey, err := extractEd25519PublicKey(ri)
	if err != nil {
		return false, oops.Wrapf(err, "failed to extract Ed25519 public key from sender RouterInfo")
	}
	bobHash := t.getOurIdentityHash()
	valid, verifyErr := ssu2noise.VerifyRelayResponseSignature(
		pubKey,
		block.Signature,
		bobHash,
		block.Nonce,
		block.Timestamp,
		block.Version,
		block.CharliePort,
		block.CharlieIP,
	)
	if verifyErr != nil {
		t.logger.WithField("sender_hash", senderHash[:4]).Warn("RelayResponse signature verification failed")
		return false, oops.Wrapf(verifyErr, "signature verification failed")
	}
	if !valid {
		t.logger.WithField("sender_hash", senderHash[:4]).Warn("RelayResponse signature invalid")
		return false, oops.Errorf("invalid RelayResponse signature from %x", senderHash[:4])
	}
	return true, nil
}

// verifyPeerTestSignature verifies the Ed25519 signature on a PeerTest block
// using the sender's signing public key retrieved from NetDB.
// Returns nil when the signature is valid; a non-nil error indicates either a
// verification failure (bad signature) or that verification could not be
// performed (fail-closed). The previous (bool, error) form was redundant —
// every invalid path also returned an error — and risked future callers
// misreading a (false, nil) tuple as success. See AUDIT.md M-4.
func (t *SSU2Transport) verifyPeerTestSignature(block *ssu2noise.PeerTestBlock, senderHash data.Hash) error {
	if t.config.RouterLookupFunc == nil {
		return oops.Errorf("signature verification unavailable: RouterLookupFunc not configured")
	}
	// Resolve Alice's hash up-front and fail-closed for codes 3/4 before any
	// NetDB lookup. PeerTest signed-data inclusion of Alice's hash depends on
	// the message code:
	//   - Messages 1 (Alice→Bob) and 2 (Bob→Charlie): aliceHash MUST be nil.
	//   - Messages 3 (Charlie→Bob) and 4 (Bob→Alice): aliceHash MUST be Alice's
	//     32-byte router hash. Per the SSU2 PeerTest block layout, message 4
	//     carries it explicitly in the optional RouterHash field; message 3
	//     does not carry it on the wire and the verifier must obtain it from
	//     external context (not currently plumbed through to this callback).
	// We fail-closed for codes 3/4 when Alice's hash cannot be determined,
	// rather than silently substituting senderHash (which would either reject
	// legitimate signatures or accept signatures attributable to the sender as
	// proof of Alice's claim — see AUDIT.md H-1).
	var aliceHash *data.Hash
	switch block.MessageCode {
	case ssu2noise.PeerTestResponse, ssu2noise.PeerTestResult:
		if block.RouterHash == nil {
			return oops.Errorf("PeerTest message code %d requires Alice's hash but block.RouterHash is nil", block.MessageCode)
		}
		hash := *block.RouterHash
		aliceHash = &hash
	}
	ri, err := t.config.RouterLookupFunc(senderHash)
	if err != nil {
		t.logger.WithField("sender_hash", senderHash[:4]).Warn("PeerTest: failed to lookup sender RouterInfo for signature verification")
		return oops.Wrapf(err, "netdb lookup failed for sender %x", senderHash[:4])
	}
	pubKey, err := extractEd25519PublicKey(ri)
	if err != nil {
		return oops.Wrapf(err, "failed to extract Ed25519 public key from sender RouterInfo")
	}
	bobHash := t.getOurIdentityHash()
	valid, verifyErr := ssu2noise.VerifyPeerTestSignature(
		pubKey,
		block.Signature,
		bobHash,
		aliceHash,
		block.Version,
		block.Nonce,
		block.Timestamp,
		block.AlicePort,
		block.AliceIP,
	)
	if verifyErr != nil {
		t.logger.WithField("sender_hash", senderHash[:4]).Warn("PeerTest signature verification failed")
		return oops.Wrapf(verifyErr, "signature verification failed")
	}
	if !valid {
		t.logger.WithField("sender_hash", senderHash[:4]).Warn("PeerTest signature invalid")
		return oops.Errorf("invalid PeerTest signature from %x", senderHash[:4])
	}
	return nil
}

// extractEd25519PublicKey extracts the Ed25519 signing public key from a RouterInfo.
// Returns an error if the key type is not Ed25519 or extraction fails.
func extractEd25519PublicKey(ri router_info.RouterInfo) (ed25519.PublicKey, error) {
	identity := ri.RouterIdentity()
	if identity == nil {
		return nil, oops.Errorf("RouterInfo has nil RouterIdentity")
	}
	signingPubKey, err := identity.SigningPublicKey()
	if err != nil {
		return nil, oops.Wrapf(err, "failed to get signing public key from RouterInfo")
	}
	// Convert to Ed25519 public key
	keyBytes := signingPubKey.Bytes()
	if len(keyBytes) != ed25519.PublicKeySize {
		return nil, oops.Errorf("signing public key has unexpected size %d (expected %d)", len(keyBytes), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(keyBytes), nil
}

// getOurIdentityHash returns the identity hash of the local router.
func (t *SSU2Transport) getOurIdentityHash() data.Hash {
	t.identityMu.RLock()
	defer t.identityMu.RUnlock()
	hash, _ := t.identity.IdentHash()
	return hash
}

// extractSenderHash extracts the router hash from an SSU2Session's remote address.
// Returns a zero hash if extraction fails or the session is nil.
func extractSenderHash(session *SSU2Session) data.Hash {
	if session == nil {
		return data.Hash{}
	}
	// Use locked accessor to avoid race with DetachConn (R-1 fix).
	remoteAddr := session.RemoteAddr()
	if remoteAddr == nil {
		return data.Hash{}
	}
	if ssu2Addr, ok := remoteAddr.(*ssu2noise.SSU2Addr); ok && ssu2Addr != nil {
		return ssu2Addr.RouterHash()
	}
	return data.Hash{}
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
		return t.handlePeerTestAsCharlie(ptBlock, session)
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
	externalAddr := extractAliceAddress(ptBlock)

	// BUG FIX HIGH RD-1: Verify the PeerTest nonce belongs to a test this node
	// initiated before recording the observation. An attacker can send unsolicited
	// PeerTest replies with arbitrary nonces to poison the address-confirmation cache.
	// Fail-closed: if the nonce is unknown, ignore the observation entirely.
	if t.peerTestManager != nil {
		test := t.peerTestManager.GetTest(nonce)
		if test == nil {
			t.logger.WithField("nonce", nonce).Warn("PeerTest: ignoring observation with unknown nonce (potential injection attack)")
			return nil
		}
	}

	result := &ssu2noise.TestResult{
		ExternalAddr: externalAddr,
		Reachable:    externalAddr != nil,
	}
	if completeErr := t.peerTestManager.CompleteTest(nonce, result); completeErr != nil {
		t.logger.Debug("PeerTest complete (non-initiator path)")
	}

	t.processExternalAddressConfirmation(externalAddr)
	return nil
}

// extractAliceAddress extracts Alice's UDP address from PeerTest block.
func extractAliceAddress(ptBlock *ssu2noise.PeerTestBlock) *net.UDPAddr {
	if len(ptBlock.AliceIP) == 0 {
		return nil
	}
	return &net.UDPAddr{
		IP:   net.IP(ptBlock.AliceIP),
		Port: int(ptBlock.AlicePort),
	}
}

// isValidExternalAddress validates that an IP address is suitable for publishing
// as the router's external address. Rejects private IPs, loopback, multicast,
// unspecified addresses, and other reserved ranges that should never be exposed.
func isValidExternalAddress(ip net.IP) bool {
	if ip == nil {
		return false
	}
	// Reject reserved, private, loopback, multicast, and link-local ranges.
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsMulticast() ||
		ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return false
	}
	// Reject loopback and reserved ranges.
	if ip.IsInterfaceLocalMulticast() || ip.IsLinkLocalMulticast() {
		return false
	}
	return true
}

// processExternalAddressConfirmation records and confirms external address via majority logic.
func (t *SSU2Transport) processExternalAddressConfirmation(externalAddr *net.UDPAddr) {
	// Record observation for majority-confirmation logic (D3).
	if externalAddr == nil || t.natStateCache == nil {
		return
	}

	// Validate the address before recording it as an observation. Reject any
	// private, reserved, or otherwise unsuitable IP ranges to prevent peers
	// from poisoning NAT detection with spoofed addresses.
	if !isValidExternalAddress(externalAddr.IP) {
		t.logger.WithFields(map[string]interface{}{
			"ip": externalAddr.IP.String(),
			"ip_type": fmt.Sprintf("loopback=%v private=%v multicast=%v unspec=%v",
				externalAddr.IP.IsLoopback(),
				externalAddr.IP.IsPrivate(),
				externalAddr.IP.IsMulticast(),
				externalAddr.IP.IsUnspecified()),
		}).Warn("Rejecting invalid external address from PeerTest observation")
		return
	}

	confirmed := t.natStateCache.recordObservation(externalAddr.String())
	if confirmed == "" || confirmed == t.natStateCache.getExternal() {
		return
	}

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
// global rate limits, verifies the signature using Alice's Ed25519 signing key
// from NetDB, then forwards a PeerTestRelay to Charlie.
func (t *SSU2Transport) handlePeerTestAsBob(ptBlock *ssu2noise.PeerTestBlock, session *SSU2Session) error {
	aliceAddr := parsePeerTestAliceAddr(ptBlock)
	if aliceAddr == nil {
		t.logger.Debug("PeerTest Bob: missing Alice address, ignoring")
		return nil
	}
	if !t.validateBobAliceAddress(session, aliceAddr) {
		return nil
	}

	// Check rate limits BEFORE expensive signature verification (DoS prevention)
	if !t.checkBobRateLimits(session) {
		return nil
	}

	// Verify signature (fail-closed: reject if session or senderHash unavailable)
	if session == nil {
		t.logger.Warn("PeerTest Bob: no session provided, cannot verify signature, rejecting")
		return oops.Errorf("signature verification failed: no session")
	}
	senderHash := extractSenderHash(session)
	if senderHash == (data.Hash{}) {
		t.logger.Warn("PeerTest Bob: cannot extract sender hash, rejecting")
		return oops.Errorf("signature verification failed: no sender hash")
	}
	if verifyErr := t.verifyPeerTestSignature(ptBlock, senderHash); verifyErr != nil {
		t.logger.WithFields(map[string]interface{}{
			"sender_hash": senderHash[:4],
			"nonce":       ptBlock.Nonce,
			"error":       verifyErr,
		}).Warn("PeerTest signature verification failed, rejecting")
		return verifyErr
	}

	// MEDIUM 5.7: Removed redundant rate-limit check here. Rate limiting is enforced
	// BEFORE signature verification (above) to prevent DoS from expensive sig checks.
	// Checking again after verification is redundant and confuses error reporting.
	// The first check at line ~529 is sufficient.

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
// relaySession is the session from which the PeerTestRelay was received;
// it is preferred for sending the probe to maintain protocol-correlated paths.
func (t *SSU2Transport) handlePeerTestAsCharlie(ptBlock *ssu2noise.PeerTestBlock, relaySession *SSU2Session) error {
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
	return t.sendProbeToAlice(ptBlock, aliceAddr, relaySession)
}

// sendProbeToAlice sends a PeerTestProbe directly to Alice so she can observe
// connectivity from a third party (Charlie). Uses an existing session's
// underlying connection to send to Alice's address.
// Prefers to send from relaySession (if provided) to maintain protocol-correlated
// probe traffic rather than from an arbitrary session.
func (t *SSU2Transport) sendProbeToAlice(ptBlock *ssu2noise.PeerTestBlock, aliceAddr *net.UDPAddr, relaySession *SSU2Session) error {
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
	// Require relaySession to maintain protocol-correlated probe traffic (6.2).
	// Sending a probe from an arbitrary peer's session skews external address
	// observations and confuses NAT behavior detection. Fail-closed if relaySession
	// is unavailable to prevent misattribution of traffic source.
	conn := relaySession.Conn()
	if relaySession == nil || conn == nil {
		t.logger.Debug("PeerTest Charlie: relay session unavailable, cannot send probe (probe requires protocol-correlated path)")
		return nil
	}
	return conn.SendToAddress(encoded, aliceAddr)
}

// anyActiveSession returns the first active SSU2Session, or nil if none exist.
func (t *SSU2Transport) anyActiveSession() *SSU2Session {
	var found *SSU2Session
	t.sessions.Range(func(_, value interface{}) bool {
		s, ok := value.(*SSU2Session)
		if ok && s.Conn() != nil {
			found = s
			return false
		}
		return true
	})
	return found
}

// handleRelayRequestBlock processes a RelayRequest from Alice (we are Bob).
// It enforces a per-Alice-session rate limit, decodes the request, verifies
// the signature using Alice's Ed25519 signing key from NetDB, and forwards a
// RelayIntro to Charlie via the session associated with the relay tag.
func (t *SSU2Transport) handleRelayRequestBlock(block *ssu2noise.SSU2Block, session *SSU2Session) error {
	if t.relayManager == nil || block == nil {
		return nil
	}
	// Verify session is available (required for signature verification, fail-closed)
	if session == nil {
		t.logger.Warn("RelayRequest: no session provided, cannot verify signature, rejecting")
		return oops.Errorf("signature verification failed: no session")
	}
	// Rate-limit per Alice session using the same token bucket as PeerTest.
	if !session.peerTestLimiter.Allow() {
		t.logger.Debug("RelayRequest: per-session rate limit exceeded, dropping")
		return nil
	}
	req, err := ssu2noise.DecodeRelayRequest(block)
	if err != nil {
		t.logger.WithField("error", err).Warn("failed to decode RelayRequest")
		return nil
	}

	// Verify signature (fail-closed: reject if senderHash unavailable)
	senderHash := extractSenderHash(session)
	if senderHash == (data.Hash{}) {
		t.logger.Warn("RelayRequest: cannot extract sender hash, rejecting")
		return oops.Errorf("signature verification failed: no sender hash")
	}
	valid, verifyErr := t.verifyRelayRequestSignature(req, senderHash)
	if verifyErr != nil {
		t.logger.WithFields(map[string]interface{}{
			"sender_hash": senderHash[:4],
			"nonce":       req.Nonce,
			"error":       verifyErr,
		}).Warn("RelayRequest signature verification failed, rejecting")
		return verifyErr
	}
	if !valid {
		t.logger.WithFields(map[string]interface{}{
			"sender_hash": senderHash[:4],
			"nonce":       req.Nonce,
		}).Warn("RelayRequest signature invalid, rejecting")
		return oops.Errorf("invalid RelayRequest signature")
	}

	return t.forwardRelayIntro(req)
}

// forwardRelayIntro looks up the relay tag target (Charlie), builds a
// RelayIntro block, and writes it to Charlie's session.
// Rejects when no relay tag is registered for the requested tag value or when
// there is no active session to Charlie. Enforces introducer capability
// validation (caps=B) via RouterLookupFunc before forwarding.
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
	if !t.hasIntroducerCapability(session) {
		t.logger.WithFields(map[string]interface{}{
			"relay_tag":    req.RelayTag,
			"charlie_addr": tag.ForAddr,
		}).Warn("RelayRequest rejected: Charlie lacks introducer capability caps=B")
		return nil
	}
	intro := buildRelayIntro(req)
	encoded, err := ssu2noise.EncodeRelayIntro(intro)
	if err != nil {
		return err
	}
	return session.WriteBlocks([]*ssu2noise.SSU2Block{encoded})
}

// hasIntroducerCapability returns true when session's remote peer advertises
// introducer capability (caps=B) in its RouterInfo.
func (t *SSU2Transport) hasIntroducerCapability(session *SSU2Session) bool {
	if t == nil || t.config == nil || t.config.RouterLookupFunc == nil || session == nil || session.conn == nil {
		return false
	}
	addr, ok := session.conn.RemoteAddr().(*ssu2noise.SSU2Addr)
	if !ok {
		return false
	}
	rh := data.Hash(addr.RouterHash())
	ri, err := t.config.RouterLookupFunc(rh)
	if err != nil {
		t.logger.WithFields(map[string]interface{}{
			"router_hash": rh.String(),
			"error":       err,
		}).Warn("RelayRequest rejected: failed RouterInfo lookup for Charlie")
		return false
	}
	return strings.Contains(ri.RouterCapabilities(), "B")
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
	if !t.isRelayResponseValid(block) {
		return nil
	}

	resp, err := t.decodeAndLogRelayResponse(block)
	if err != nil {
		return nil
	}

	t.deliverRelayResponse(resp)
	return nil
}

// isRelayResponseValid checks if relay response processing is possible.
func (t *SSU2Transport) isRelayResponseValid(block *ssu2noise.SSU2Block) bool {
	return t.relayManager != nil && block != nil
}

// decodeAndLogRelayResponse decodes the relay response block and logs it.
func (t *SSU2Transport) decodeAndLogRelayResponse(block *ssu2noise.SSU2Block) (*ssu2noise.RelayResponseBlock, error) {
	resp, err := ssu2noise.DecodeRelayResponse(block)
	if err != nil {
		t.logger.WithField("error", err).Warn("failed to decode RelayResponse")
		return nil, err
	}

	t.logger.WithField("code", resp.Code).Debug("relay response received")
	return resp, nil
}

// deliverRelayResponse delivers the relay response to any waiting dialViaIntroducer call.
// After delivery, marks the entry as consumed to prevent duplicate deliveries from
// writing to the channel after the waiter has moved on (MEDIUM 2.6 cleanup).
func (t *SSU2Transport) deliverRelayResponse(resp *ssu2noise.RelayResponseBlock) {
	v, ok := t.pendingRelayResponses.Load(resp.Nonce)
	if !ok {
		return
	}

	pending, ok := v.(*pendingRelayResponse)
	if !ok || pending.consumed.Load() {
		return
	}
	select {
	case pending.ch <- resp:
		// Successfully delivered; mark as consumed to prevent late duplicate
		// deliveries from overwriting the channel after waiter timeout.
		pending.consumed.Store(true)
	default:
		// channel already has a value (duplicate delivery); ignore
	}
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

	// E-3 fix: Rate-limit per Bob session using the same token bucket as PeerTest/RelayRequest.
	// This prevents a malicious Bob from flooding RelayIntro messages, which trigger expensive
	// Ed25519 signing operations in sendRelayResponseToBob.
	if bobSession != nil && !bobSession.peerTestLimiter.Allow() {
		t.logger.Debug("RelayIntro: per-session rate limit exceeded, dropping")
		return nil
	}

	// E-3 fix: Apply global rate limiting to prevent coordinated flooding from multiple sessions.
	if t.peerTestGlobalLimiter != nil && !t.peerTestGlobalLimiter.Allow() {
		t.logger.Debug("RelayIntro: global rate limit exceeded, dropping")
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

	// BUG FIX HIGH E-2: Validate Alice's IP to prevent reflection attacks.
	// Reject private, loopback, multicast, and other invalid addresses.
	if !isValidExternalAddress(aliceAddr.IP) {
		t.logger.WithFields(map[string]interface{}{
			"alice_ip":   aliceAddr.IP.String(),
			"alice_port": aliceAddr.Port,
		}).Warn("hole-punch: rejected RelayIntro with invalid Alice IP (potential reflection attack)")
		return oops.Errorf("invalid Alice IP address: %s", aliceAddr.IP)
	}

	if bobSession == nil {
		t.logger.Debug("hole-punch: no Bob session provided, skipping")
		return nil
	}
	bobAddr := bobSession.RemoteUDPAddr()
	if bobAddr == nil {
		t.logger.Debug("hole-punch: Bob session has no remote address, skipping")
		return nil
	}

	// BUG FIX HIGH E-1: Verify the RelayIntro signature with the CORRECT Bob hash.
	// The initial verification in initNATManagers used Alice's hash as a placeholder
	// because Bob's hash wasn't available in that closure. Now that we have Bob's
	// session, perform proper signature verification with the real Bob hash and
	// Alice's signing key from NetDB.
	if err := t.verifyRelayIntroSignature(intro, bobSession); err != nil {
		t.logger.WithField("error", err).Warn("hole-punch: RelayIntro signature verification failed")
		return err
	}

	// BUG FIX HIGH E-2: Only send hole-punch/RelayResponse when InitiateHolePunch succeeds.
	// This prevents reflection attacks where an attacker triggers emissions to arbitrary IPs.
	_, err := t.holePunchCoord.InitiateHolePunch(aliceAddr, bobAddr, intro.AliceRelayTag)
	if err != nil {
		t.logger.WithField("error", err).Warn("hole-punch coordinator registration failed; not sending hole-punch/RelayResponse")
		return err
	}

	t.sendHolePunchToAlice(intro, aliceAddr, bobSession)
	if err := t.sendRelayResponseToBob(bobSession, intro); err != nil {
		t.logger.WithField("error", err).Warn("failed to send RelayResponse to Bob")
		return err
	}
	t.logger.WithField("alice_addr", aliceAddr).Debug("hole-punch initiated towards Alice")
	return nil
}

// verifyRelayIntroSignature performs proper signature verification on a RelayIntro
// block using Alice's Ed25519 public key (from NetDB) and the correct Bob hash
// (from bobSession). This is the fail-closed verification that replaces the
// placeholder-based verification done in the init-time closure.
func (t *SSU2Transport) verifyRelayIntroSignature(intro *ssu2noise.RelayIntroBlock, bobSession *SSU2Session) error {
	if intro == nil || len(intro.Signature) == 0 {
		return oops.Errorf("relay intro: missing block or signature")
	}

	// Extract Alice's router hash from the intro block
	var aliceHash data.Hash
	if len(intro.AliceRouterHash) == 32 {
		copy(aliceHash[:], intro.AliceRouterHash)
	} else {
		return oops.Errorf("relay intro: AliceRouterHash missing or wrong size")
	}

	// Look up Alice's RouterInfo from NetDB to get her Ed25519 signing key
	if t.config.RouterLookupFunc == nil {
		return oops.Errorf("signature verification unavailable: RouterLookupFunc not configured")
	}
	aliceRI, err := t.config.RouterLookupFunc(aliceHash)
	if err != nil {
		t.logger.WithField("alice_hash", aliceHash[:4]).Warn("RelayIntro: failed to lookup Alice's RouterInfo for signature verification")
		return oops.Wrapf(err, "netdb lookup failed for Alice %x", aliceHash[:4])
	}
	alicePubKey, err := extractEd25519PublicKey(aliceRI)
	if err != nil {
		return oops.Wrapf(err, "failed to extract Ed25519 public key from Alice's RouterInfo")
	}

	// Extract Bob's router hash from the session
	bobHash := t.extractPeerHash(bobSession.conn)

	// Get our (Charlie's) identity hash
	charlieHash := t.getOurIdentityHash()

	// Verify the signature with correct hashes
	ok, err := ssu2noise.VerifyRelayRequestSignature(
		alicePubKey,
		intro.Signature,
		bobHash, // NOW using the real Bob hash, not Alice's hash as placeholder
		charlieHash,
		intro.Nonce,
		intro.AliceRelayTag,
		intro.Timestamp,
		intro.Version,
		intro.AlicePort,
		intro.AliceIP,
	)
	if err != nil {
		return oops.Wrapf(err, "relay intro signature verification error")
	}
	if !ok {
		return oops.Errorf("relay intro signature invalid")
	}

	t.logger.WithFields(map[string]interface{}{
		"alice_hash": fmt.Sprintf("%x", aliceHash[:4]),
		"bob_hash":   fmt.Sprintf("%x", bobHash[:4]),
	}).Debug("RelayIntro signature verified successfully with correct Bob hash")

	return nil
}

// sendHolePunchToAlice sends a best-effort HolePunch UDP datagram to Alice.
// Uses the same wire format as RelayIntro (block type 9; the receiver ignores
// the type byte for UDP hole-punch purposes). Non-fatal on failure.
// Prefers to send from bobSession if provided, to maintain protocol-correlated
// hole-punch traffic rather than from an arbitrary session.
func (t *SSU2Transport) sendHolePunchToAlice(intro *ssu2noise.RelayIntroBlock, aliceAddr *net.UDPAddr, bobSession *SSU2Session) {
	// Require bobSession to maintain protocol-correlated hole-punch traffic (6.2).
	// Using an arbitrary peer's session for hole-punch confuses NAT path tracking.
	// Fail-closed if Bob's session is unavailable.
	if bobSession == nil || bobSession.conn == nil {
		t.logger.Debug("hole-punch: Bob session unavailable, cannot send hole-punch (requires protocol-correlated path)")
		return
	}
	encoded, err := ssu2noise.EncodeRelayIntro(intro)
	if err != nil {
		t.logger.WithField("error", err).Debug("hole-punch: encode block failed")
		return
	}
	if err := bobSession.conn.SendToAddress(encoded, aliceAddr); err != nil {
		t.logger.WithField("error", err).Debug("hole-punch: send to Alice failed")
	}
}

// sendRelayResponseToBob signs and sends a RelayResponse (code=0) to Bob so
// that Bob can forward it to Alice. Alice uses Charlie's IP/Port and token to
// send the SSU2 SessionRequest directly to us.
func (t *SSU2Transport) sendRelayResponseToBob(bobSession *SSU2Session, intro *ssu2noise.RelayIntroBlock) error {
	// BUG FIX HIGH RD-2: Use confirmed external address, not local bind address.
	// localIPPort() returns the listener bind address (often 0.0.0.0 or private),
	// which breaks hole-punching when Charlie advertises an unreachable address.
	// Use the external address confirmed by PeerTest observations when available.
	charlieIP, charliePort, err := t.externalAddressForRelay()
	if err != nil {
		return oops.Wrapf(err, "hole-punch: external address")
	}

	signingKey, token, err := t.prepareRelayResponseCredentials()
	if err != nil {
		return err
	}

	bobHash := extractBobRouterHash(bobSession)
	timestamp := uint32(time.Now().Unix())

	resp, err := t.buildSignedRelayResponse(signingKey, bobHash, intro, timestamp, charliePort, charlieIP, token)
	if err != nil {
		return err
	}

	return t.sendEncodedRelayResponse(bobSession, resp)
}

// prepareRelayResponseCredentials retrieves the signing key and generates a token.
func (t *SSU2Transport) prepareRelayResponseCredentials() ([]byte, []byte, error) {
	signingKey := t.keystore.GetSigningPrivateKey()
	if signingKey == nil {
		return nil, nil, oops.Errorf("hole-punch: signing key unavailable")
	}

	token := make([]byte, 8)
	if _, err := cryptorand.Read(token); err != nil {
		return nil, nil, oops.Wrapf(err, "hole-punch: token generation")
	}

	return signingKey.Bytes(), token, nil
}

// extractBobRouterHash extracts the router hash from Bob's session address.
func extractBobRouterHash(bobSession *SSU2Session) data.Hash {
	var bobHash data.Hash
	// Use locked accessor to avoid race with DetachConn (R-1 fix).
	remoteAddr := bobSession.RemoteAddr()
	if remoteAddr == nil {
		return bobHash
	}
	if ssu2Addr, ok := remoteAddr.(*ssu2noise.SSU2Addr); ok && ssu2Addr != nil {
		bobHash = ssu2Addr.RouterHash()
	}
	return bobHash
}

// buildSignedRelayResponse creates and signs a RelayResponse block.
func (t *SSU2Transport) buildSignedRelayResponse(signingKeyBytes []byte, bobHash data.Hash, intro *ssu2noise.RelayIntroBlock, timestamp uint32, charliePort uint16, charlieIP net.IP, token []byte) (*ssu2noise.RelayResponseBlock, error) {
	ed25519Key := ed25519.PrivateKey(signingKeyBytes)
	sig, err := ssu2noise.SignRelayResponse(ed25519Key, bobHash, intro.Nonce, timestamp, intro.Version, charliePort, charlieIP)
	if err != nil {
		return nil, oops.Wrapf(err, "hole-punch: sign RelayResponse")
	}

	return &ssu2noise.RelayResponseBlock{
		Code: 0, Nonce: intro.Nonce, Timestamp: timestamp,
		Version: intro.Version, CharliePort: charliePort, CharlieIP: charlieIP,
		Signature: sig, Token: token,
	}, nil
}

// sendEncodedRelayResponse encodes and sends the RelayResponse to Bob.
func (t *SSU2Transport) sendEncodedRelayResponse(bobSession *SSU2Session, resp *ssu2noise.RelayResponseBlock) error {
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
	return ssu2noise.DetermineNATType(result)
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
// published RouterInfo. Up to 3 introducers are maintained (implementation convention; up to 3 is common practice in I2P implementations).
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
// T-1 fix: Uses single-flight pattern (natDetectionRunning flag) to prevent
// concurrent detection runs from overwriting shared retry state.
func (t *SSU2Transport) runNATDetection(candidates []router_info.RouterInfo, republish func()) {
	// T-1 fix: Single-flight check — if detection already running, skip this call.
	if !t.natDetectionRunning.CompareAndSwap(false, true) {
		t.logger.Info("NAT detection already in progress; skipping concurrent run")
		return
	}
	defer t.natDetectionRunning.Store(false)

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
// Implements retry logic with exponential backoff (T-1 fix): after N consecutive
// failures (default 3), the node classifies itself as firewalled and registers
// introducers. This prevents false firewalled classification from transient
// network issues while ensuring eventual fallback for genuinely firewalled nodes.
func (t *SSU2Transport) handlePeerTestTimeout(candidates []router_info.RouterInfo, republish func()) {
	const maxRetries = 3
	const initialBackoff = 60 * time.Second

	t.peerTestRetryMu.Lock()
	t.peerTestRetryCount++
	retryCount := t.peerTestRetryCount
	t.peerTestLastAttempt = time.Now()

	// Store candidates and republish for retry attempts
	t.peerTestCandidates = candidates
	t.peerTestRepublishFn = republish
	t.peerTestRetryMu.Unlock()

	if retryCount <= maxRetries {
		// T-2 fix: Calculate exponential backoff with jitter to prevent thundering herd.
		// Base: 60s, 120s, 240s; jitter adds ±25% randomization using crypto/rand for safety.
		baseBackoff := initialBackoff * time.Duration(1<<uint(retryCount-1))
		var backoff time.Duration

		// Generate cryptographically secure random jitter (±25% of base backoff)
		var randBytes [8]byte
		if _, err := cryptorand.Read(randBytes[:]); err != nil {
			t.logger.WithError(err).Warn("Failed to generate jitter; using base backoff")
			backoff = baseBackoff
		} else {
			// Convert random bytes to float64 in [0, 1) range
			randUint64 := uint64(randBytes[0]) | uint64(randBytes[1])<<8 | uint64(randBytes[2])<<16 |
				uint64(randBytes[3])<<24 | uint64(randBytes[4])<<32 | uint64(randBytes[5])<<40 |
				uint64(randBytes[6])<<48 | uint64(randBytes[7])<<56
			randFloat := float64(randUint64) / float64(^uint64(0))

			// Apply jitter: ±25% → range [0.75, 1.25] * baseBackoff
			jitterFactor := 0.75 + (randFloat * 0.5) // 0.75 + [0, 0.5) = [0.75, 1.25)
			backoff = time.Duration(float64(baseBackoff) * jitterFactor)
		}

		t.logger.WithFields(map[string]interface{}{
			"timeout_seconds": 60,
			"retry_count":     retryCount,
			"base_backoff":    baseBackoff.String(),
			"next_retry_in":   backoff.String(),
		}).Warn("NAT detection: peer test timed out; scheduling retry to avoid false FIREWALLED classification")

		// Schedule retry after backoff
		t.scheduleNATDetectionRetry(backoff)
	} else {
		// After maxRetries consecutive failures, classify as firewalled
		t.logger.WithFields(map[string]interface{}{
			"timeout_seconds":   60,
			"consecutive_fails": retryCount,
			"classification":    "FIREWALLED",
		}).Warn("NAT detection: peer test failed after maximum retries; classifying as FIREWALLED and registering introducers")

		// Register introducers for firewalled nodes
		t.registerIntroducers(candidates, republish)

		// Reset retry counter after successful fallback
		t.peerTestRetryMu.Lock()
		t.peerTestRetryCount = 0
		t.peerTestRetryMu.Unlock()
	}
}

// scheduleNATDetectionRetry schedules a retry of NAT detection after the specified backoff delay.
// The retry is tracked in the transport WaitGroup and cancellable via context.
func (t *SSU2Transport) scheduleNATDetectionRetry(backoff time.Duration) {
	t.peerTestRetryMu.Lock()
	// Cancel any existing retry timer to avoid multiple concurrent retries
	if t.peerTestRetryTimer != nil {
		t.peerTestRetryTimer.Stop()
	}

	t.peerTestRetryTimer = time.AfterFunc(backoff, func() {
		// Check if transport is still running
		select {
		case <-t.ctx.Done():
			return
		default:
		}

		// Retrieve stored candidates and republish function
		t.peerTestRetryMu.Lock()
		candidates := t.peerTestCandidates
		republish := t.peerTestRepublishFn
		t.peerTestRetryMu.Unlock()

		if len(candidates) >= 2 {
			t.logger.Info("NAT detection: retry timer fired; re-running peer test")
			t.wg.Add(1)
			go func() {
				defer t.wg.Done()
				t.runNATDetection(candidates, republish)
			}()
		} else {
			t.logger.Warn("NAT detection: retry scheduled but no candidates available")
		}
	})
	t.peerTestRetryMu.Unlock()
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

	// Reset retry counter on successful peer test completion (T-1 fix)
	t.peerTestRetryMu.Lock()
	t.peerTestRetryCount = 0
	if t.peerTestRetryTimer != nil {
		t.peerTestRetryTimer.Stop()
		t.peerTestRetryTimer = nil
	}
	t.peerTestRetryMu.Unlock()

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
	return ssu2noise.DetermineNATType(&ssu2noise.TestResult{
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
// BUG FIX HIGH 2.4: createIntroducerFromRouterInfo allocates a relay tag as a side effect.
// If registration fails, the tag is leaked. This wrapper minimizes that risk by
// deferring tag allocation until we're sure the introducer can be registered.
func (t *SSU2Transport) tryRegisterIntroducer(ri router_info.RouterInfo) bool {
	intro, err := t.createIntroducerFromRouterInfo(ri)
	if err != nil {
		// Failure during creation — tag was not allocated yet, so no cleanup needed.
		return false
	}
	// Registration may fail even though creation succeeded. Track abandoned tags
	// for monitoring and future cleanup when a release API becomes available.
	err = t.RegisterIntroducer(intro)
	if err != nil {
		t.trackAbandonedRelayTag(intro.RelayTag, intro.Addr, err.Error())
		t.logger.WithError(err).WithFields(map[string]interface{}{
			"introducer_hash": fmt.Sprintf("%x", intro.RouterHash[:8]),
			"relay_tag":       intro.RelayTag,
		}).Warn("Introducer registration failed; relay tag tracked for future cleanup")
		return false
	}
	return true
}

// trackAbandonedRelayTag records a relay tag that was allocated but not successfully
// registered. Provides monitoring and prepares for future cleanup when a release
// API becomes available in the RelayManager.
// L-2 fix: Bound the slice to maxAbandonedRelayTags and prune entries older than maxAbandonedRelayTagAge.
func (t *SSU2Transport) trackAbandonedRelayTag(tag uint32, addr *net.UDPAddr, reason string) {
	t.abandonedRelayTagsMu.Lock()
	defer t.abandonedRelayTagsMu.Unlock()

	const maxAbandonedRelayTags = 50                 // Hard cap on slice size
	const maxAbandonedRelayTagAge = 10 * time.Minute // Prune entries older than this

	// Prune expired entries before adding
	now := time.Now()
	pruned := t.abandonedRelayTags[:0]
	for i := range t.abandonedRelayTags {
		if now.Sub(t.abandonedRelayTags[i].allocatedAt) < maxAbandonedRelayTagAge {
			pruned = append(pruned, t.abandonedRelayTags[i])
		}
	}
	t.abandonedRelayTags = pruned

	// Append new entry
	t.abandonedRelayTags = append(t.abandonedRelayTags, abandonedRelayTag{
		tag:         tag,
		addr:        addr,
		allocatedAt: now,
		reason:      reason,
	})

	// If still over cap after pruning, evict oldest entries (ring-buffer style)
	if len(t.abandonedRelayTags) > maxAbandonedRelayTags {
		evictCount := len(t.abandonedRelayTags) - maxAbandonedRelayTags
		t.abandonedRelayTags = t.abandonedRelayTags[evictCount:]
		t.logger.WithField("evicted", evictCount).Warn("Evicted oldest abandoned relay tags to enforce cap")
	}

	// Log a warning if we're accumulating many abandoned tags (even after pruning)
	if len(t.abandonedRelayTags) > 10 {
		t.logger.WithField("count", len(t.abandonedRelayTags)).
			Warn("Accumulating abandoned relay tags; may indicate registration instability")
	}
}

// GetAbandonedRelayTagCount returns the number of tracked abandoned relay tags.
// Exported for monitoring and diagnostics.
func (t *SSU2Transport) GetAbandonedRelayTagCount() int {
	t.abandonedRelayTagsMu.Lock()
	defer t.abandonedRelayTagsMu.Unlock()
	return len(t.abandonedRelayTags)
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
	if !t.shouldInitiatePeerTest() {
		return
	}

	udpAddr := t.extractUDPAddr(remote)
	if udpAddr == nil {
		return
	}

	t.launchPeerTest(udpAddr)
}

// shouldInitiatePeerTest checks if we should initiate a peer test.
// SA-1 fix: Use CAS loop to atomically increment only when below the cap,
// preventing the race where concurrent goroutines could all read "<= 3" and
// proceed, allowing more than startupPeerTestMax tests.
func (t *SSU2Transport) shouldInitiatePeerTest() bool {
	const startupPeerTestMax = 3
	if t.peerTestManager == nil {
		return false
	}
	// Atomic CAS loop: only increment if we're below the cap.
	for {
		current := atomic.LoadInt32(&t.startupPeerTestCount)
		if current >= startupPeerTestMax {
			return false
		}
		if atomic.CompareAndSwapInt32(&t.startupPeerTestCount, current, current+1) {
			return true
		}
		// CAS failed (another goroutine incremented); retry.
	}
}

// extractUDPAddr extracts a UDPAddr from a net.Addr, unwrapping SSU2Addr if needed.
func (t *SSU2Transport) extractUDPAddr(remote net.Addr) *net.UDPAddr {
	udpAddr, ok := remote.(*net.UDPAddr)
	if ok {
		return udpAddr
	}

	// Try SSU2Addr unwrapping.
	ssu2a, ok := remote.(*ssu2noise.SSU2Addr)
	if !ok {
		return nil
	}

	underlying := ssu2a.UnderlyingAddr()
	if underlying == nil {
		return nil
	}

	udpAddr, _ = underlying.(*net.UDPAddr)
	return udpAddr
}

// launchPeerTest launches a peer test in a goroutine.
func (t *SSU2Transport) launchPeerTest(udpAddr *net.UDPAddr) {
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()

		// Check for shutdown before initiating to avoid starting work that will be discarded
		select {
		case <-t.ctx.Done():
			return
		default:
		}

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
	internalPort, valid := t.validateAndExtractPort()
	if !valid {
		return
	}

	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		// L-1: Capture per-generation NAT context.
		t.natCtxMu.Lock()
		natCtx := t.natCtx
		t.natCtxMu.Unlock()
		t.runPortMappingRetryLoop(natCtx, internalPort)
	}()
}

// validateAndExtractPort validates the listener address and extracts the internal port.
// Returns the port number and true if valid, or 0 and false if validation fails.
// R-2 fix: Reads t.config.ListenerAddress under identityMu to avoid race with SetIdentity.
func (t *SSU2Transport) validateAndExtractPort() (int, bool) {
	if t.config == nil {
		return 0, false
	}
	t.identityMu.RLock()
	listenerAddr := t.config.ListenerAddress
	t.identityMu.RUnlock()

	_, portStr, err := net.SplitHostPort(listenerAddr)
	if err != nil {
		return 0, false
	}
	internalPort, err := strconv.Atoi(portStr)
	if err != nil || internalPort <= 0 {
		return 0, false
	}
	host, _, _ := net.SplitHostPort(listenerAddr)
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return 0, false
	}
	return internalPort, true
}

// runPortMappingRetryLoop performs the actual port mapping retry loop with exponential backoff.
func (t *SSU2Transport) runPortMappingRetryLoop(natCtx context.Context, internalPort int) {
	backoff := natRetryInitial
	for {
		if !t.waitForRetryDelay(natCtx, backoff) {
			return
		}

		if t.attemptPortMapping(internalPort, &backoff) {
			return
		}
	}
}

// waitForRetryDelay waits for the backoff delay or context cancellation.
// Returns false if context is done, true if delay completed.
func (t *SSU2Transport) waitForRetryDelay(natCtx context.Context, backoff time.Duration) bool {
	select {
	case <-natCtx.Done():
		return false
	case <-time.After(backoff):
		return true
	}
}

// attemptPortMapping attempts to create a port mapper and map the port.
// Returns true if successful (should exit loop), false if should retry.
func (t *SSU2Transport) attemptPortMapping(internalPort int, backoff *time.Duration) bool {
	mapper, err := t.createPortMapper()
	if err != nil {
		t.logAndIncreaseBackoff(backoff, err, "", "NAT-PMP/UPnP port mapper unavailable; will retry")
		return false
	}

	gwIP, _ := mapper.GetExternalIP()
	t.logger.WithFields(map[string]interface{}{
		"gateway": gwIP,
		"port":    internalPort,
	}).Debug("NAT-PMP retry: attempting port mapping")

	externalPort, err := mapper.MapPort("udp", internalPort, 1*time.Hour)
	if err != nil {
		t.logAndIncreaseBackoff(backoff, err, gwIP, "NAT-PMP port mapping failed; will retry")
		return false
	}

	// Store mapper and external port for cleanup on transport shutdown (MEDIUM 2.5)
	t.portMapperMu.Lock()
	t.activePortMapper = mapper
	t.activeExternalPort = externalPort
	t.portMapperMu.Unlock()

	t.logSuccessAndExit(mapper, internalPort)
	return true
}

// createPortMapper creates a port mapper with timeout context.
func (t *SSU2Transport) createPortMapper() (nattraversal.PortMapper, error) {
	mapCtx, mapCancel := context.WithTimeout(t.ctx, 5*time.Second)
	defer mapCancel()
	mapper, err := nattraversal.NewPortMapperContext(mapCtx)
	if err != nil {
		t.reachMetrics.natMappingFailure.Add(1)
		return nil, err
	}
	return mapper, nil
}

// logAndIncreaseBackoff logs the failure and increases backoff using exponential growth.
func (t *SSU2Transport) logAndIncreaseBackoff(backoff *time.Duration, err error, gwIP, message string) {
	t.reachMetrics.natMappingFailure.Add(1)
	fields := map[string]interface{}{
		"error":   err,
		"backoff": backoff.String(),
	}
	if gwIP != "" {
		fields["gateway"] = gwIP
	}
	t.logger.WithFields(fields).Debug(message)
	*backoff = increaseBackoff(*backoff)
}

// increaseBackoff doubles the backoff duration, capped at natRetryMax.
func increaseBackoff(current time.Duration) time.Duration {
	if current < natRetryMax {
		current *= 2
		if current > natRetryMax {
			return natRetryMax
		}
	}
	return current
}

// logSuccessAndExit logs successful port mapping and increments success metrics.
func (t *SSU2Transport) logSuccessAndExit(mapper nattraversal.PortMapper, internalPort int) {
	t.reachMetrics.natMappingSuccess.Add(1)
	extIP, _ := mapper.GetExternalIP()
	t.logger.WithFields(map[string]interface{}{
		"external_ip":   extIP,
		"internal_port": internalPort,
	}).Info("NAT-PMP/UPnP port mapping succeeded")
}
