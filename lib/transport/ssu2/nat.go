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
	i2ped25519 "github.com/go-i2p/crypto/ed25519"
	"github.com/go-i2p/go-i2p/lib/nat"
	"github.com/go-i2p/go-i2p/lib/util/logutil"
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

// relayResponseCharlieUnspecified is RelayResponse status code 64, "rejected by
// Charlie, reason unspecified", per ssu2.rst §"RelayResponse". Codes 1-63 are
// Bob rejections and 64-127 Charlie rejections; the library exposes the Code
// field but no named constants, so the one we emit is named here.
const relayResponseCharlieUnspecified uint8 = 64

// initNATManagers allocates and wires the PeerTestManager, RelayManager,
// IntroducerRegistry, and HolePunchCoordinator on a freshly started transport.
// Must be called after t.listener is initialised.
// Returns an error if HolePunchCoordinator initialization fails.
// Creates a per-generation context for NAT goroutines so they can be cancelled
// on SetIdentity without affecting the transport-level context.
// Reads t.listener under identityMu to avoid TOCTOU with SetIdentity.
// Writes all manager pointers under natManagerMu to prevent concurrent
// callback reads from seeing nil or partially-initialized managers.
func initNATManagers(t *SSU2Transport) error {
	// Create per-generation context for NAT goroutines.
	t.natCtxMu.Lock()
	t.natCtx, t.natCancel = context.WithCancel(t.ctx)
	t.natCtxMu.Unlock()

	// Snapshot t.listener under lock to avoid race with SetIdentity.
	t.identityMu.RLock()
	listener := t.listener
	t.identityMu.RUnlock()

	if listener == nil {
		return oops.New("cannot initialize NAT managers: listener is nil")
	}

	// Build all managers first, THEN install them under the write lock
	// as a batch. This minimizes the critical section and prevents callbacks from seeing
	// partially initialized state.
	relayMgr := ssu2noise.NewRelayManager(listener)
	introducerReg := ssu2noise.NewIntroducerRegistry(3)
	// resolveHolePunchContext resolves the peer identities and signer key for
	// incoming hole-punch messages. Per SSU2 spec §Hole Punch, the Hole Punch
	// message carries the identical signed Relay Response block that Bob
	// forwards to Alice, and that signature is made by Charlie (the
	// introduction target). Both router hashes must therefore be resolved from
	// live session state (fail-closed when unknown):
	// - BobHash: router hash of the introducer session (attempt.Introducer)
	// - CharlieHash: router hash of the target session (attempt.RemoteAddr)
	// - signerKey: Charlie's Ed25519 signing key, looked up in NetDB from the
	//   target session's router hash
	resolver := func(info ssu2noise.HolePunchVerifyInfo) (ssu2noise.HolePunchVerifyContext, i2ped25519.Ed25519PublicKey, bool) {
		var ctx ssu2noise.HolePunchVerifyContext

		// Resolve Bob's hash from the introducer session.
		bobSession := t.findSessionByAddr(info.IntroducerAddr)
		if bobSession == nil {
			t.logger.Debug("hole-punch verify: no session for introducer address; failing closed")
			return ctx, nil, false
		}
		ctx.BobHash = extractBobRouterHash(bobSession)

		// Resolve Charlie's hash from the target session.
		charlieSession := t.findSessionByAddr(info.RemoteAddr)
		if charlieSession == nil {
			t.logger.Debug("hole-punch verify: no session for remote address; failing closed")
			return ctx, nil, false
		}
		ctx.CharlieHash = extractBobRouterHash(charlieSession)

		if info.Block == nil {
			t.logger.Debug("hole-punch verify: nil relay response block; failing closed")
			return ctx, nil, false
		}

		cfg := t.config.Load()
		if cfg.RouterLookupFunc == nil {
			t.logger.Debug("hole-punch verify: RouterLookupFunc not configured; failing closed")
			return ctx, nil, false
		}
		charlieRI, err := cfg.RouterLookupFunc(ctx.CharlieHash)
		if err != nil {
			t.logger.WithField("error", err).Debug("hole-punch verify: NetDB lookup for Charlie failed; failing closed")
			return ctx, nil, false
		}
		charliePubKey, err := extractEd25519PublicKey(charlieRI)
		if err != nil {
			t.logger.WithField("error", err).Debug("hole-punch verify: failed to extract Charlie's Ed25519 key; failing closed")
			return ctx, nil, false
		}

		return ctx, charliePubKey, true
	}
	holePunch, err := ssu2noise.NewHolePunchCoordinator(relayMgr, resolver)
	if err != nil {
		// MEDIUM 5.5: HolePunchCoordinator initialization failure should be reported,
		// not silently downgraded to a warning. Return the error so the caller can decide
		// whether to fail the transport or degrade gracefully.
		return oops.Wrapf(err, "failed to initialize HolePunchCoordinator")
	}
	peerTestMgr := ssu2noise.NewPeerTestManager(listener)
	if t.natStateCache == nil {
		t.natStateCache = &natState{}
	}
	t.loadNATState()
	t.startNATCleanup()

	// Register the out-of-session (intro-key protected) message handler on the
	// listener socket. Peer Test messages 5-7 and the Hole Punch arrive there
	// rather than on any session, and until this is installed they are dropped
	// unseen -- which is why Bob's probe, Alice's reply and Charlie's
	// hole-punch were all one-way conversations.
	//
	// Registered before the managers are installed below: the handler reads them
	// under natManagerMu at call time, so registering here (outside the lock)
	// both avoids a natManagerMu/identityMu ordering inversion and is safe,
	// because a message that arrives in the window simply finds no manager and is
	// dropped as unsolicited.
	listener.SetOutOfSessionHandler(t.handleOutOfSessionMessage)

	// Now install all managers under the write lock.
	// This prevents callbacks from starting to read managers until all are fully initialized.
	t.natManagerMu.Lock()
	defer t.natManagerMu.Unlock()
	t.relayManager = relayMgr
	t.introducerRegistry = introducerReg
	t.holePunchCoord = holePunch
	t.peerTestManager = peerTestMgr

	// Start port mapper with retry logic (extracted to lib/nat).
	if port, valid := t.validateAndExtractPort(); valid {
		cfg := &nat.PortMapperConfig{
			Network:      "udp",
			InternalPort: port,
			Context:      t.natCtx,
		}
		t.portMapperManager = nat.NewPortMapperManager(cfg)
	}

	return nil
}

// stopNATManagers stops all NAT managers and cancels the per-generation NAT context
// to signal NAT goroutines (cleanup, port mapping) to exit. .
// Must be called before initNATManagers in SetIdentity.
// Acquire write lock to protect manager pointer writes from concurrent reads in callbacks.
func stopNATManagers(t *SSU2Transport) {
	// Cancel the per-generation NAT context to stop NAT goroutines.
	t.natCtxMu.Lock()
	if t.natCancel != nil {
		t.natCancel()
		t.natCancel = nil
		t.natCtx = nil
	}
	t.natCtxMu.Unlock()

	// Stop all managers under write lock to prevent callbacks from reading
	// half-cleared state. Callbacks acquire read lock and nil-check; if they start before
	// this lock is acquired, they see consistent manager state.
	t.natManagerMu.Lock()
	defer t.natManagerMu.Unlock()

	// Stop all managers explicitly.
	if t.relayManager != nil {
		t.relayManager.Stop()
		t.relayManager = nil
	}
	if t.peerTestManager != nil {
		t.peerTestManager.Stop()
		t.peerTestManager = nil
	}
	if t.holePunchCoord != nil {
		t.holePunchCoord.Stop()
		t.holePunchCoord = nil
	}
	if t.keyRotationManager != nil {
		t.keyRotationManager.Stop()
		t.keyRotationManager = nil
	}
	if t.portMapperManager != nil {
		_ = t.portMapperManager.Stop()
		t.portMapperManager = nil
	}
	// introducerRegistry has no Stop method; just replace it.
	t.introducerRegistry = nil
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
		// H2 fix: Full Ed25519 signature verification for RelayIntro blocks
		// Verifies that the RelayIntro was signed by Alice and covers the correct peers
		VerifyRelayIntroSignature: func(block *ssu2noise.RelayIntroBlock) error {
			return t.verifyRelayIntroSignature(block, session)
		},

		// Per-session signature verifiers. go-noise's DataHandler verifies
		// signatures BEFORE dispatching to the On* callbacks above and fails
		// closed (VERIFIER_MISSING) when a signed block arrives with no
		// verifier registered, so these are what actually make peer testing and
		// relaying work. Each closure supplies the session peer's router hash --
		// the block does not carry it and the transport cannot know it any other
		// way.
		VerifyPeerTestSignature: func(block *ssu2noise.PeerTestBlock) error {
			return t.verifyPeerTestSignature(block, extractSenderHash(session))
		},
		VerifyRelayRequestSignature: func(block *ssu2noise.RelayRequestBlock) error {
			// Alice is our session peer when she sends us a RelayRequest, so
			// senderHash is both the signer and (per §"RelayRequest") the bhash
			// is ours. verifyRelayRequestSignature resolves Charlie from the
			// relay tag we issued.
			valid, err := t.verifyRelayRequestSignature(block, extractSenderHash(session))
			return relayVerifierResult(valid, err)
		},
		VerifyRelayResponseSignature: func(block *ssu2noise.RelayResponseBlock) error {
			valid, err := t.verifyRelayResponseSignature(block, extractSenderHash(session))
			return relayVerifierResult(valid, err)
		},
	}
}

// relayVerifierResult collapses the legacy (bool, error) verifier shape into
// the error-only shape go-noise's DataHandlerCallbacks expects. A (false, nil)
// result -- which the old API documented as "gracefully skip" -- must NOT be
// treated as success here: an unsigned-but-required block silently passing
// verification is exactly the forgery vector the spec's signature rules exist
// to close, so it becomes an error.
func relayVerifierResult(valid bool, err error) error {
	if err != nil {
		return err
	}
	if !valid {
		return oops.Errorf("signature verification did not succeed")
	}
	return nil
}

// handleRouterInfoBlock processes RouterInfo block data received from a peer.
// If RouterStoreFunc is configured, it delegates storage to NetDB; otherwise
// it logs and skips processing (test/default behavior).
// E-4 fix: Emits a warn-level log (once per transport lifetime) when RouterInfo
// blocks arrive but RouterStoreFunc is nil, to catch misconfiguration in production.
func (t *SSU2Transport) handleRouterInfoBlock(data []byte) error {
	// Atomic config snapshot
	cfg := t.config.Load()
	if cfg.RouterStoreFunc == nil {
		// Warn once if RouterInfo blocks are received but no store function is configured.
		// This indicates misconfiguration: RouterStoreFunc must be wired for production
		// to allow reply routing. Tests can ignore this safely.
		t.routerStoreWarnOnce.Do(func() {
			t.logger.Warn("Received RouterInfo block but RouterStoreFunc not configured; reply routing may fail (RouterStoreFunc must be set for production)")
		})
		t.logger.Debug("Received RouterInfo block but RouterStoreFunc not configured (using default callbacks)")
		return nil
	}
	if err := cfg.RouterStoreFunc(data); err != nil {
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
	// Atomic config snapshot
	cfg := t.config.Load()
	if cfg.RouterLookupFunc == nil {
		return false, oops.Errorf("signature verification unavailable: RouterLookupFunc not configured")
	}
	ri, err := cfg.RouterLookupFunc(senderHash)
	if err != nil {
		t.logger.WithField("sender_hash", senderHash[:4]).Warn("RelayRequest: failed to lookup sender RouterInfo for signature verification")
		return false, oops.Wrapf(err, "netdb lookup failed for sender %x", senderHash[:4])
	}
	pubKey, err := extractEd25519PublicKey(ri)
	if err != nil {
		return false, oops.Wrapf(err, "failed to extract Ed25519 public key from sender RouterInfo")
	}

	// Look up Charlie's hash from the relay tag
	// Acquire read lock to safely read relayManager.
	// SetIdentity can modify this pointer, so we must hold the lock for consistency.
	t.natManagerMu.RLock()
	relayMgr := t.relayManager
	t.natManagerMu.RUnlock()

	if relayMgr == nil {
		return false, oops.Errorf("signature verification unavailable: relay manager not configured")
	}
	relayTag := relayMgr.GetRelayTag(block.RelayTag)
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
// block.
//
// Returns (true, nil) if the signature is valid (or genuinely absent), and
// (false, error) on failure or when verification cannot be performed
// (fail-closed).
//
// Which key verifies the block depends on the code AND on our role, per
// ssu2.rst §"RelayResponse": "If Charlie agrees (response code 0) or rejects
// (response code 64 or higher), Charlie signs the response"; "If Bob rejects
// (response code 1-63), Bob signs"; and the signature always covers
// "prologue, Bob's hash, and signed data". senderHash is the session peer the
// block arrived on, which is Charlie when we are Bob but Bob when we are Alice
// -- so treating senderHash as both the signer and bhash (as this function
// previously did) only ever worked for one role, and not for the role that
// actually consumes the response. The go-i2p delivery path (handleRelayResponseBlock
// -> deliverRelayResponse) is Alice-side, so the previous logic was wrong on
// the live path.
func (t *SSU2Transport) verifyRelayResponseSignature(block *ssu2noise.RelayResponseBlock, senderHash data.Hash) (bool, error) {
	if block == nil {
		return false, oops.Errorf("RelayResponse: nil block")
	}
	if senderHash == (data.Hash{}) {
		return false, oops.Errorf("RelayResponse: unknown session peer for nonce %d", block.Nonce)
	}

	// Charlie's field layout makes the signature optional: "Not present if
	// rejected by Bob." go-noise's dispatcher already fails closed when a
	// signature is present but no verifier is configured, so an absent
	// signature on a Bob rejection is legitimate and needs no check here.
	if len(block.Signature) == 0 {
		if block.Code == 0 || block.Code >= 64 {
			return false, oops.Errorf("RelayResponse code %d requires Charlie's signature but none present", block.Code)
		}
		return true, nil
	}

	ourHash := t.getOurIdentityHash()
	var (
		signerHash data.Hash
		bhash      data.Hash
		port       uint16
		ip         net.IP
	)

	switch t.natRoleFor(block.Nonce) {
	case natRoleBob:
		// We are the relay: Charlie's response arrives on his session. Charlie
		// signs either an accept (code 0) or his own rejection (code >= 64),
		// and both include the Charlie endpoint, so csz comes from the block.
		bhash = ourHash
		signerHash = senderHash // Charlie
		port, ip = block.CharliePort, block.CharlieIP
	case natRoleAlice:
		// We are the relay client: the response arrives forwarded by Bob.
		bhash = senderHash // Bob
		if block.Code >= 1 && block.Code <= 63 {
			// Bob's own rejection, signed by Bob with csz = 0, so the Charlie
			// endpoint is left out of the signed data entirely.
			signerHash = senderHash
			port, ip = 0, nil
		} else {
			// Accept or Charlie rejection: Charlie signed it, and Bob forwarded
			// the block unmodified. Charlie is not our session peer here, so
			// his identity must come from the relay context we authenticated.
			ch, ok := t.lookupCharlieForNonce(block.Nonce)
			if !ok {
				return false, oops.Errorf("RelayResponse: no authenticated Charlie context for nonce %d", block.Nonce)
			}
			signerHash = ch
			port, ip = block.CharliePort, block.CharlieIP
		}
	default:
		// No context for this nonce means we never asked for this relay.
		// Anything arriving for an unknown nonce is unsolicited and must not
		// influence anything: the intro key it is sealed with is public.
		return false, oops.Errorf("RelayResponse: no relay context for nonce %d (unsolicited)", block.Nonce)
	}

	pubKey, err := t.signingKeyForHash(signerHash)
	if err != nil {
		t.logger.WithField("signer_hash", signerHash[:4]).Warn("RelayResponse: failed to resolve signer RouterInfo")
		return false, oops.Wrapf(err, "netdb lookup failed for signer %x", signerHash[:4])
	}

	valid, verifyErr := ssu2noise.VerifyRelayResponseSignature(
		pubKey,
		block.Signature,
		bhash,
		block.Nonce,
		block.Timestamp,
		block.Version,
		port,
		ip,
	)
	if verifyErr != nil {
		t.logger.WithField("signer_hash", signerHash[:4]).Warn("RelayResponse signature verification failed")
		return false, oops.Wrapf(verifyErr, "signature verification failed")
	}
	if !valid {
		t.logger.WithField("signer_hash", signerHash[:4]).Warn("RelayResponse signature invalid")
		return false, oops.Errorf("invalid RelayResponse signature from %x", signerHash[:4])
	}
	return true, nil
}

// verifyPeerTestSignature verifies the Ed25519 signature on a PeerTest block.
//
// Returns nil when the signature is valid; a non-nil error means either the
// signature is invalid or verification could not be performed (fail-closed).
// The previous (bool, error) form was redundant -- every invalid path also
// returned an error -- and risked future callers misreading a (false, nil)
// tuple as success.
//
// Per ssu2.rst §"Peer Test Block" / §"Signatures" a peer-test signature is
// made by Alice (messages 1 and 2) or Charlie (messages 3 and 4) over
// "prologue, Bob's hash, and signed data", where the Alice hash is "Only used
// in the signature for messages 3 and 4; not included in message 3 or 4" and
// the hash field itself is "only present in messages 2 and 4". So NEITHER the
// signer NOR the bhash/ahash inputs can be taken from the wire alone: they
// depend on which role we are playing in the transaction. senderHash is the
// router on the other end of the session the block arrived on, which is only
// the signer for message 1 (Alice -> us as Bob) and message 3 (Charlie -> us
// as Bob). Deriving everything from senderHash -- as this function previously
// did -- verifies every message against the wrong key and the wrong hashes, so
// a legitimate peer test could never pass verification.
//
// The identities that are not on the wire come from t.natContexts, which is
// populated only from data we already authenticated.
func (t *SSU2Transport) verifyPeerTestSignature(block *ssu2noise.PeerTestBlock, senderHash data.Hash) error {
	if block == nil {
		return oops.Errorf("PeerTest: nil block")
	}
	// Messages 5-7 arrive out-of-session, so there is no session peer to
	// require; their signer comes from the nonce context instead. Only the
	// in-session codes need senderHash.
	if senderHash == (data.Hash{}) && block.MessageCode <= ssu2noise.PeerTestResult {
		return oops.Errorf("PeerTest: unknown session peer, cannot verify message %d", block.MessageCode)
	}

	ourHash := t.getOurIdentityHash()

	// Resolve the signer, bhash and ahash for this message code given our role.
	var (
		signerHash data.Hash
		bhash      data.Hash
		ahash      *data.Hash
	)
	switch block.MessageCode {
	case ssu2noise.PeerTestRequest: // msg 1: Alice -> Bob. We are Bob.
		signerHash = senderHash // Alice, our session peer
		bhash = ourHash
		// Messages 1 and 2 sign without an Alice hash: bhash identifies us.
	case ssu2noise.PeerTestRelay: // msg 2: Bob -> Charlie. We are Charlie.
		if block.RouterHash == nil {
			return oops.Errorf("PeerTest msg 2 to us as Charlie carries no Alice hash")
		}
		signerHash = *block.RouterHash // Alice
		bhash = senderHash             // Bob, our session peer
		ah := *block.RouterHash
		ahash = &ah
	case ssu2noise.PeerTestResponse: // msg 3: Charlie -> Bob. We are Bob.
		signerHash = senderHash // Charlie, our session peer
		bhash = ourHash
		// Alice's hash is covered by the signature but is not present on the
		// wire in message 3, so it must come from what we learned at message 1.
		ah, ok := t.lookupAliceForNonce(block.Nonce)
		if !ok {
			return oops.Errorf("PeerTest msg 3: no authenticated Alice context for nonce %d", block.Nonce)
		}
		ahash = &ah
	case ssu2noise.PeerTestResult: // msg 4: Bob -> Alice. We are Alice.
		if block.RouterHash == nil {
			return oops.Errorf("PeerTest msg 4 to us as Alice carries no Charlie hash")
		}
		signerHash = *block.RouterHash // Charlie
		bhash = senderHash             // Bob, our session peer
		ah := ourHash
		ahash = &ah
	default:
		// Messages 5-7 are out-of-session and their signature is optional
		// ("Signature is optional" per §"Peer Test Process"). When one IS
		// present we still have to attribute it: 5 and 7 are signed by Charlie
		// and 6 by Alice, neither of whom is the UDP source. If the signer
		// cannot be resolved from authenticated context, reject rather than
		// skip -- a present-but-unverifiable signature must never be treated
		// as valid.
		if len(block.Signature) == 0 {
			return nil
		}
		signer, ok := t.outOfSessionPeerTestSigner(block)
		if !ok {
			return oops.Errorf("PeerTest msg %d: cannot resolve signer for nonce %d", block.MessageCode, block.Nonce)
		}
		// §"Peer Test Process": "Messages 5 and 7 may contain the same signed
		// data as sent in messages 3 and 4" and "Message 6 may contain the same
		// signed data as sent in messages 1 and 2". The signed-data recipe in
		// §"Signatures" uses bhash = Bob's hash always, and ahash only for
		// messages 3 and 4 -- so 5 and 7 (Charlie's agreement, mirroring 3/4)
		// take ahash = Alice's hash (us), while 6 (Alice's request, mirroring
		// 1/2) takes NO ahash at all.
		b, ok := t.lookupBobForNonce(block.Nonce)
		if !ok {
			return oops.Errorf("PeerTest msg %d: no authenticated Bob context for nonce %d", block.MessageCode, block.Nonce)
		}
		signerHash = signer
		bhash = b
		if block.MessageCode != ssu2noise.PeerTestReply {
			ah := ourHash // we are Alice
			ahash = &ah
		}
	}

	pubKey, err := t.signingKeyForHash(signerHash)
	if err != nil {
		t.logger.WithField("signer_hash", signerHash[:4]).Warn("PeerTest: failed to resolve signer RouterInfo")
		return oops.Wrapf(err, "netdb lookup failed for signer %x", signerHash[:4])
	}

	valid, verifyErr := ssu2noise.VerifyPeerTestSignature(
		pubKey,
		block.Signature,
		bhash,
		ahash,
		block.Version,
		block.Nonce,
		block.Timestamp,
		block.AlicePort,
		block.AliceIP,
	)
	if verifyErr != nil {
		t.logger.WithField("signer_hash", signerHash[:4]).Warn("PeerTest signature verification failed")
		return oops.Wrapf(verifyErr, "signature verification failed")
	}
	if !valid {
		t.logger.WithField("signer_hash", signerHash[:4]).Warn("PeerTest signature invalid")
		return oops.Errorf("invalid PeerTest signature from %x", signerHash[:4])
	}
	return nil
}

// outOfSessionPeerTestSigner resolves the signing router for an out-of-session
// peer-test message (5, 6 or 7). Charlie signs 5 and 7, Alice signs 6.
//
// The UDP source address is useless for this: Charlie sends 5/7 from his own
// NAT endpoint and the message is not tied to a session. The identity therefore
// has to come from the in-session half of the same transaction, which we
// verified when it arrived. A nonce we have no context for is unsolicited.
func (t *SSU2Transport) outOfSessionPeerTestSigner(block *ssu2noise.PeerTestBlock) (data.Hash, bool) {
	switch block.MessageCode {
	case ssu2noise.PeerTestProbe, ssu2noise.PeerTestConfirmation:
		return t.lookupCharlieForNonce(block.Nonce)
	case ssu2noise.PeerTestReply:
		return t.lookupAliceForNonce(block.Nonce)
	default:
		return data.Hash{}, false
	}
}

// signingKeyForHash resolves a router's Ed25519 signing public key from the
// netdb. Fails closed when no lookup is configured.
func (t *SSU2Transport) signingKeyForHash(hash data.Hash) (i2ped25519.Ed25519PublicKey, error) {
	cfg := t.config.Load()
	if cfg == nil || cfg.RouterLookupFunc == nil {
		return nil, oops.Errorf("signature verification unavailable: RouterLookupFunc not configured")
	}
	ri, err := cfg.RouterLookupFunc(hash)
	if err != nil {
		return nil, oops.Wrapf(err, "netdb lookup failed for %x", hash[:4])
	}
	return extractEd25519PublicKey(ri)
}

// extractEd25519PublicKey extracts the Ed25519 signing public key from a RouterInfo.
// Returns an error if the key type is not Ed25519 or extraction fails.
func extractEd25519PublicKey(ri router_info.RouterInfo) (i2ped25519.Ed25519PublicKey, error) {
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
	return i2ped25519.Ed25519PublicKey(keyBytes), nil
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
	// Use locked accessor to avoid race with DetachConn.
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
	// Acquire read lock to safely read peerTestManager.
	// SetIdentity can modify this pointer, so we must hold the lock for consistency.
	t.natManagerMu.RLock()
	mgr := t.peerTestManager
	t.natManagerMu.RUnlock()

	if mgr == nil {
		return nil
	}
	ptBlock, err := ssu2noise.DecodePeerTestBlock(block)
	if err != nil {
		t.logger.WithField("error", err).Warn("failed to decode PeerTest block")
		return err
	}
	// Route strictly by message code and the role that code implies for US.
	// ssu2.rst §"Peer Test Process" fixes the direction of every message, so a
	// code uniquely determines which party we must be: 1 arrives only at Bob, 2
	// only at Charlie, 3 only at Bob (Charlie's response) and 4 only at Alice
	// (Bob's result). The previous "default -> Alice" catch-all sent message 3
	// to the initiator handler, which recorded Charlie's response as if it were
	// our own external-address observation and completed the wrong test.
	switch ptBlock.MessageCode {
	case ssu2noise.PeerTestRequest: // 1: Alice -> Bob
		return t.handlePeerTestAsBob(ptBlock, session, mgr)
	case ssu2noise.PeerTestRelay: // 2: Bob -> Charlie
		return t.handlePeerTestAsCharlie(ptBlock, session, mgr)
	case ssu2noise.PeerTestResponse: // 3: Charlie -> Bob
		return t.handlePeerTestResponseAsBob(ptBlock, session, mgr)
	case ssu2noise.PeerTestResult: // 4: Bob -> Alice
		return t.handlePeerTestResultAsAlice(ptBlock, session, mgr)
	default:
		t.logger.WithField("code", uint8(ptBlock.MessageCode)).
			Debug("PeerTest: unexpected message code on an in-session block")
		return nil
	}
}

// handlePeerTestResponseAsBob handles PeerTest message 3 (Charlie's response,
// arriving on our session with Charlie while we are relaying for Alice).
//
// Per ssu2.rst §"Peer Test Process" Bob must forward the result to Alice as
// message 4, and §"Peer Test Block" Notes requires "Bob must send Charlie's RI
// to Alice prior to sending message 4, if accepted (reason code 0)". The
// signature on message 3 was already verified before dispatch with Alice's hash
// taken from the context we recorded at message 1.
func (t *SSU2Transport) handlePeerTestResponseAsBob(ptBlock *ssu2noise.PeerTestBlock, session *SSU2Session, mgr *ssu2noise.PeerTestManager) error {
	charlieHash := extractSenderHash(session)
	if charlieHash == (data.Hash{}) {
		t.logger.Debug("PeerTest msg 3: cannot identify Charlie session, ignoring")
		return nil
	}
	aliceHash, ok := t.lookupAliceForNonce(ptBlock.Nonce)
	if !ok {
		// The verifier above already required this context, so reaching here
		// means the context expired between verification and dispatch.
		t.logger.WithField("nonce", ptBlock.Nonce).Debug("PeerTest msg 3: Alice context expired, dropping")
		return nil
	}
	// Record Charlie for the out-of-session messages: when Alice later receives
	// nothing from us she still cannot attribute message 5/7, but WE can use
	// this when relaying, and it is what the nonce context exists to hold.
	t.rememberCharlieForNonce(ptBlock.Nonce, charlieHash)

	aliceSession := t.findSessionByHash(aliceHash)
	if aliceSession == nil {
		t.logger.WithField("alice_hash", logutil.HashPrefixPlain(aliceHash)).
			Debug("PeerTest msg 3: no session to Alice, cannot forward result")
		return nil
	}

	// §"Peer Test Process" Notes: "Bob must send Charlie's RI to Alice prior to
	// sending message 4, if accepted (reason code 0)." Alice needs Charlie's
	// full RouterInfo to open the session she will build with the token from the
	// peer test, so this is only required on the accept path.
	if ptBlock.Code == 0 {
		if err := t.sendRouterInfoToPeer(aliceSession, charlieHash); err != nil {
			t.logger.WithField("error", err).Debug("PeerTest Bob: could not forward Charlie's RouterInfo to Alice")
		}
	}

	// §"Peer Test Block": message 4 carries Charlie's hash in the hash field,
	// which is how Alice knows whose agreement she is being given.
	charlie := charlieHash
	resultBlock := &ssu2noise.PeerTestBlock{
		MessageCode: ssu2noise.PeerTestResult,
		Code:        ptBlock.Code,
		RouterHash:  &charlie,
		Nonce:       ptBlock.Nonce,
		Version:     ptBlock.Version,
		Timestamp:   ptBlock.Timestamp,
		AlicePort:   ptBlock.AlicePort,
		AliceIP:     ptBlock.AliceIP,
		Signature:   ptBlock.Signature,
	}
	encoded, err := ssu2noise.EncodePeerTestBlock(resultBlock)
	if err != nil {
		return oops.Wrapf(err, "PeerTest msg 3: encode result block")
	}
	if err := aliceSession.WriteBlocks([]*ssu2noise.SSU2Block{encoded}); err != nil {
		return oops.Wrapf(err, "PeerTest msg 3: forward result to Alice")
	}
	if mgr != nil {
		if err := mgr.UpdateState(ptBlock.Nonce, ssu2noise.TestProbed); err != nil {
			t.logger.WithField("error", err).Debug("PeerTest msg 3: relay test state update failed")
		}
	}
	return nil
}

// handlePeerTestResultAsAlice handles PeerTest message 4 (Bob's forwarded
// result). The signature was already verified against Charlie's key, resolved
// from block.RouterHash, so the Charlie hash the block names is authenticated.
//
// Recording it here is what makes the out-of-session half usable: messages 5 and
// 7 arrive with no session behind them, and their (optional) signature can only
// be attributed to Charlie if we learned his identity from this in-session
// message.
func (t *SSU2Transport) handlePeerTestResultAsAlice(ptBlock *ssu2noise.PeerTestBlock, session *SSU2Session, mgr *ssu2noise.PeerTestManager) error {
	if ptBlock.RouterHash != nil {
		t.rememberCharlieForNonce(ptBlock.Nonce, *ptBlock.RouterHash)
	}
	bobHash := extractSenderHash(session)
	if bobHash != (data.Hash{}) {
		t.rememberBobForNonce(ptBlock.Nonce, bobHash)
	}
	t.setNatRole(ptBlock.Nonce, natRoleAlice)
	return t.handlePeerTestAsAlice(ptBlock, mgr)
}

// handlePeerTestAsAlice processes a PeerTest response/probe/result directed at
// the test initiator (Alice). It reconstructs the observed external address
// and completes the pending test. If 3+ PeerTest observations agree on the
// same external address within peerTestObservationWindow, the republish
// callback is invoked so the new address can be published to the netdb.
func (t *SSU2Transport) handlePeerTestAsAlice(ptBlock *ssu2noise.PeerTestBlock, mgr *ssu2noise.PeerTestManager) error {
	nonce := ptBlock.Nonce
	externalAddr := extractAliceAddress(ptBlock)

	// Fail-closed if manager unavailable. Without this check,
	// an attacker can send unsolicited PeerTest replies when manager is nil
	// (e.g., after initialization failure) and bypass nonce verification,
	// poisoning the external address cache with arbitrary IPs.
	if mgr == nil {
		t.logger.Warn("PeerTest observation rejected: manager unavailable")
		return nil
	}

	// BUG FIX HIGH RD-1: Verify the PeerTest nonce belongs to a test this node
	// initiated before recording the observation. An attacker can send unsolicited
	// PeerTest replies with arbitrary nonces to poison the address-confirmation cache.
	// Fail-closed: if the nonce is unknown, ignore the observation entirely.
	test := mgr.GetTest(nonce)
	if test == nil {
		t.logger.WithField("nonce", nonce).Warn("PeerTest: ignoring observation with unknown nonce (potential injection attack)")
		return nil
	}

	result := &ssu2noise.TestResult{
		ExternalAddr: externalAddr,
		Reachable:    externalAddr != nil,
	}
	if completeErr := mgr.CompleteTest(nonce, result); completeErr != nil {
		t.logger.Debug("PeerTest complete (non-initiator path)")
	}

	t.processExternalAddressConfirmation(externalAddr, nonce)
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
func (t *SSU2Transport) processExternalAddressConfirmation(externalAddr *net.UDPAddr, nonce uint32) {
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

	confirmed := t.natStateCache.recordObservation(externalAddr.String(), nonce)
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
func (t *SSU2Transport) handlePeerTestAsBob(ptBlock *ssu2noise.PeerTestBlock, session *SSU2Session, mgr *ssu2noise.PeerTestManager) error {
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

	// The signature above validated that Alice (our session peer) signed this
	// request, so her identity is now authenticated for this nonce. We record it
	// because message 3 from Charlie must be verified with Alice's hash in the
	// signed data, and §"Peer Test Block" states that hash is not carried in
	// message 3 -- it has to come from what we learned here.
	t.setNatRole(ptBlock.Nonce, natRoleBob)
	t.rememberAliceForNonce(ptBlock.Nonce, senderHash)

	charlieHash, charlieAddr := t.selectCharlieForPeerTest(aliceAddr)
	if charlieAddr == nil {
		t.logger.Debug("PeerTest Bob: no Charlie available for this address family, ignoring")
		return nil
	}
	// mgr is already locked and safe to use
	if mgr != nil {
		if _, err := mgr.CreateRelayTest(ptBlock.Nonce, aliceAddr, charlieAddr); err != nil {
			t.logger.WithField("error", err).Debug("PeerTest Bob: failed to create relay test")
			return nil
		}
	}
	t.rememberCharlieForNonce(ptBlock.Nonce, charlieHash)

	// §"Peer Test Process" Notes: "Bob must send Alice's RI to Charlie prior to
	// sending message 2." Charlie needs Alice's RouterInfo to reach her with the
	// out-of-session probe, and message 2 gives him only her hash.
	charlieSession := t.findSessionByHash(charlieHash)
	if err := t.sendRouterInfoToPeer(charlieSession, senderHash); err != nil {
		t.logger.WithField("error", err).Debug("PeerTest Bob: could not forward Alice's RouterInfo to Charlie")
	}

	return t.forwardPeerTestToCharlie(ptBlock, charlieAddr, senderHash, charlieHash)
}

// selectCharlieForPeerTest picks the responder Bob relays a peer test to.
//
// ssu2.rst §"Peer Test Block" Notes: "When Bob receives a request from Alice via
// IPv4, Bob must select a Charlie that advertises an IPv4 address. When Bob
// receives a request from Alice via IPv6, Bob must select a Charlie that
// advertises an IPv6 address." So the choice is ours, driven by the family of
// the address Alice asked us to test -- it is NOT read from the block: the same
// section states the hash field is "only present in messages 2 and 4", so
// message 1 carries no Charlie (or Alice) hash at all. The previous
// implementation looked up ptBlock.RouterHash here, which is always nil on a
// conformant message 1, so Bob silently dropped every peer-test request and the
// relay never started.
//
// Candidates come from the introducer registry the router maintains from
// connected peers. Bob needs a live session with Charlie to send message 2
// in-session, so a registered introducer we are not connected to is unusable
// and is skipped.
func (t *SSU2Transport) selectCharlieForPeerTest(aliceAddr *net.UDPAddr) (data.Hash, *net.UDPAddr) {
	t.natManagerMu.RLock()
	registry := t.introducerRegistry
	t.natManagerMu.RUnlock()
	if registry == nil {
		return data.Hash{}, nil
	}

	wantV6 := aliceAddr != nil && aliceAddr.IP != nil && aliceAddr.IP.To4() == nil
	for _, intro := range registry.GetIntroducers() {
		if intro == nil || intro.Addr == nil {
			continue
		}
		isV6 := intro.Addr.IP != nil && intro.Addr.IP.To4() == nil
		if isV6 != wantV6 {
			continue
		}
		hash, err := hashFromIntroBytes(intro.RouterHash)
		if err != nil {
			continue
		}
		// Message 2 must travel in-session (§"Peer Test Process": "Messages 1-4
		// must be contained in a Data message in an existing session"), so we
		// can only use a Charlie we actually have a session with.
		session := t.findSessionByHash(hash)
		if session == nil {
			continue
		}
		if addr := session.RemoteUDPAddr(); addr != nil {
			return hash, addr
		}
	}
	return data.Hash{}, nil
}

// hashFromIntroBytes converts a 32-byte router hash from a registry entry.
func hashFromIntroBytes(b []byte) (data.Hash, error) {
	var h data.Hash
	if len(b) != len(h) {
		return h, oops.Errorf("router hash has unexpected size %d (want %d)", len(b), len(h))
	}
	copy(h[:], b)
	return h, nil
}

// forwardPeerTestToCharlie builds a PeerTestRelay (message 2) block and sends it
// to Charlie via an existing session.
//
// aliceHash is the router hash Bob learned from Alice's session. Per ssu2.rst
// §"Peer Test Block", the 32-byte hash field is "Alice's or Charlie's router
// hash, only present in messages 2 and 4", so message 2 must carry Alice's hash
// and EncodePeerTestBlock fails closed without it. Passing it through is also
// what lets Charlie resolve Alice's introduction key for the out-of-session
// probe (message 5) without a separate lookup.
func (t *SSU2Transport) forwardPeerTestToCharlie(ptBlock *ssu2noise.PeerTestBlock, charlieAddr *net.UDPAddr, aliceHash, charlieHash data.Hash) error {
	// Prefer the hash- keyed lookup: selectCharlieForPeerTest already proved a
	// session exists for this Charlie, and an address lookup can miss it when the
	// session was re-keyed onto a different port.
	session := t.findSessionByHash(charlieHash)
	if session == nil {
		session = t.findSessionByAddr(charlieAddr)
	}
	if session == nil {
		t.logger.Debug("PeerTest Bob: no session to Charlie for relay")
		return nil
	}
	relayBlock := &ssu2noise.PeerTestBlock{
		MessageCode: ssu2noise.PeerTestRelay,
		RouterHash:  &aliceHash,
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
// (responder). We record the test and send the direct probe to Alice.
//
// The probe is peer-test message 5, which ssu2.rst §"Peer Test Process" places
// out-of-session ("Messages 5-7 are out-of-session using Peer Test blocks in a
// Peer Test message"), sealed under Alice's intro key. It therefore travels on
// the listener socket, not on the Bob session the relay arrived over, so no
// session is needed here.
func (t *SSU2Transport) handlePeerTestAsCharlie(ptBlock *ssu2noise.PeerTestBlock, session *SSU2Session, mgr *ssu2noise.PeerTestManager) error {
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
	// ssu2.rst §"Peer Test Block": the hash field is "Alice's or Charlie's router
	// hash, only present in messages 2 and 4", and this is message 2, so the
	// block identifies Alice. Her intro key (needed to seal the out-of-session
	// probe) is resolved from it. The block went through signature verification
	// before dispatch, and that verifier required this hash to be present, so it
	// is authenticated context rather than an unverified claim.
	if ptBlock.RouterHash == nil {
		t.logger.Debug("PeerTest Charlie: message 2 carried no Alice hash, ignoring")
		return nil
	}
	aliceHash := *ptBlock.RouterHash

	bobHash := extractSenderHash(session)
	bobAddr := session.RemoteUDPAddr()

	// Record the transaction identities before emitting anything. Message 6
	// arrives out-of-session from Alice with no session to attribute it to, so
	// the only way to know who signed it (Alice) and who bhash refers to (Bob)
	// is what we learned here, from the authenticated message 2.
	t.setNatRole(ptBlock.Nonce, natRoleCharlie)
	t.rememberAliceForNonce(ptBlock.Nonce, aliceHash)
	if bobHash != (data.Hash{}) {
		t.rememberBobForNonce(ptBlock.Nonce, bobHash)
	}

	// mgr is already locked and safe to use
	if mgr != nil && bobAddr != nil {
		if err := mgr.CreateResponderTest(ptBlock.Nonce, aliceAddr, bobAddr); err != nil {
			t.logger.WithField("error", err).Debug("PeerTest Charlie: failed to create responder test")
			return nil
		}
	}
	return t.sendPeerTestProbeToAlice(ptBlock, aliceAddr, aliceHash)
}

// anyActiveSession returns the first active SSU2Session, or nil if none exist.
func (t *SSU2Transport) anyActiveSession() *SSU2Session {
	var found *SSU2Session
	t.sessionRegistry.Range(func(_, value interface{}) bool {
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
	// Acquire read lock to safely read relayManager.
	// SetIdentity can modify this pointer, so we must hold the lock for consistency.
	t.natManagerMu.RLock()
	mgr := t.relayManager
	t.natManagerMu.RUnlock()

	if mgr == nil || block == nil {
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

	return t.forwardRelayIntro(req, mgr)
}

// forwardRelayIntro looks up the relay tag target (Charlie), builds a
// RelayIntro block, and writes it to Charlie's session.
// Rejects when no relay tag is registered for the requested tag value or when
// there is no active session to Charlie. Enforces introducer capability
// validation (caps=B) via RouterLookupFunc before forwarding.
func (t *SSU2Transport) forwardRelayIntro(req *ssu2noise.RelayRequestBlock, mgr *ssu2noise.RelayManager) error {
	// mgr is already locked and safe to use
	if mgr == nil {
		return nil
	}
	tag := mgr.GetRelayTag(req.RelayTag)
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
	if t == nil || session == nil || session.conn == nil {
		return false
	}
	// Atomic config snapshot
	cfg := t.config.Load()
	if cfg == nil || cfg.RouterLookupFunc == nil {
		return false
	}
	addr, ok := session.conn.RemoteAddr().(*ssu2noise.SSU2Addr)
	if !ok {
		return false
	}
	rh := data.Hash(addr.RouterHash())
	ri, err := cfg.RouterLookupFunc(rh)
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
	// Acquire read lock to safely read relayManager.
	t.natManagerMu.RLock()
	mgr := t.relayManager
	t.natManagerMu.RUnlock()
	return mgr != nil && block != nil
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
	// Acquire read lock to safely read holePunchCoord.
	t.natManagerMu.RLock()
	coord := t.holePunchCoord
	t.natManagerMu.RUnlock()

	if coord == nil || block == nil {
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

	return t.initiateHolePunch(intro, bobSession, coord)
}

// initiateHolePunch starts a hole-punch towards Alice based on a RelayIntro,
// sends a HolePunch datagram to Alice, and sends a RelayResponse to Bob.
// bobSession carries Bob's session (from which the RelayIntro arrived).
func (t *SSU2Transport) initiateHolePunch(intro *ssu2noise.RelayIntroBlock, bobSession *SSU2Session, coord *ssu2noise.HolePunchCoordinator) error {
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
	// E-2 fix (defense-in-depth): Guard against nil holePunchCoord (NAT-degraded mode).
	// coord is already locked and safe to use
	if coord == nil {
		t.logger.Warn("hole-punch: coordinator unavailable (NAT-degraded mode); cannot complete hole-punch")
		return oops.Errorf("NAT managers not initialized")
	}
	_, err := coord.InitiateHolePunch(aliceAddr, bobAddr, intro.AliceRelayTag)
	if err != nil {
		t.logger.WithField("error", err).Warn("hole-punch coordinator registration failed; not sending hole-punch/RelayResponse")
		return err
	}

	// Alice's router hash identifies whose intro key seals the Hole Punch. The
	// RelayIntro block carries it (§"RelayIntro": "Alice's router hash") and its
	// signature was verified above, so it is trustworthy here.
	aliceHash := data.Hash{}
	if len(intro.AliceRouterHash) == 32 {
		copy(aliceHash[:], intro.AliceRouterHash)
	}

	// The Hole Punch message carries the Relay Response block (§"Hole Punch
	// (Type 11)" payload list), and it must be the identical block Bob forwards
	// to Alice in message 4 -- i2pd reuses the exact bytes. Build it once here
	// and share it between the two emissions so Alice can verify a signature she
	// actually receives.
	resp, respErr := t.buildRelayResponse(bobSession, intro)
	if respErr != nil {
		t.logger.WithField("error", respErr).Warn("hole-punch: could not build RelayResponse")
	}

	// The hole-punch datagram itself is best-effort: if Alice's intro key cannot
	// be resolved we still owe Bob a RelayResponse (or a rejection), and Bob
	// forwards it to Alice in-session.
	if respErr == nil {
		if err := t.sendHolePunchToAlice(intro, aliceAddr, aliceHash, resp); err != nil {
			t.logger.WithField("error", err).Debug("hole-punch: send to Alice failed")
		}
	}

	if err := t.sendRelayResponseToBob(bobSession, resp, respErr); err != nil {
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
	// Atomic config snapshot
	cfg := t.config.Load()
	if cfg.RouterLookupFunc == nil {
		return oops.Errorf("signature verification unavailable: RouterLookupFunc not configured")
	}
	aliceRI, err := cfg.RouterLookupFunc(aliceHash)
	if err != nil {
		t.logger.WithField("alice_hash", aliceHash[:4]).Warn("RelayIntro: failed to lookup Alice's RouterInfo for signature verification")
		return oops.Wrapf(err, "netdb lookup failed for Alice %x", aliceHash[:4])
	}
	alicePubKey, err := extractEd25519PublicKey(aliceRI)
	if err != nil {
		return oops.Wrapf(err, "failed to extract Ed25519 public key from Alice's RouterInfo")
	}

	// Extract Bob's router hash from the session
	bobHash := extractBobRouterHash(bobSession)

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

// sendRelayResponseToBob signs and sends a RelayResponse (code=0) to Bob so
// that Bob can forward it to Alice. Alice uses Charlie's IP/Port and token to
// send the SSU2 SessionRequest directly to us.
func (t *SSU2Transport) sendRelayResponseToBob(bobSession *SSU2Session, resp *ssu2noise.RelayResponseBlock, buildErr error) error {
	if buildErr != nil {
		// We cannot produce an accepted RelayResponse, so tell Bob we are
		// rejecting rather than staying silent: per ssu2.rst §"Relay Process",
		// a RelayResponse with a non-zero code is how Charlie declines, and
		// without it Alice waits on a relay that will never come.
		reject := &ssu2noise.RelayResponseBlock{
			Code:  relayResponseCharlieUnspecified,
			Nonce: respNonceOrZero(resp),
		}
		return t.sendEncodedRelayResponse(bobSession, reject)
	}
	return t.sendEncodedRelayResponse(bobSession, resp)
}

func respNonceOrZero(resp *ssu2noise.RelayResponseBlock) uint32 {
	if resp == nil {
		return 0
	}
	return resp.Nonce
}

// buildRelayResponse constructs the signed accepted RelayResponse for a relay
// request from Alice that we (as Charlie) are honouring.
//
// BUG FIX HIGH RD-2: uses the confirmed external address, not the local bind
// address. localIPPort() returns the listener bind address (often 0.0.0.0 or
// private), which breaks hole-punching when Charlie advertises an unreachable
// address.
func (t *SSU2Transport) buildRelayResponse(bobSession *SSU2Session, intro *ssu2noise.RelayIntroBlock) (*ssu2noise.RelayResponseBlock, error) {
	charlieIP, charliePort, err := t.externalAddressForRelay()
	if err != nil {
		return nil, oops.Wrapf(err, "hole-punch: external address")
	}

	signingKey, token, err := t.prepareRelayResponseCredentials()
	if err != nil {
		return nil, err
	}

	bobHash := extractBobRouterHash(bobSession)
	timestamp := uint32(time.Now().Unix())

	return t.buildSignedRelayResponse(signingKey, bobHash, intro, timestamp, charliePort, charlieIP, token)
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
	// Use locked accessor to avoid race with DetachConn.
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
	ed25519Key := i2ped25519.Ed25519PrivateKey(signingKeyBytes)
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

// IsInboundBlocked reports whether the most recent NAT detection concluded that
// unsolicited inbound connections are blocked, i.e. the router is reachable
// only via introducers / hole-punching (restricted, port-restricted, or
// symmetric NAT). Returns false when the NAT type is unknown or indicates
// direct reachability (no NAT / full-cone), so callers do not misreport a
// directly-reachable or not-yet-tested router as inbound-blocked.
func (t *SSU2Transport) IsInboundBlocked() bool {
	return t.InboundBlockedStatusCode() != 0
}

// InboundBlockedStatusCode maps the most recent NAT detection result to the
// I2PControl network-status code that most specifically describes how inbound
// connectivity is blocked, giving callers a granular view of the firewalled
// state rather than a single coarse "firewalled" verdict:
//
//	11 (ERROR_SYMMETRIC_NAT) — behind a symmetric NAT; per-destination port
//	 mapping prevents introducer-assisted inbound connections from working
//	 reliably.
//	 2 (FIREWALLED) — restricted or port-restricted NAT; reachable via
//	 introducers / hole-punching but not by unsolicited direct inbound.
//	 0 — inbound is not blocked: NAT type is unknown
//	 (not yet tested) or indicates direct reachability (no NAT / full-cone).
//
// Returning 0 for the unknown/direct cases ensures a directly-reachable or
// not-yet-tested router is never misreported as inbound-blocked.
func (t *SSU2Transport) InboundBlockedStatusCode() int {
	if t.natStateCache == nil {
		return 0
	}
	natType, valid := t.natStateCache.get()
	if !valid {
		return 0
	}
	switch {
	case ssu2noise.IsSymmetricNAT(natType):
		return 11 // ERROR_SYMMETRIC_NAT
	case ssu2noise.RequiresRelay(natType) || natType == ssu2noise.NATRestricted:
		return 2 // FIREWALLED
	default:
		return 0
	}
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

// DirectPublicExternalAddr returns the locally-determined external address
// ("ip:port") when this router is bound to — or its host owns — a publicly
// routable address (IPv4 or IPv6), or "" otherwise. Unlike GetCachedExternalAddr
// this does not depend on PeerTest having completed: a publicly-addressed host
// is directly reachable by definition. Callers use it as the authoritative
// "directly reachable" signal so a public node is never misreported as
// FIREWALLED or left stuck in TESTING when PeerTest cannot run (e.g. too few
// SSU2 peers).
func (t *SSU2Transport) DirectPublicExternalAddr() string {
	ip, port, ok := t.publicBoundAddress()
	if !ok {
		return ""
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))
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
// On NAT types that require introducers (Restricted or Symmetric), up to three
// candidates are registered in the IntroducerRegistry and republish (if non-nil)
// is invoked so the caller can re-publish the updated RouterInfo.
// The goroutine is tracked in the transport WaitGroup and exits cleanly when
// the transport context is cancelled.
func (t *SSU2Transport) StartNATDetection(candidates []router_info.RouterInfo, republish func()) {
	// Public-IP short-circuit: a host bound to (or whose interface owns) a
	// publicly routable address — IPv4 or IPv6 — is directly reachable by
	// definition. Seed the terminal DIRECT (NATNone) classification immediately
	// and skip PeerTest entirely, so reachability does not depend on having >=2
	// SSU2 peers or on probes succeeding — and so a PeerTest timeout can never
	// downgrade a genuinely public node to FIREWALLED.
	if t.seedDirectReachability() {
		if republish != nil {
			republish()
		}
		t.logger.Info("NAT detection: bound to a public IP; classified DIRECT, skipping PeerTest")
		return
	}

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

// seedDirectReachability inspects the transport's bound local address and, when
// it is publicly routable (IPv4 or IPv6), seeds the NAT state cache with a
// direct (NATNone) classification plus the corresponding external address.
// This is the public-IP short-circuit: a host with a public, routable address
// is deterministically classified "direct" without waiting for — or depending
// on — SSU2 PeerTest, which can silently fail when too few SSU2 peers are
// available or when probes are dropped. It is idempotent: it only writes when a
// public address is detected and the cache does not already hold the identical
// direct classification.
// Returns true when the host is directly reachable via a public address.
func (t *SSU2Transport) seedDirectReachability() bool {
	if t.natStateCache == nil {
		return false
	}
	ip, port, ok := t.publicBoundAddress()
	if !ok {
		return false
	}
	ext := net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))

	// Don't rewrite an identical existing direct classification.
	if cur, valid := t.natStateCache.get(); valid && ssu2noise.HasPublicIP(cur) &&
		t.natStateCache.getExternal() == ext {
		return true
	}
	t.natStateCache.set(ssu2noise.NATNone, ext)
	t.saveNATState()
	t.logger.WithField("external", ext).Info("NAT detection: public IP bound locally; classified DIRECT (short-circuit)")
	return true
}

// publicBoundAddress resolves the transport's externally-visible address and
// port when the local bind is itself a publicly routable IP (IPv4 or IPv6), or
// when a wildcard bind (0.0.0.0/::) is backed by a host interface that owns a
// publicly routable address. Returns ok=false when no public reachability can
// be established locally.
func (t *SSU2Transport) publicBoundAddress() (net.IP, uint16, bool) {
	ip, port, err := t.localIPPort()
	if err != nil {
		return nil, 0, false
	}
	if ip.IsUnspecified() {
		// Wildcard bind: probe interface addresses for a publicly routable IP.
		if ext := detectExternalIP(); ext != "" {
			if pip := net.ParseIP(ext); nat.IsPubliclyRoutableIP(pip) {
				return pip, port, true
			}
		}
		return nil, 0, false
	}
	if nat.IsPubliclyRoutableIP(ip) {
		return ip, port, true
	}
	return nil, 0, false
}

// runNATDetection carries out the NAT detection sequence inside a goroutine.
// T-1 fix: Uses single-flight pattern (natDetectionRunning flag) to prevent
// concurrent detection runs from overwriting shared retry state.
func (t *SSU2Transport) runNATDetection(candidates []router_info.RouterInfo, republish func()) {
	// T-1 fix: Single-flight check — if detection already running, skip this call.
	if !t.natDetectionRunning.CompareAndSwap(false, true) {
		t.logger.Debug("NAT detection already in progress; skipping concurrent run")
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

		// Step 4: write a *terminal* NAT classification so the router stops
		// reporting TESTING indefinitely once detection has genuinely given up.
		// Re-check the public-IP short-circuit first (an external IPv4 may have
		// appeared after startup): if directly reachable, classify DIRECT and
		// republish; otherwise record NATRestricted (relay required) and persist
		// it so GetNetworkStatus resolves to FIREWALLED rather than TESTING.
		if t.seedDirectReachability() {
			if republish != nil {
				republish()
			}
		} else {
			t.natStateCache.set(ssu2noise.NATRestricted, t.natStateCache.getExternal())
			t.saveNATState()
			// Register introducers for firewalled nodes
			t.registerIntroducers(candidates, republish)
		}

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
			t.logger.Debug("NAT detection: retry timer fired; re-running peer test")
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

	switch {
	case ssu2noise.RequiresRelay(natType) || natType == ssu2noise.NATRestricted:
		// Relay/hole-punch required (restricted, port-restricted, or symmetric
		// NAT): register introducers so peers can reach us via them.
		t.registerIntroducers(candidates, republish)
	case ssu2noise.HasPublicIP(natType) && extStr != "" && republish != nil:
		// Directly reachable (no NAT / full-cone NAT) with a detected external
		// address: republish immediately so the correct public IP is advertised
		// without waiting for the next periodic republish interval.
		// previously NATNone fell through here and the 'R' cap was never set
		// until the slow reachability loop ran.
		republish()
	}
	return true
}

// classifyNATType determines the NAT type from a completed test.
// The authoritative classification is the NATType the
// PeerTestManager already computed (via CompleteTest) and stored on the test.
// The previous implementation reconstructed a TestResult that omitted the
// DirectProbeSuccess/RelayedProbeSuccess/*Consistent fields that
// DetermineNATType keys on, so every completed test collapsed to NATUnknown.
// We trust test.NATType when it is a known type and only fall back to
// re-deriving from the full stored TestResult (which retains the probe fields)
// when the test left the type unresolved — keeping this path in agreement with
// GetNATType so the two classifiers cannot diverge.
func (t *SSU2Transport) classifyNATType(test *ssu2noise.PeerTest) ssu2noise.NATType {
	if test.NATType != ssu2noise.NATUnknown {
		return test.NATType
	}
	// Fall back to the full stored result, which preserves the probe-success
	// flags DetermineNATType requires.
	if t.peerTestManager != nil {
		if result := t.peerTestManager.GetResult(test.ExternalAddr); result != nil {
			return ssu2noise.DetermineNATType(result)
		}
	}
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
			"introducer_hash": logutil.BytePrefix(intro.RouterHash[:]),
			"relay_tag":       intro.RelayTag,
		}).Warn("Introducer registration failed; relay tag tracked for future cleanup")
		return false
	}
	return true
}

// trackAbandonedRelayTag records a relay tag that was allocated but not successfully
// registered. Provides monitoring and prepares for future cleanup when a release
// API becomes available in the RelayManager.
// Bound the slice to maxAbandonedRelayTags and prune entries older than maxAbandonedRelayTagAge.
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
// implements the D3 startup probe: 5 peers (raised from 3) report our
// external address with margin for failures, so majority-confirmation
// logic (threshold 3) can reliably confirm and republish it.
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
	// T-2/RD-1 FIX: Raised from 3 to 5 to provide margin for failures/timeouts.
	// peerTestConfirmThreshold requires 3 matching observations, so budget must
	// exceed threshold to account for lost/non-responding peers or per-observer
	// port variance on Restricted/Symmetric NAT. With 5 tests, confirmation is
	// achievable even if 2 tests fail/timeout.
	const startupPeerTestMax = 5
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

// validateAndExtractPort validates the listener address and extracts the internal port.
// Returns the port number and true if valid, or 0 and false if validation fails.
// Reads t.config.ListenerAddress under identityMu to avoid race with SetIdentity.
func (t *SSU2Transport) validateAndExtractPort() (int, bool) {
	// Atomic config snapshot
	cfg := t.config.Load()
	if cfg == nil {
		return 0, false
	}
	t.identityMu.RLock()
	listenerAddr := cfg.ListenerAddress
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
