package ssu2

import (
	"context"
	"crypto/ed25519"
	"net"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/go-i2p/crypto/rand"
	"github.com/samber/oops"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/transport"
	ssu2noise "github.com/go-i2p/go-noise/ssu2"
)

const (
	// relayRequestTimeout is how long Alice waits for Bob to forward a
	// RelayResponse after sending a RelayRequest.
	relayRequestTimeout = 10 * time.Second

	// introducerPhaseTimeout is the total time Alice waits for the entire
	// introducer phase (all concurrent attempts) before giving up. This
	// prevents sequential 10s waits from blocking the dial path for 30s+
	// when multiple slow introducers are present (T-2 remediation).
	introducerPhaseTimeout = 15 * time.Second
)

// dialViaIntroducer establishes a session to Charlie by routing through one of
// Charlie's introducers (Bob).
//
// SSU2 relay 6-step flow (§Relay in the SSU2 spec):
//  1. Alice → Bob:     RelayRequest (signed with Alice's Ed25519 key)
//  2. Bob   → Charlie: RelayIntro
//  3. Charlie → Bob:   RelayResponse
//  4. Bob   → Alice:   RelayResponse  (Code=0 ⇒ accepted, contains Charlie addr)
//  5. Charlie → Alice: HolePunch      (optional NAT punch-through)
//  6. Alice → Charlie: SessionRequest (direct UDP)
//
// T-2 fix: Introducers are tried concurrently with an overall phase deadline,
// taking the first successful result and canceling remaining attempts. This
// prevents sequential 10s waits from blocking the dial path for 30s+ when
// multiple slow introducers are present.
// EH-3 fix: Check NAT health before attempting introducer dial.
func (t *SSU2Transport) dialViaIntroducer(charlieRI router_info.RouterInfo, charlieHash data.Hash) (transport.TransportSession, error) {
	t.recordPeerAttempt(charlieHash)
	dialStart := time.Now()

	// R-2 fix: Atomic config snapshot
	cfg := t.config.Load()
	if cfg.RouterLookupFunc == nil {
		err := oops.Errorf("RouterLookupFunc not configured: cannot dial via introducer")
		t.recordPeerFailure(charlieHash, err)
		return nil, err
	}

	// EH-3 fix: Check NAT managers health before attempting relay/introducer dial.
	// Introducer-based connections require NAT managers (relay manager for RelayRequest,
	// hole punch coordinator for optional NAT punch-through). If NAT init failed,
	// relay will be unavailable and the dial will fail with confusing errors;
	// fail fast with a clear error instead.
	if !t.NATManagersHealthy() {
		err := oops.Errorf("NAT managers degraded: cannot dial via introducer (try direct addresses only)")
		t.recordPeerFailure(charlieHash, err)
		return nil, err
	}

	introducers := t.collectIntroducers(charlieRI)
	if len(introducers) == 0 {
		err := oops.Errorf("no valid introducers found for router %x", charlieHash[:4])
		t.recordPeerFailure(charlieHash, err)
		return nil, err
	}

	// T-2 fix: Apply an overall deadline to the entire introducer phase.
	ctx, cancel := context.WithTimeout(t.ctx, introducerPhaseTimeout)
	defer cancel()

	// Try all introducers concurrently with bounded fan-out.
	type result struct {
		session transport.TransportSession
		err     error
	}
	resultCh := make(chan result, len(introducers))

	// Launch concurrent attempts for each introducer.
	for _, intro := range introducers {
		intro := intro // capture loop variable
		go func() {
			session, err := t.tryOneIntroducerWithContext(ctx, charlieRI, charlieHash, intro)
			resultCh <- result{session: session, err: err}
		}()
	}

	// Collect results, taking the first success or the last error.
	var lastErr error
	for i := 0; i < len(introducers); i++ {
		select {
		case res := <-resultCh:
			if res.err == nil {
				// Success: cancel remaining attempts and return the session.
				cancel()
				t.recordPeerSuccess(charlieHash, time.Since(dialStart).Milliseconds())
				return res.session, nil
			}
			t.logger.WithField("error", res.err).Debug("introducer attempt failed")
			lastErr = res.err
		case <-ctx.Done():
			// Overall deadline exceeded.
			err := oops.Errorf("introducer phase timed out after %v: %w", introducerPhaseTimeout, ctx.Err())
			t.recordPeerFailure(charlieHash, err)
			return nil, err
		}
	}

	// All introducers failed.
	err := oops.Wrapf(lastErr, "all %d introducer(s) failed for router %x", len(introducers), charlieHash[:4])
	t.recordPeerFailure(charlieHash, err)
	return nil, err
}

// collectIntroducers gathers all distinct IntroducerAddr entries from all SSU2
// addresses in charlieRI.
func (t *SSU2Transport) collectIntroducers(charlieRI router_info.RouterInfo) []IntroducerAddr {
	var result []IntroducerAddr
	type introducerKey struct {
		hash data.Hash
		tag  uint32
	}
	seen := make(map[introducerKey]bool)
	for _, addr := range charlieRI.RouterAddresses() {
		if !isSSU2Transport(addr) {
			continue
		}
		for _, intro := range ExtractIntroducers(addr) {
			key := introducerKey{hash: intro.RouterHash, tag: intro.RelayTag}
			if !seen[key] {
				seen[key] = true
				result = append(result, intro)
			}
		}
	}
	return result
}

// tryOneIntroducer attempts relay through a single introducer entry.
// tryOneIntroducerWithContext attempts relay through a single introducer entry
// with a parent context for cancellation. This is the context-aware version
// used by concurrent introducer attempts (T-2 fix).
func (t *SSU2Transport) tryOneIntroducerWithContext(ctx context.Context, charlieRI router_info.RouterInfo, charlieHash data.Hash, intro IntroducerAddr) (transport.TransportSession, error) {
	// Check if context is already canceled before starting.
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Step 1 & 2: Get a session to Bob (the introducer).
	bobSSU2Session, err := t.establishBobSessionWithContext(ctx, intro)
	if err != nil {
		return nil, err
	}

	// Step 3 & 4: Send signed RelayRequest to Bob and wait for response.
	nonce := rand.Uint32()
	resp, err := t.sendRelayRequestAndWaitWithContext(ctx, bobSSU2Session, intro, charlieHash, nonce)
	if err != nil {
		return nil, err
	}

	// Step 5: Use Charlie's RelayResponse to dial Charlie directly.
	return t.dialCharlieDirectly(charlieRI, charlieHash, resp)
}

// tryOneIntroducer attempts relay through a single introducer entry.
// Kept for backward compatibility; wraps tryOneIntroducerWithContext with t.ctx.
func (t *SSU2Transport) tryOneIntroducer(charlieRI router_info.RouterInfo, charlieHash data.Hash, intro IntroducerAddr) (transport.TransportSession, error) {
	return t.tryOneIntroducerWithContext(t.ctx, charlieRI, charlieHash, intro)
}

// establishBobSessionWithContext looks up Bob's RouterInfo and establishes a session to Bob,
// honoring the parent context for cancellation.
func (t *SSU2Transport) establishBobSessionWithContext(ctx context.Context, intro IntroducerAddr) (*SSU2Session, error) {
	// R-2 fix: Atomic config snapshot
	cfg := t.config.Load()
	bobRI, err := cfg.RouterLookupFunc(intro.RouterHash)
	if err != nil {
		return nil, oops.Wrapf(err, "Bob (%x...) lookup failed", intro.RouterHash[:4])
	}

	// Note: GetSession doesn't support context yet, but if the parent context
	// is canceled, the concurrent attempt will be abandoned anyway.
	bobSession, err := t.GetSession(bobRI)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to get session to Bob (%x...)", intro.RouterHash[:4])
	}

	bobSSU2Session, ok := bobSession.(*SSU2Session)
	if !ok {
		return nil, oops.Errorf("unexpected Bob session type %T", bobSession)
	}

	return bobSSU2Session, nil
}

// establishBobSession looks up Bob's RouterInfo and establishes a session to Bob.
func (t *SSU2Transport) establishBobSession(intro IntroducerAddr) (*SSU2Session, error) {
	// R-2 fix: Atomic config snapshot
	cfg := t.config.Load()
	bobRI, err := cfg.RouterLookupFunc(intro.RouterHash)
	if err != nil {
		return nil, oops.Wrapf(err, "Bob (%x...) lookup failed", intro.RouterHash[:4])
	}

	bobSession, err := t.GetSession(bobRI)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to get session to Bob (%x...)", intro.RouterHash[:4])
	}

	bobSSU2Session, ok := bobSession.(*SSU2Session)
	if !ok {
		return nil, oops.Errorf("unexpected Bob session type %T", bobSession)
	}

	return bobSSU2Session, nil
}

// pendingRelayResponse wraps a relay-response channel with a consumed flag
// so that a delivery attempt arriving after the waiter has timed out is
// silently dropped instead of buffered indefinitely.
type pendingRelayResponse struct {
	ch       chan *ssu2noise.RelayResponseBlock
	consumed atomic.Bool
}

// sendRelayRequestAndWaitWithContext sends a RelayRequest to Bob and waits for Charlie's RelayResponse,
// honoring the parent context for cancellation (T-2 fix).
func (t *SSU2Transport) sendRelayRequestAndWaitWithContext(ctx context.Context, bobSSU2Session *SSU2Session, intro IntroducerAddr, charlieHash data.Hash, nonce uint32) (*ssu2noise.RelayResponseBlock, error) {
	pending := &pendingRelayResponse{ch: make(chan *ssu2noise.RelayResponseBlock, 1)}
	t.pendingRelayResponses.Store(nonce, pending)
	defer func() {
		pending.consumed.Store(true)
		t.pendingRelayResponses.Delete(nonce)
	}()

	if err := t.sendRelayRequest(bobSSU2Session, intro, charlieHash, nonce); err != nil {
		return nil, oops.Wrapf(err, "failed to send RelayRequest to Bob")
	}

	return t.waitForRelayResponseWithContext(ctx, pending.ch)
}

// sendRelayRequestAndWait sends a RelayRequest to Bob and waits for Charlie's RelayResponse.
func (t *SSU2Transport) sendRelayRequestAndWait(bobSSU2Session *SSU2Session, intro IntroducerAddr, charlieHash data.Hash, nonce uint32) (*ssu2noise.RelayResponseBlock, error) {
	pending := &pendingRelayResponse{ch: make(chan *ssu2noise.RelayResponseBlock, 1)}
	t.pendingRelayResponses.Store(nonce, pending)
	defer func() {
		pending.consumed.Store(true)
		t.pendingRelayResponses.Delete(nonce)
	}()

	if err := t.sendRelayRequest(bobSSU2Session, intro, charlieHash, nonce); err != nil {
		return nil, oops.Wrapf(err, "failed to send RelayRequest to Bob")
	}

	return t.waitForRelayResponse(pending.ch)
}

// waitForRelayResponseWithContext waits for Charlie's RelayResponse or times out,
// honoring the parent context for early cancellation (T-2 fix).
func (t *SSU2Transport) waitForRelayResponseWithContext(ctx context.Context, responseCh chan *ssu2noise.RelayResponseBlock) (*ssu2noise.RelayResponseBlock, error) {
	// Use the shorter of the parent context and the per-request timeout.
	ctx, cancel := context.WithTimeout(ctx, relayRequestTimeout)
	defer cancel()

	select {
	case resp, ok := <-responseCh:
		if !ok || resp == nil {
			return nil, oops.Errorf("relay response channel closed unexpectedly")
		}
		return resp, nil
	case <-ctx.Done():
		return nil, oops.Errorf("relay request timed out or canceled: %w", ctx.Err())
	}
}

// waitForRelayResponse waits for Charlie's RelayResponse or times out.
func (t *SSU2Transport) waitForRelayResponse(responseCh chan *ssu2noise.RelayResponseBlock) (*ssu2noise.RelayResponseBlock, error) {
	ctx, cancel := context.WithTimeout(t.ctx, relayRequestTimeout)
	defer cancel()

	select {
	case resp, ok := <-responseCh:
		if !ok || resp == nil {
			return nil, oops.Errorf("relay response channel closed unexpectedly")
		}
		return resp, nil
	case <-ctx.Done():
		return nil, oops.Errorf("relay request timed out after %v", relayRequestTimeout)
	}
}

// sendRelayRequest signs and transmits a RelayRequest block to Bob's session.
func (t *SSU2Transport) sendRelayRequest(bobSession *SSU2Session, intro IntroducerAddr, charlieHash data.Hash, nonce uint32) error {
	signingKey := t.keystore.GetSigningPrivateKey()
	if signingKey == nil {
		return oops.Errorf("signing key unavailable")
	}
	// types.PrivateKey.Bytes() returns the raw 64-byte Ed25519 seed+public.
	ed25519Key := ed25519.PrivateKey(signingKey.Bytes())

	// BUG FIX HIGH RD-2: Use confirmed external address, not local bind address.
	// localIPPort() returns the listener bind address (often 0.0.0.0 or private),
	// which fails validation at Charlie and breaks hole-punching. Use the
	// external address confirmed by PeerTest observations when available.
	aliceIP, alicePort, err := t.externalAddressForRelay()
	if err != nil {
		return oops.Wrapf(err, "could not determine external address for RelayRequest")
	}

	timestamp := uint32(time.Now().Unix())
	sig, err := ssu2noise.SignRelayRequest(
		ed25519Key,
		intro.RouterHash, charlieHash,
		nonce, intro.RelayTag, timestamp,
		2, // SSU2 version
		alicePort, aliceIP,
	)
	if err != nil {
		return oops.Wrapf(err, "failed to sign RelayRequest")
	}

	req := &ssu2noise.RelayRequestBlock{
		Nonce:     nonce,
		RelayTag:  intro.RelayTag,
		Timestamp: timestamp,
		Version:   2,
		AlicePort: alicePort,
		AliceIP:   aliceIP,
		Signature: sig,
	}
	block, err := ssu2noise.EncodeRelayRequest(req)
	if err != nil {
		return oops.Wrapf(err, "failed to encode RelayRequest")
	}
	return bobSession.WriteBlocks([]*ssu2noise.SSU2Block{block})
}

// externalAddressForRelay returns the external IP and port to use in RelayRequest/RelayResponse.
// BUG FIX HIGH RD-2: Prefers the confirmed external address from PeerTest observations/NAT mapping
// over the local bind address. Falls back to localIPPort() only when no external address is known yet.
// RD-2 fix: Validates fallback address with isValidExternalAddress - refuses to emit relay/hole-punch
// material with wildcard/private IPs that will be rejected by Charlie.
func (t *SSU2Transport) externalAddressForRelay() (net.IP, uint16, error) {
	externalStr := t.GetCachedExternalAddr()
	if externalStr != "" {
		host, portStr, err := net.SplitHostPort(externalStr)
		if err == nil {
			ip := net.ParseIP(host)
			port, portErr := strconv.Atoi(portStr)
			if ip != nil && portErr == nil && port > 0 && port <= 65535 {
				return ip, uint16(port), nil
			}
		}
	}
	// RD-2 fix: Fall back to local listener address (bind address) when external is unknown,
	// but validate before use. Refuse to emit unroutable addresses in relay blocks - Charlie
	// will reject them and hole-punching will fail silently.
	ip, port, err := t.localIPPort()
	if err != nil {
		return nil, 0, err
	}
	// RD-2 fix: Validate fallback before signing into relay material.
	if !isValidExternalAddress(ip) {
		return nil, 0, oops.New("external address not yet confirmed and bind address is not routable " +
			"(wildcard/private/loopback); defer relay operations until PeerTest completes")
	}
	return ip, port, nil
}

// localIPPort extracts Alice's IP and port from the transport listener.
// R-3 fix: Read t.listener under identityMu to avoid race with SetIdentity.
func (t *SSU2Transport) localIPPort() (net.IP, uint16, error) {
	t.identityMu.RLock()
	listener := t.listener
	t.identityMu.RUnlock()

	if listener == nil {
		return nil, 0, oops.New("listener is nil (identity not yet initialized or failed rebind)")
	}

	addr := listener.Addr()
	s := addr.String()
	if ssu2Addr, ok := addr.(*ssu2noise.SSU2Addr); ok {
		s = ssu2Addr.UnderlyingAddr().String()
	}
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return nil, 0, oops.Wrapf(err, "malformed listener address %q", s)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, 0, oops.Errorf("could not parse IP %q", host)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, 0, oops.Wrapf(err, "could not parse port %q", portStr)
	}
	return ip, uint16(port), nil
}

// dialCharlieDirectly dials Charlie's address obtained from the RelayResponse.
func (t *SSU2Transport) dialCharlieDirectly(charlieRI router_info.RouterInfo, charlieHash data.Hash, resp *ssu2noise.RelayResponseBlock) (transport.TransportSession, error) {
	if resp.Code != 0 {
		return nil, oops.Errorf("relay rejected by introducer: code=%d", resp.Code)
	}

	charlieAddr := &net.UDPAddr{
		IP:   resp.CharlieIP,
		Port: int(resp.CharliePort),
	}
	t.logger.WithField("charlie_addr", charlieAddr).Debug("dialing Charlie directly after relay")

	if err := t.waitForHolePunch(); err != nil {
		return nil, err
	}

	return t.establishCharlieSession(charlieRI, charlieHash, charlieAddr)
}

// waitForHolePunch waits for Charlie's hole-punch packets to arrive.
// Returns error if context is cancelled during the wait.
//
// T-3 fix: Uses the configurable HolePunchDelay from config. The delay allows
// Charlie's hole-punch packets to create NAT state before Alice sends the direct
// SessionRequest. Built-in SSU2 message retransmission makes a too-early send
// recoverable if the delay is insufficient for the network conditions.
func (t *SSU2Transport) waitForHolePunch() error {
	// R-2 fix: Atomic config snapshot
	cfg := t.config.Load()
	delay := cfg.GetHolePunchDelay()
	select {
	case <-time.After(delay):
		return nil
	case <-t.ctx.Done():
		return oops.Wrapf(t.ctx.Err(), "context canceled during hole-punch delay")
	}
}

// establishCharlieSession establishes a connection to Charlie and registers the session.
// Handles session limit checking and cleanup on failure.
func (t *SSU2Transport) establishCharlieSession(charlieRI router_info.RouterInfo, charlieHash data.Hash, charlieAddr *net.UDPAddr) (transport.TransportSession, error) {
	dialConfig, err := t.buildCharlieDialConfig(charlieRI, charlieHash)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to build dial config for Charlie")
	}

	conn, err := ssu2noise.DialSSU2WithHandshakeContext(t.ctx, nil, charlieAddr, dialConfig)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to dial Charlie at %v", charlieAddr)
	}

	return t.registerCharlieSession(conn, charlieHash)
}

// registerCharlieSession registers or reuses a session for Charlie, handling session limit checks.
// Closes the connection and returns error if session limit is exceeded.
func (t *SSU2Transport) registerCharlieSession(conn *ssu2noise.SSU2Conn, charlieHash data.Hash) (transport.TransportSession, error) {
	if err := t.checkSessionLimit(); err != nil {
		_ = conn.Close()
		return nil, err
	}

	// Use deferred cleanup - only unreserve if slotUsed is false
	slotUsed := false
	defer func() {
		if !slotUsed {
			t.unreserveSessionSlot()
		}
	}()

	session, newSlotUsed, err := t.registerOrReuseSession(conn, charlieHash)
	if err != nil {
		return nil, err
	}

	slotUsed = newSlotUsed
	return session, nil
}

// buildCharlieDialConfig constructs a dialler SSU2Config for Charlie, using
// Charlie's static key from his RouterInfo.
func (t *SSU2Transport) buildCharlieDialConfig(charlieRI router_info.RouterInfo, charlieHash data.Hash) (*ssu2noise.SSU2Config, error) {
	dialConfig, err := t.initializeCharlieDialConfig(charlieHash)
	if err != nil {
		return nil, err
	}

	if err := t.configureRemoteKeys(dialConfig, charlieRI); err != nil {
		return nil, err
	}

	t.configureIntroKeys(dialConfig, charlieRI)

	return dialConfig, nil
}

// initializeCharlieDialConfig creates and initializes the base SSU2Config for dialing.
func (t *SSU2Transport) initializeCharlieDialConfig(charlieHash data.Hash) (*ssu2noise.SSU2Config, error) {
	t.identityMu.RLock()
	ourHash, err := t.identity.IdentHash()
	t.identityMu.RUnlock()
	if err != nil {
		return nil, oops.Wrapf(err, "failed to get our identity hash")
	}

	dialConfig, err := ssu2noise.NewSSU2Config(ourHash, true)
	if err != nil {
		return nil, WrapSSU2Error(err, "creating Charlie dial config")
	}
	if err := initializeCryptoKeys(dialConfig, t.keystore); err != nil {
		return nil, err
	}
	dialConfig = dialConfig.WithRemoteRouterHash(charlieHash)

	if err := t.attachLocalRouterInfo(dialConfig); err != nil {
		return nil, err
	}

	return dialConfig, nil
}

// configureRemoteKeys extracts and sets Charlie's static key in the dial config.
func (t *SSU2Transport) configureRemoteKeys(dialConfig *ssu2noise.SSU2Config, charlieRI router_info.RouterInfo) error {
	remoteStaticKey, err := extractRemoteStaticKey(charlieRI)
	if err != nil {
		return oops.Wrapf(err, "no SSU2 static key in Charlie's RI")
	}
	dialConfig.RemoteStaticKey = remoteStaticKey
	return nil
}

// configureIntroKeys sets both local and remote introduction keys in the dial config.
func (t *SSU2Transport) configureIntroKeys(dialConfig *ssu2noise.SSU2Config, charlieRI router_info.RouterInfo) error {
	// Set our local intro key for header protection.
	if ik := t.GetIntroKey(); len(ik) == 32 {
		dialConfig.IntroKey = ik
	}

	// Set Charlie's intro key for ChaCha header obfuscation.
	charlieIK, err := ExtractSSU2IntroKey(charlieRI)
	if err != nil {
		return oops.Wrapf(err, "no SSU2 intro key in Charlie's RI")
	}
	dialConfig.RemoteIntroKey = charlieIK

	return nil
}
