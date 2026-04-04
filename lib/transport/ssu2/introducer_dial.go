package ssu2

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/transport"
	ssu2noise "github.com/go-i2p/go-noise/ssu2"
)

const (
	// relayRequestTimeout is how long Alice waits for Bob to forward a
	// RelayResponse after sending a RelayRequest.
	relayRequestTimeout = 10 * time.Second

	// holePunchDelay gives Charlie's hole-punch packets a chance to arrive
	// before Alice sends the SessionRequest directly.
	holePunchDelay = 150 * time.Millisecond
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
func (t *SSU2Transport) dialViaIntroducer(charlieRI router_info.RouterInfo, charlieHash data.Hash) (transport.TransportSession, error) {
	if t.config.RouterLookupFunc == nil {
		return nil, fmt.Errorf("RouterLookupFunc not configured: cannot dial via introducer")
	}

	introducers := t.collectIntroducers(charlieRI)
	if len(introducers) == 0 {
		return nil, fmt.Errorf("no valid introducers found for router %x", charlieHash[:4])
	}

	for _, intro := range introducers {
		session, err := t.tryOneIntroducer(charlieRI, charlieHash, intro)
		if err != nil {
			t.logger.WithField("error", err).Debug("introducer attempt failed, trying next")
			continue
		}
		return session, nil
	}
	return nil, fmt.Errorf("all %d introducer(s) failed for router %x", len(introducers), charlieHash[:4])
}

// collectIntroducers gathers all distinct IntroducerAddr entries from all SSU2
// addresses in charlieRI.
func (t *SSU2Transport) collectIntroducers(charlieRI router_info.RouterInfo) []IntroducerAddr {
	var result []IntroducerAddr
	seen := make(map[data.Hash]bool)
	for _, addr := range charlieRI.RouterAddresses() {
		if !isSSU2Transport(addr) {
			continue
		}
		for _, intro := range ExtractIntroducers(addr) {
			if !seen[intro.RouterHash] {
				seen[intro.RouterHash] = true
				result = append(result, intro)
			}
		}
	}
	return result
}

// tryOneIntroducer attempts relay through a single introducer entry.
func (t *SSU2Transport) tryOneIntroducer(charlieRI router_info.RouterInfo, charlieHash data.Hash, intro IntroducerAddr) (transport.TransportSession, error) {
	// Step 1: look up Bob's RouterInfo so we can dial him directly.
	bobRI, err := t.config.RouterLookupFunc(intro.RouterHash)
	if err != nil {
		return nil, fmt.Errorf("Bob (%x...) lookup failed: %w", intro.RouterHash[:4], err)
	}

	// Step 2: get (or create) a session to Bob.
	bobSession, err := t.GetSession(bobRI)
	if err != nil {
		return nil, fmt.Errorf("failed to get session to Bob (%x...): %w", intro.RouterHash[:4], err)
	}
	bobSSU2Session, ok := bobSession.(*SSU2Session)
	if !ok {
		return nil, fmt.Errorf("unexpected Bob session type %T", bobSession)
	}

	// Step 3: register a pending-response channel keyed by nonce.
	nonce := rand.Uint32()
	responseCh := make(chan *ssu2noise.RelayResponseBlock, 1)
	t.pendingRelayResponses.Store(nonce, responseCh)
	defer t.pendingRelayResponses.Delete(nonce)

	// Step 4: send signed RelayRequest to Bob.
	if err := t.sendRelayRequest(bobSSU2Session, intro, charlieHash, nonce); err != nil {
		return nil, fmt.Errorf("failed to send RelayRequest to Bob: %w", err)
	}

	// Step 5: wait for Bob to forward Charlie's RelayResponse.
	ctx, cancel := context.WithTimeout(t.ctx, relayRequestTimeout)
	defer cancel()

	select {
	case resp, ok := <-responseCh:
		if !ok || resp == nil {
			return nil, fmt.Errorf("relay response channel closed unexpectedly")
		}
		return t.dialCharlieDirectly(charlieRI, charlieHash, resp)
	case <-ctx.Done():
		return nil, fmt.Errorf("relay request timed out after %v", relayRequestTimeout)
	}
}

// sendRelayRequest signs and transmits a RelayRequest block to Bob's session.
func (t *SSU2Transport) sendRelayRequest(bobSession *SSU2Session, intro IntroducerAddr, charlieHash data.Hash, nonce uint32) error {
	signingKey := t.keystore.GetSigningPrivateKey()
	if signingKey == nil {
		return fmt.Errorf("signing key unavailable")
	}
	// types.PrivateKey.Bytes() returns the raw 64-byte Ed25519 seed+public.
	ed25519Key := ed25519.PrivateKey(signingKey.Bytes())

	aliceIP, alicePort, err := t.localIPPort()
	if err != nil {
		return fmt.Errorf("could not determine local address: %w", err)
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
		return fmt.Errorf("failed to sign RelayRequest: %w", err)
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
		return fmt.Errorf("failed to encode RelayRequest: %w", err)
	}
	return bobSession.WriteBlocks([]*ssu2noise.SSU2Block{block})
}

// localIPPort extracts Alice's IP and port from the transport listener.
func (t *SSU2Transport) localIPPort() (net.IP, uint16, error) {
	addr := t.listener.Addr()
	s := addr.String()
	if ssu2Addr, ok := addr.(*ssu2noise.SSU2Addr); ok {
		s = ssu2Addr.UnderlyingAddr().String()
	}
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return nil, 0, fmt.Errorf("malformed listener address %q: %w", s, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, 0, fmt.Errorf("could not parse IP %q", host)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, 0, fmt.Errorf("could not parse port %q: %w", portStr, err)
	}
	return ip, uint16(port), nil
}

// dialCharlieDirectly dials Charlie's address obtained from the RelayResponse.
func (t *SSU2Transport) dialCharlieDirectly(charlieRI router_info.RouterInfo, charlieHash data.Hash, resp *ssu2noise.RelayResponseBlock) (transport.TransportSession, error) {
	if resp.Code != 0 {
		return nil, fmt.Errorf("relay rejected by introducer: code=%d", resp.Code)
	}

	charlieAddr := &net.UDPAddr{
		IP:   resp.CharlieIP,
		Port: int(resp.CharliePort),
	}
	t.logger.WithField("charlie_addr", charlieAddr).Debug("dialing Charlie directly after relay")

	// Give Charlie's hole-punch packets time to arrive so NAT state is open.
	time.Sleep(holePunchDelay)

	dialConfig, err := t.buildCharlieDialConfig(charlieRI, charlieHash)
	if err != nil {
		return nil, fmt.Errorf("failed to build dial config for Charlie: %w", err)
	}

	conn, err := ssu2noise.DialSSU2WithHandshakeContext(t.ctx, nil, charlieAddr, dialConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to dial Charlie at %v: %w", charlieAddr, err)
	}

	if err := t.checkSessionLimit(); err != nil {
		conn.Close()
		return nil, err
	}

	session, newSlotUsed, err := t.registerOrReuseSession(conn, charlieHash)
	if err != nil {
		return nil, err
	}
	if !newSlotUsed {
		// session limit was pre-checked but slot ended up not used (reused existing)
		t.unreserveSessionSlot()
	}
	return session, nil
}

// buildCharlieDialConfig constructs a dialler SSU2Config for Charlie, using
// Charlie's static key from his RouterInfo.
func (t *SSU2Transport) buildCharlieDialConfig(charlieRI router_info.RouterInfo, charlieHash data.Hash) (*ssu2noise.SSU2Config, error) {
	t.identityMu.RLock()
	ourHash, err := t.identity.IdentHash()
	t.identityMu.RUnlock()
	if err != nil {
		return nil, fmt.Errorf("failed to get our identity hash: %w", err)
	}

	dialConfig, err := ssu2noise.NewSSU2Config(ourHash, true)
	if err != nil {
		return nil, WrapSSU2Error(err, "creating Charlie dial config")
	}
	if err := initializeCryptoKeys(dialConfig, t.keystore); err != nil {
		return nil, err
	}
	dialConfig = dialConfig.WithRemoteRouterHash(charlieHash)

	remoteStaticKey, err := extractRemoteStaticKey(charlieRI)
	if err != nil {
		return nil, fmt.Errorf("no SSU2 static key in Charlie's RI: %w", err)
	}
	dialConfig = dialConfig.WithRemoteStaticKey(remoteStaticKey)

	return dialConfig, nil
}
