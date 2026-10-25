package ssu2

import (
	"sync"
	"time"

	"github.com/go-i2p/common/data"
)

// natTestContext records the cross-peer identities the local router has
// legitimately learned for one peer-test or relay nonce.
//
// Why this exists: the SSU2 peer test and relay exchanges spread a single
// transaction across three routers, and the router holding the transaction
// routinely needs the identity of a peer it is NOT directly connected to.
// ssu2.rst §"Peer Test Process" / §"Signatures" requires signatures to be
// verified with Alice's or Charlie's signing key depending on the message, and
// §"Peer Test Block" states the Alice hash is "Only used in the signature for
// messages 3 and 4; not included in message 3". So when we are Bob handling
// message 3 from Charlie, Alice's hash is simply not on the wire: it has to
// come from what we learned at message 1. Likewise, when we are Alice handling
// the out-of-session messages 5 and 7, Charlie's identity is not the UDP
// source (he is behind his own NAT) and must come from the in-session message
// 4 we already validated.
//
// Every field is therefore populated ONLY from data this router has already
// authenticated (a validated signature on an in-session block, or the session
// peer's own identity). Nothing is learned from an unauthenticated
// out-of-session datagram: the introduction key those messages are sealed with
// is published in the netdb (ssu2.rst §"Introduction Key": "Any party knowing
// Bob's intro key, which is published in the network database..."), so the
// intro-key AEAD gives confidentiality and probing resistance but authenticates
// nobody.
//
// This mirrors the nonceContext the upstream go-noise Coordinator keeps for the
// same purpose (go-noise/ssu2/coordinator.go).
type natTestContext struct {
	// role is which party WE are in this transaction. The signature inputs for
	// a peer-test or relay block depend on it: the same on-the-wire block is
	// verified with different bhash/signer choices when we are the initiator,
	// the relay, or the responder.
	role natTestRole

	aliceHash   data.Hash
	charlieHash data.Hash
	bobHash     data.Hash

	// aliceKnown / charlieKnown / bobKnown report whether each hash was
	// actually learned. A zero data.Hash is a plausible-looking value, so
	// presence is tracked separately instead of being inferred from the bytes.
	aliceKnown   bool
	charlieKnown bool
	bobKnown     bool

	expiresAt time.Time
}

// natTestRole is our participation in a peer-test or relay transaction.
type natTestRole uint8

const (
	natRoleUnknown natTestRole = iota
	// natRoleAlice: we initiated the test / are the relay client.
	natRoleAlice
	// natRoleBob: we are the relay between Alice and Charlie.
	natRoleBob
	// natRoleCharlie: we are the responder / introducer target.
	natRoleCharlie
)

// setRole records which party we are for nonce. First writer wins: a role is
// established by the authenticated in-session message that starts our part in
// the transaction, and must not be overwritten by a later, weaker signal.
func (t *SSU2Transport) setNatRole(nonce uint32, role natTestRole) {
	if role == natRoleUnknown {
		return
	}
	t.natContexts.mutate(nonce, func(c *natTestContext) {
		if c.role == natRoleUnknown {
			c.role = role
		}
	})
}

// natRoleFor returns our recorded role for nonce.
func (t *SSU2Transport) natRoleFor(nonce uint32) natTestRole {
	c := t.natContexts.lookup(nonce)
	if c == nil {
		return natRoleUnknown
	}
	return c.role
}

// natNonceStore is the transport's nonce -> context map with TTL pruning.
//
// Entries live for the lifetime of a peer test / relay transaction plus slack
// for the out-of-session messages that can arrive after the in-session ones
// complete. peerTestObservationWindow already bounds how long a test is
// interesting; natContextTTL is deliberately a few times larger so a late
// message 5/7 can still be correlated.
type natNonceStore struct {
	mu      sync.RWMutex
	entries map[uint32]*natTestContext
	ttl     time.Duration
}

const natContextTTL = 5 * time.Minute

// mutate runs fn against the context for nonce, creating it if absent, and
// prunes expired entries while the lock is held. nonce 0 is never a valid
// test/relay nonce (path.PeerTestManager rejects it), so it is ignored.
func (s *natNonceStore) mutate(nonce uint32, fn func(*natTestContext)) {
	if nonce == 0 || fn == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.entries == nil {
		s.entries = make(map[uint32]*natTestContext)
	}
	if s.ttl == 0 {
		s.ttl = natContextTTL
	}

	now := time.Now()
	s.pruneLocked(now)

	ctx := s.entries[nonce]
	if ctx == nil {
		ctx = &natTestContext{}
		s.entries[nonce] = ctx
	}
	fn(ctx)
	ctx.expiresAt = now.Add(s.ttl)
}

func (s *natNonceStore) pruneLocked(now time.Time) {
	for nonce, ctx := range s.entries {
		if now.After(ctx.expiresAt) {
			delete(s.entries, nonce)
		}
	}
}

// lookup returns a copy of the context for nonce, or nil when nothing has been
// recorded (or it has expired).
func (s *natNonceStore) lookup(nonce uint32) *natTestContext {
	if nonce == 0 {
		return nil
	}
	s.mu.RLock()
	ctx := s.entries[nonce]
	s.mu.RUnlock()
	if ctx == nil || time.Now().After(ctx.expiresAt) {
		return nil
	}
	// Copy so callers cannot mutate shared state through the returned pointer.
	c := *ctx
	return &c
}

// remove drops the context for nonce, used when a transaction finishes.
func (s *natNonceStore) remove(nonce uint32) {
	s.mu.Lock()
	delete(s.entries, nonce)
	s.mu.Unlock()
}

// size reports the number of live contexts (for tests and metrics).
func (s *natNonceStore) size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries)
}

// rememberAliceForNonce records that nonce belongs to a transaction initiated
// by the router with aliceHash. Only call this with a hash learned from an
// authenticated source.
func (t *SSU2Transport) rememberAliceForNonce(nonce uint32, aliceHash data.Hash) {
	t.natContexts.mutate(nonce, func(c *natTestContext) {
		c.aliceHash = aliceHash
		c.aliceKnown = true
	})
}

// rememberCharlieForNonce records the responder/relay target for nonce.
func (t *SSU2Transport) rememberCharlieForNonce(nonce uint32, charlieHash data.Hash) {
	t.natContexts.mutate(nonce, func(c *natTestContext) {
		c.charlieHash = charlieHash
		c.charlieKnown = true
	})
}

// lookupAliceForNonce returns Alice's hash for nonce if previously learned.
func (t *SSU2Transport) lookupAliceForNonce(nonce uint32) (data.Hash, bool) {
	c := t.natContexts.lookup(nonce)
	if c == nil || !c.aliceKnown {
		return data.Hash{}, false
	}
	return c.aliceHash, true
}

// lookupCharlieForNonce returns Charlie's hash for nonce if previously learned.
func (t *SSU2Transport) lookupCharlieForNonce(nonce uint32) (data.Hash, bool) {
	c := t.natContexts.lookup(nonce)
	if c == nil || !c.charlieKnown {
		return data.Hash{}, false
	}
	return c.charlieHash, true
}

// rememberBobForNonce records the introducer/relay router for nonce.
func (t *SSU2Transport) rememberBobForNonce(nonce uint32, bobHash data.Hash) {
	t.natContexts.mutate(nonce, func(c *natTestContext) {
		c.bobHash = bobHash
		c.bobKnown = true
	})
}

// lookupBobForNonce returns Bob's hash for nonce if previously learned.
func (t *SSU2Transport) lookupBobForNonce(nonce uint32) (data.Hash, bool) {
	c := t.natContexts.lookup(nonce)
	if c == nil || !c.bobKnown {
		return data.Hash{}, false
	}
	return c.bobHash, true
}
