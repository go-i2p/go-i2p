package ssu2

import (
	"time"

	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/go-i2p/lib/i2pcontrol/netstatus"
	ssu2noise "github.com/go-i2p/go-noise/ssu2"
)

// ──────────────────────────────────────────────────────────────────────────────
// Key and identity sizes
// ──────────────────────────────────────────────────────────────────────────────

// The widths below are both 32 bytes but for different reasons, and the code
// checks them at separate boundaries, so they are named separately. The
// introduction key's own width, introKeySize, is already declared in
// persistent_config.go and is left there.
//
// Moved from: transport.go, nat.go
const (
	// staticKeySize is the width of the SSU2 X25519 static key. Aliased from the
	// handshake library that consumes it, so the router's length checks and the
	// library's key schedule cannot disagree about what a valid static key is.
	staticKeySize = ssu2noise.StaticKeySize // 32

	// routerHashSize is the width of an I2P router identity hash: the SHA-256 of
	// the router's Destination. It is the size of every hash field the
	// out-of-session blocks (PeerTest, RelayRequest, RelayIntro) carry, and the
	// width a replay token must have before it can be used as a replay key
	// without being hashed first.
	//
	// Spec: ssu2.rst "Peer Test Block" / "Relay Request Block" (each carries a
	// 32-byte router hash).
	// Reference: i2pd libi2pd/SSU2Packet.h.
	routerHashSize = 32
)

// ──────────────────────────────────────────────────────────────────────────────
// Protocol version
// ──────────────────────────────────────────────────────────────────────────────

// ssu2ProtocolVersion is the SSU2 wire revision this router speaks. It is the
// version byte at header offset 13, the Version field of every out-of-session
// block, and part of what those blocks' signatures cover, so a mismatch between
// what we sign and what a peer verifies fails the signature check rather than
// reporting a version error. Aliased from the handshake library.
//
// Spec: ssu2.rst "Common Header" ("ver :: 2 - SSU2 version").
// Moved from: nat.go, introducer_dial.go
const ssu2ProtocolVersion = ssu2noise.SSU2ProtocolVersion // 2

// ssu2VersionString is the same version as it appears in a RouterAddress's
// protocol-version option, which is an I2PString holding decimal digits rather
// than a wire byte. It must always agree with ssu2ProtocolVersion.
//
// Moved from: router_address.go
const ssu2VersionString = "2"

// ──────────────────────────────────────────────────────────────────────────────
// Block payload field layout
// ──────────────────────────────────────────────────────────────────────────────

// dateTimeFieldSize is the width of a DateTime block's payload: the sender's
// clock as a big-endian Integer, fixed at four bytes. Both the outbound block
// builder and the out-of-session skew check work in this width, and a shorter
// block is malformed rather than merely low-resolution.
//
// Spec: ssu2.rst:2832-2836 ("time :: 4 bytes"; "Implementations must round to
// the nearest second to prevent clock bias").
// Reference: i2pd libi2pd/SSU2.cpp handleDateTimeBlock.
// Moved from: framing.go, nat_outofsession_inbound.go
const dateTimeFieldSize = 4

// An explicit ACK block's data is a four-byte Ack-Through packet number, a
// one-byte Ack-Count, and then zero or more two-byte SACK ranges, each a
// Nack-Count followed by an Ack-Count. The minimum parseable length is composed
// from the first two widths so the parser's "too short" check and its field
// reads cannot drift apart.
//
// Spec: ssu2.rst "Data Block" ACK section.
// Reference: i2pd libi2pd/SSU2.cpp handleAckBlock.
// Moved from: framing.go
const (
	// ackThroughSize is the width of the leading Ack-Through packet number.
	ackThroughSize = 4

	// ackCountSize is the width of the Ack-Count byte that follows it.
	ackCountSize = 1

	// ackBlockMinSize is the shortest ACK block data that can be parsed: the
	// Ack-Through and the Ack-Count, with no ranges.
	ackBlockMinSize = ackThroughSize + ackCountSize // 5

	// ackRangeSize is the width of one SACK range entry: Nack-Count then
	// Ack-Count, one byte each.
	ackRangeSize = 2
)

// ──────────────────────────────────────────────────────────────────────────────
// Fragmentation
// ──────────────────────────────────────────────────────────────────────────────

// Follow-on fragments number the pieces of a message they carry, and the
// numbering starts at 1 rather than 0: the spec reserves 0 so a receiver can
// always tell a follow-on from the first fragment by number alone. The counter
// is seven bits wide, since the eighth bit is the more-fragments flag folded
// into the fragment-info byte, so 127 is the largest fragment a message can be
// split into before the numbering wraps.
//
// Spec: ssu2.rst "Fragmentation" ("fragnum :: 7 bits").
// Reference: i2pd libi2pd/SSU2.cpp fragmentMessage.
// Moved from: session.go
const (
	// firstFollowOnFragmentNumber is the number given to the first follow-on
	// fragment.
	firstFollowOnFragmentNumber = 1

	// maxFollowOnFragments is the largest fragment number representable in the
	// seven-bit field. Exceeding it means the message is too large to fragment.
	maxFollowOnFragments = 127
)

// ──────────────────────────────────────────────────────────────────────────────
// Out-of-session status codes
// ──────────────────────────────────────────────────────────────────────────────

// PeerTest and RelayResponse blocks carry a one-byte reason code. Zero means the
// request was accepted; the values above it name who rejected and why. The
// library exposes the Code field but no named values, so the ones this router
// compares against are named here. The relay-response bounds decide whether
// Charlie's signature is required on a block, so getting them wrong is a
// verification bypass rather than a cosmetic error.
//
// Spec: ssu2.rst "Peer Test Block" ("code :: 0 if accepted, else an error"),
// "Relay Response Block" ("1-63 rejected by Bob, 64-127 rejected by Charlie").
// Reference: i2pd libi2pd/SSU2.cpp handleRelayResponse.
// Moved from: nat.go
const (
	// codeAccepted is the shared "no error" value of a PeerTest or RelayResponse
	// reason code.
	codeAccepted = 0

	// relayResponseBobRejectionMin is the first code that means "rejected by
	// Bob": Bob signs his own rejections, so the signer is us.
	relayResponseBobRejectionMin = 1

	// relayResponseBobRejectionMax is the last such code. Above it the rejection
	// came from Charlie, whose signature must be present.
	relayResponseBobRejectionMax = 63
)

// relayResponseTokenSize is the width of the random token a RelayResponse
// carries, which Alice later presents in the Hole Punch message to prove the
// response was meant for her. Eight bytes is the field's size on the wire and
// the size i2pd fills, so it is 64 bits of unguessable identifier per relay
// attempt.
//
// Spec: ssu2.rst "Relay Response Block" ("token :: 8 bytes, random").
// Reference: i2pd libi2pd/SSU2.cpp handleRelayIntro.
// Moved from: nat.go
const relayResponseTokenSize = 8

// InboundBlockedStatusCode reports our reachability using the I2PControl network
// status vocabulary, so the code the router turns into i2p.router.net.status and
// the code this transport reports are the same number for the same condition.
// The codes are owned by lib/i2pcontrol/netstatus; this package cannot import
// lib/i2pcontrol (which depends on the transports) but the leaf package is
// importable from here.
//
// Reference: Java RouterErrorMessages.java ERROR_SYMMETRIC_NAT (11),
// FIREWALLED (2).
// Moved from: nat.go
const (
	// inboundBlockedSymmetricNATCode reports a symmetric NAT, which cannot be
	// hole-punched at all.
	inboundBlockedSymmetricNATCode = netstatus.ErrorSymmetricNAT

	// inboundBlockedFirewalledCode reports a restricted or port-restricted NAT:
	// reachable via introducers and hole-punching, but not by unsolicited
	// inbound.
	inboundBlockedFirewalledCode = netstatus.Firewalled
)

// ──────────────────────────────────────────────────────────────────────────────
// NAT detection
// ──────────────────────────────────────────────────────────────────────────────

// minPeerTestCandidates is how many SSU2-capable peers a PeerTest needs: Bob,
// who relays, and Charlie, who probes us from outside our NAT. With fewer than
// two there is no Charlie, so detection is skipped rather than run against a
// single peer.
//
// Spec: ssu2.rst "Peer Test Process" (Alice to Bob to Charlie to Alice).
// Moved from: nat.go
const minPeerTestCandidates = 2

// maxIntroducerRegistrations caps how many introducers this router registers,
// and the size the go-noise introducer registry is created with. Three is i2pd's
// number: enough redundancy that one introducer going offline does not make us
// unreachable, few enough that the transit load we place on other routers stays
// small.
//
// Reference: i2pd libi2pd/SSU2.cpp introducer count.
// Moved from: nat.go
const maxIntroducerRegistrations = 3

// abandonedRelayTagWarnThreshold is the number of tracked abandoned relay tags
// past which the router warns about registration instability. It sits below the
// hard cap on purpose: reaching the cap means entries are being evicted, and an
// operator who wants to act on that should hear about it first.
//
// Moved from: nat.go
const abandonedRelayTagWarnThreshold = 10

// ──────────────────────────────────────────────────────────────────────────────
// Peer-test rate limiting
// ──────────────────────────────────────────────────────────────────────────────

// A PeerTest is signed work on both ends and it is the cheapest way to make a
// router do expensive NAT testing, so it is rate-limited twice: per session and
// transport-wide.
//
// Spec basis: ssu2.rst "DoS Mitigation" (limit the rate of Peer Tests).
// Moved from: session.go, transport.go
const (
	// perSessionPeerTestRateLimit is the sustained PeerTest requests per second a
	// single session may trigger.
	perSessionPeerTestRateLimit = 1

	// perSessionPeerTestBurst is how many PeerTests a session may trigger at
	// once: three, so a legitimate reconnect that needs a fresh test is not
	// queued behind its own previous one.
	perSessionPeerTestBurst = 3

	// peerTestGlobalRateLimit is the sustained transport-wide PeerTest rate.
	peerTestGlobalRateLimit = 100

	// peerTestGlobalBurst is the instantaneous allowance above that rate. The
	// global cap is what bounds the router's total signing cost under a
	// many-source flood.
	peerTestGlobalBurst = 200
)

// ──────────────────────────────────────────────────────────────────────────────
// Peer-test retry jitter
// ──────────────────────────────────────────────────────────────────────────────

// peerTestJitterMinFactor and peerTestJitterSpan spread a retry over
// [0.75, 1.25) of the exponential base backoff, i.e. plus or minus 25%. Without
// jitter, routers that failed a peer test at the same moment retry in lockstep
// and produce a thundering herd against the same introducers.
//
// Moved from: nat.go
const (
	peerTestJitterMinFactor = 0.75
	peerTestJitterSpan      = 0.5
)

// ──────────────────────────────────────────────────────────────────────────────
// Introducer lifetime
// ──────────────────────────────────────────────────────────────────────────────

// introducerLifetime is how long a registered introducer stays usable. The
// router's published "exp=" option is derived from it, so an introducer we still
// consider valid and the expiry a peer reads from our RouterInfo are the same
// instant. Four hours is i2pd's value: long enough that a stable introducer is
// not re-registered every few minutes, short enough that a dead one stops being
// used without waiting a day.
//
// Reference: i2pd libi2pd/SSU2.cpp introducer expiration; Java
// SSU2Communications.java introducer expiry.
// Moved from: router_address.go
const introducerLifetime = 4 * time.Hour

// ──────────────────────────────────────────────────────────────────────────────
// RouterAddress cost values
// ──────────────────────────────────────────────────────────────────────────────

// The cost byte advertised on a RouterAddress is how tunnel builders rank
// candidate hops: lower is cheaper, so directly reachable routers are preferred.
// The spec assigns no numbers; these are the values Java I2P and i2pd use, and
// matching them keeps go-i2p's tunnel selection comparable with the rest of the
// network instead of quietly biasing peer choice.
//
// Reference: Java RouterAddress.java COST_* constants; i2pd RouterInfo.cpp.
// Moved from: router_address.go
const (
	// costSSU2Published is the cost of an address carrying a "host=" option, or
	// of an introducer-reachable router (caps "B"): peers can reach it, directly
	// or through the listed introducers.
	costSSU2Published = 8

	// costSSU2NonPublished is the cost of a caps-only unpublished address, priced
	// above every reachable one.
	costSSU2NonPublished = 15
)

// ──────────────────────────────────────────────────────────────────────────────
// Peer hash marker
// ──────────────────────────────────────────────────────────────────────────────

// peerHashMarkerByte overwrites the first byte of the fallback peer hash that
// transport.DeriveConnectionHash builds from a socket address, used when a
// connection has no router hash yet. It keeps address-derived session keys from
// colliding with a real router hash whose leading byte happens to match, and it
// must stay distinct from NTCP2's marker (0xFF) so the two transports cannot
// claim each other's sessions.
//
// Moved from: transport.go
const peerHashMarkerByte = 0xFE

// ──────────────────────────────────────────────────────────────────────────────
// Inbound accept loop
// ──────────────────────────────────────────────────────────────────────────────

// Moved from: transport.go, introducer_dial.go
const (
	// listenerSwapPollInterval is how long the accept loop waits before
	// re-checking for a listener when the current one is nil. A nil listener
	// while the transport is still running means SetIdentity is swapping it,
	// which is brief; polling rather than blocking lets the loop notice a
	// shutdown without waiting on a signal only Close() sends.
	listenerSwapPollInterval = 50 * time.Millisecond

	// transientAcceptBackoff is the pause after a transient accept error before
	// retrying. Short enough that a recovered listener resumes promptly, long
	// enough that a permanently erroring listener does not spin hot.
	transientAcceptBackoff = 10 * time.Millisecond

	// relayResponseChanBuffer is the depth of the per-attempt channel a relay
	// response is delivered on. One, deliberately: a relay attempt is answered
	// once, so a deeper buffer would hide a duplicate response instead of letting
	// it be noticed.
	relayResponseChanBuffer = 1
)

// ──────────────────────────────────────────────────────────────────────────────
// Session sizing and pacing
// ──────────────────────────────────────────────────────────────────────────────

// Moved from: session.go
const (
	// recvBackpressureTimeout is how long the receive path waits for space in the
	// application's receive channel before dropping the message. Dropping rather
	// than blocking keeps one slow consumer from stalling decryption of every
	// later packet on the session.
	recvBackpressureTimeout = 100 * time.Millisecond

	// clockSkewToleranceSeconds is how far a peer's DateTime block may disagree
	// with our clock before the session is closed, in the seconds that block's
	// timestamp is measured in. It is the in-session bound; out-of-session
	// packets use the looser defaultOutOfSessionMaxSkew.
	//
	// Reference: i2pd libi2pd/SSU2PacketHandler MAX_SKEW.
	clockSkewToleranceSeconds = 60
)

// ──────────────────────────────────────────────────────────────────────────────
// Network address bounds
// ──────────────────────────────────────────────────────────────────────────────

// maxPortNumber is the largest value a UDP or TCP port can take: ports are
// sixteen-bit fields, so anything above it cannot be dialled and is a
// misconfiguration rather than an unreachable peer.
//
// Moved from: introducer_dial.go
const maxPortNumber = 65535

// ──────────────────────────────────────────────────────────────────────────────
// Diagnostic log prefixes
// ──────────────────────────────────────────────────────────────────────────────

// logHashPrefixBytes is how many leading bytes of a router hash are logged when
// identifying the peer a failed signature or a failed lookup concerns. Four
// bytes is enough to disambiguate in a log and short enough that a log file does
// not accumulate full identity material.
//
// Moved from: nat.go, nat_ri.go, nat_outofsession.go, introducer_dial.go,
// transport.go
const logHashPrefixBytes = 4

// ──────────────────────────────────────────────────────────────────────────────
// On-disk file permissions
// ──────────────────────────────────────────────────────────────────────────────

// secureFilePermissions is the mode used for every file this transport writes
// that contains key material or persisted router state: owner read/write only.
// Aliased from lib/config, which owns the router-wide policy, so the transport
// cannot write a state file with a looser mode than the rest of the router.
//
// Moved from: nat_state.go
const secureFilePermissions = config.SecureFilePermissions

// ──────────────────────────────────────────────────────────────────────────────
// Peer-test nonce and connection IDs
// ──────────────────────────────────────────────────────────────────────────────

// The 4-byte peer-test nonce is carried in an out-of-session header as a 64-bit
// connection ID built by the handshake library as (nonce << 32) | nonce, so
// recovering the nonce from the header is the inverse: take the high half. Naming
// the shift keeps the reader tied to that construction instead of to a bare 32.
//
// Spec: ssu2.rst §"Peer Test (Type 7)"
// Moved from: nat_outofsession_inbound.go
const (
	// peerTestNonceSize is the width of the test nonce in bytes.
	peerTestNonceSize = 4

	// connIDNonceShift is how far the nonce is shifted inside a 64-bit connection
	// ID: one nonce width, in bits.
	connIDNonceShift = peerTestNonceSize * 8 // 32
)

// ──────────────────────────────────────────────────────────────────────────────
// NAT detection retry
// ──────────────────────────────────────────────────────────────────────────────

// A peer test that times out is retried with exponential backoff before the
// router concludes it is firewalled, because one lost probe is not evidence of a
// blocked inbound path. The base delay is also the figure logged as the per-attempt
// timeout, so the log and the backoff report the same number.
//
// Moved from: nat.go
const (
	// natPeerTestMaxRetries is how many consecutive peer-test failures are
	// tolerated before the router classifies itself firewalled and falls back to
	// introducers.
	natPeerTestMaxRetries = 3

	// natPeerTestInitialBackoff is the first retry delay, doubled on each
	// subsequent failure.
	natPeerTestInitialBackoff = 60 * time.Second
)

// ──────────────────────────────────────────────────────────────────────────────
// Address parsing
// ──────────────────────────────────────────────────────────────────────────────

// minIPv6Colons is how many colons an address must contain before it can be an
// unbracketed IPv6 literal rather than host:port.
//
// Moved from: router_address.go
const minIPv6Colons = 2
