package ssu2

import (
	"time"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	ssu2noise "github.com/go-i2p/go-noise/ssu2"
	"github.com/go-i2p/logger"
)

// DefaultMaxSessions is the default maximum number of concurrent SSU2 sessions.
// It caps the number of simultaneous sessions to bound memory and CPU usage on
// a router that accepts many inbound UDP connections.
const DefaultMaxSessions = 512

// DefaultKeepaliveInterval is the SSU2 keepalive interval used by this implementation (15 s).
// NOTE: The SSU2 spec's 15-second value is a retransmit timeout, not a keepalive interval;
// this value is an implementation choice.
// Shorter values help aggressive NATs at the cost of extra traffic.
const DefaultKeepaliveInterval = 15 * time.Second

// DefaultMaxRetransmissions is the number of I2NP message retransmission attempts
// before the session is torn down.
const DefaultMaxRetransmissions = 3

// DefaultMaxInflightHandshakes is the default cap on concurrent inbound SSU2
// responder handshakes, authenticated or not. See [Config.MaxInflightHandshakes].
//
// A pre-handshake SessionRequest costs this router a goroutine, listener state
// for the pending session and a handshake window, and the peer proves nothing to
// get it. The cap bounds that cost; 64 is enough for a router establishing
// sessions at a normal rate and small enough that a flood cannot grow the
// handshake work past it.
const DefaultMaxInflightHandshakes = 64

// DefaultMaxHandshakesPerSource is the default cap on concurrent inbound SSU2
// handshakes from one source IP. See [Config.MaxHandshakesPerSource].
const DefaultMaxHandshakesPerSource = 8

// DefaultHandshakeTimeout bounds one inbound SSU2 responder handshake when the
// transport's go-noise config carries no value of its own. It matches go-noise's
// spec-derived default (ssu2.rst: 15 s), so this only makes the bound explicit
// rather than changing it.
const DefaultHandshakeTimeout = 15 * time.Second

// DefaultRequireRetry is the transport's default for [Config.RequireRetry].
//
// It is FALSE, and deliberately so, even though source-address validation is a
// real hardening: go-i2p pins a go-noise whose Retry-issuance path
// (SSU2Listener.processTokenRequest → verifyIntroKeyMessage) AEAD-opens the
// inbound packet's payload with the intro key as if it were a Token Request. A
// SessionRequest's payload is Noise-encrypted, not intro-key-sealed, so that
// check always fails and the SessionRequest is dropped with
// "failed to send Retry: no token present in SessionRequest" — before any session
// is created. Turning RequireRetry on therefore rejects EVERY inbound
// SessionRequest, including valid peers, which is a total inbound SSU2 outage:
// strictly worse than the stall it was meant to prevent.
//
// The pre-authentication stall in finding 005 is fixed by the other controls here
// (the responder handshake moved off the accept path, CloseImmediate, and the
// [Config.MaxInflightHandshakes] budget), none of which depend on RequireRetry.
// The knob stays wired so an operator can opt in once go-noise's Retry path
// handles a Noise-encrypted SessionRequest payload; until then the default must
// stay off.
const DefaultRequireRetry = false

// DefaultHolePunchDelay is the time Alice waits for Charlie's hole-punch packets
// to arrive before sending the SessionRequest directly during introducer-based
// relay connections.
//
// Rationale: In the 6-step SSU2 relay flow, after Alice receives Bob's RelayResponse
// (step 4), Charlie sends a HolePunch to Alice (step 5) to create NAT state, then
// Alice sends a direct SessionRequest to Charlie (step 6). The delay gives Charlie's
// hole-punch a chance to arrive and open NAT bindings before Alice's direct packet,
// improving connection success rates.
//
// The 150ms default assumes:
//   - Typical relay RTT (Alice ↔ Bob ↔ Charlie) is 100-200ms
//   - Charlie processes RelayIntro and sends HolePunch within 50ms
//   - Network jitter is <50ms
//
// Operators may tune this value based on observed network conditions:
//   - Lower values (50-100ms) work for low-latency networks but risk premature sends
//   - Higher values (200-300ms) help high-latency/jitter cases but increase dial time
//
// T-3 note: Future enhancement could derive this from observed RTT to Bob/Charlie
// where available. Built-in retransmission at the SSU2 message layer makes a
// too-early send recoverable.
const DefaultHolePunchDelay = 150 * time.Millisecond

// Config holds SSU2 transport configuration, extending the go-noise SSU2Config
// with transport-layer settings needed by the go-i2p router.
// It is the single configuration object passed to NewSSU2Transport, which
// uses it to bind the UDP listener and size the session pool.
// See [I2P Spec: SSU2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ssu2.rst) for the protocol.
// See also [NewConfig] and [SSU2Transport].
type Config struct {
	ListenerAddress    string        // UDP address to listen on, e.g. ":9002"
	WorkingDir         string        // Persistent storage path for keys
	MaxSessions        int           // Maximum concurrent sessions (0 = DefaultMaxSessions)
	KeepaliveInterval  time.Duration // How often keepalive packets are sent (0 = DefaultKeepaliveInterval)
	MaxRetransmissions int           // I2NP retransmission attempts before teardown (0 = DefaultMaxRetransmissions)
	HolePunchDelay     time.Duration // Delay before sending SessionRequest after RelayResponse (0 = default 150ms)

	// MaxInflightHandshakes bounds how many inbound SSU2 responder handshakes
	// the transport runs at once, before any of them authenticates. Unlike
	// MaxSessions, which is only enforced after a handshake succeeds, this caps
	// the work an unauthenticated SessionRequest can make the router do.
	// Zero (the default) selects [DefaultMaxInflightHandshakes]; a negative
	// value disables the bound.
	MaxInflightHandshakes int

	// MaxHandshakesPerSource bounds how many of those concurrent handshakes may
	// come from one source IP, so a single host cannot consume the whole
	// budget. Zero selects [DefaultMaxHandshakesPerSource]; a negative value
	// disables the bound.
	MaxHandshakesPerSource int

	// InboundHandshakeTimeout bounds one inbound SSU2 responder handshake: the
	// deadline the transport's handshake worker enforces, and the value published
	// onto the go-noise config so the timeouts go-noise applies internally agree
	// with it. Zero selects [DefaultHandshakeTimeout].
	//
	// It is a construction-time field on purpose. The go-noise listener copies its
	// config into every session it creates, so mutating the noise config once the
	// listener is running is a data race — which is why
	// [Config.GetHandshakeTimeout] resolves this field rather than reading the
	// live noise config.
	InboundHandshakeTimeout time.Duration

	// RequireRetry makes the listener answer a SessionRequest that carries no
	// valid token with a Retry, so the initiator must prove it can receive
	// packets at the claimed source address before this router spends a
	// handshake on it. This is SSU2's own source-address validation, and in
	// principle it is the reason a spoofed-source flood should cost the spoofer
	// more than it costs us.
	//
	// Do NOT turn this on yet. The pinned go-noise treats the SessionRequest as
	// if it were a Token Request when issuing the Retry token and AEAD-opens its
	// payload with the intro key, which a Noise-encrypted SessionRequest payload
	// can never satisfy — so every inbound SessionRequest is dropped. See
	// [DefaultRequireRetry] for the full failure mode. The transport's own
	// pre-authentication bounds ([Config.MaxInflightHandshakes],
	// [Config.MaxHandshakesPerSource]) are what actually cap the cost of a
	// spoofed flood today.
	//
	// Defaults to [DefaultRequireRetry] (off). Opt in with
	// transport.ssu2_require_retry once go-noise's Retry path is fixed.
	RequireRetry bool

	// RouterLookupFunc looks up a RouterInfo by identity hash.
	// Required for SSU2 via introducers: Alice looks up Bob (the introducer)
	// to get a direct dialable address before sending the RelayRequest.
	RouterLookupFunc func(hash data.Hash) (router_info.RouterInfo, error)

	// RouterStoreFunc stores RouterInfo data received via SSU2 blocks.
	// Called when a peer sends a RouterInfo block (type 2) during a session.
	// The function should parse, verify, and persist the RouterInfo to NetDB.
	//
	// E-4 documentation: RouterStoreFunc MUST be wired for production deployments.
	// When nil, inbound RouterInfo blocks are discarded with a warn-level log
	// (emitted once per transport lifetime), which breaks reply routing for tunnel
	// builds. Tests can safely leave this nil. Production routers must provide a
	// NetDB storage callback or tunnel build replies may fail silently.
	RouterStoreFunc func(data []byte) error

	*ssu2noise.SSU2Config
}

// GetMaxSessions returns the effective maximum session limit.
// It falls back to DefaultMaxSessions when MaxSessions is unset (zero or
// negative), so callers can rely on a sane limit without extra checks.
func (c *Config) GetMaxSessions() int {
	if c.MaxSessions <= 0 {
		return DefaultMaxSessions
	}
	return c.MaxSessions
}

// GetMaxInflightHandshakes returns the effective inbound handshake concurrency
// cap. Zero selects [DefaultMaxInflightHandshakes]; a negative value means the
// bound is disabled and every inbound handshake is admitted.
func (c *Config) GetMaxInflightHandshakes() int {
	if c == nil || c.MaxInflightHandshakes == 0 {
		return DefaultMaxInflightHandshakes
	}
	return c.MaxInflightHandshakes
}

// GetMaxHandshakesPerSource returns the effective per-source inbound handshake
// cap. Zero selects [DefaultMaxHandshakesPerSource]; a negative value means the
// bound is disabled.
func (c *Config) GetMaxHandshakesPerSource() int {
	if c == nil || c.MaxHandshakesPerSource == 0 {
		return DefaultMaxHandshakesPerSource
	}
	return c.MaxHandshakesPerSource
}

// GetHandshakeTimeout returns the bound applied to one inbound responder
// handshake. It resolves [Config.InboundHandshakeTimeout], falling back to
// [DefaultHandshakeTimeout] when unset; a negative value returns the value from
// the go-noise config, which is how an operator opts out of this layer's bound
// and lets go-noise's own handshake budget apply.
//
// It deliberately does NOT read the live noise config: the listener copies that
// config into every session, so the transport's worker and the listener could
// otherwise disagree, and a test that set the noise value after the listener
// started would race it.
func (c *Config) GetHandshakeTimeout() time.Duration {
	if c == nil {
		return DefaultHandshakeTimeout
	}
	switch {
	case c.InboundHandshakeTimeout == 0:
		return DefaultHandshakeTimeout
	case c.InboundHandshakeTimeout < 0:
		if c.SSU2Config != nil && c.SSU2Config.HandshakeTimeout > 0 {
			return c.SSU2Config.HandshakeTimeout
		}
		return DefaultHandshakeTimeout
	default:
		return c.InboundHandshakeTimeout
	}
}

// GetKeepaliveInterval returns the effective keepalive interval.
// Shorter values help aggressive NATs that time out idle UDP bindings quickly.
func (c *Config) GetKeepaliveInterval() time.Duration {
	if c.KeepaliveInterval <= 0 {
		return DefaultKeepaliveInterval
	}
	return c.KeepaliveInterval
}

// GetMaxRetransmissions returns the effective maximum I2NP retransmission count.
// It falls back to DefaultMaxRetransmissions when MaxRetransmissions is unset,
// so callers can rely on a sane retry limit without extra checks.
func (c *Config) GetMaxRetransmissions() int {
	if c.MaxRetransmissions <= 0 {
		return DefaultMaxRetransmissions
	}
	return c.MaxRetransmissions
}

// GetHolePunchDelay returns the effective hole-punch delay.
// This delay allows Charlie's hole-punch packets to arrive and open NAT bindings
// before Alice sends the direct SessionRequest during introducer-based relay.
// See DefaultHolePunchDelay for tuning guidance.
func (c *Config) GetHolePunchDelay() time.Duration {
	if c.HolePunchDelay <= 0 {
		return DefaultHolePunchDelay
	}
	return c.HolePunchDelay
}

// NewConfig creates a new SSU2 Config with the given listener address.
// It returns a Config with only the listener address set and source-address
// validation on; the remaining limits (session pool, handshake budget,
// keepalive, retransmissions) fall back to their defaults via the Get* methods.
// Call Validate to check the listener address before use.
// See also [Config] and [NewSSU2Transport].
func NewConfig(listenerAddress string) (*Config, error) {
	log.WithFields(logger.Fields{
		"at":               "NewConfig",
		"reason":           "initialization",
		"phase":            "startup",
		"listener_address": listenerAddress,
	}).Debug("creating new SSU2 config")
	return &Config{
		ListenerAddress: listenerAddress,
		WorkingDir:      "",
		RequireRetry:    DefaultRequireRetry,
		SSU2Config:      nil,
	}, nil
}

// Validate checks the configuration for correctness.
// It returns ErrInvalidListenerAddress when the listener address is empty,
// which would prevent the UDP listener from binding.
func (c *Config) Validate() error {
	if c.ListenerAddress == "" {
		return ErrInvalidListenerAddress
	}
	return nil
}
