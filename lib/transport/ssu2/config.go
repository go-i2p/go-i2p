package ssu2

import (
	"time"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	ssu2noise "github.com/go-i2p/go-noise/ssu2"
	"github.com/go-i2p/logger"
)

// DefaultMaxSessions is the default maximum number of concurrent SSU2 sessions.
const DefaultMaxSessions = 512

// DefaultKeepaliveInterval is the SSU2 keepalive interval used by this implementation (15 s).
// NOTE: The SSU2 spec's 15-second value is a retransmit timeout, not a keepalive interval;
// this value is an implementation choice.
// Shorter values help aggressive NATs at the cost of extra traffic.
const DefaultKeepaliveInterval = 15 * time.Second

// DefaultMaxRetransmissions is the number of I2NP message retransmission attempts
// before the session is torn down.
const DefaultMaxRetransmissions = 3

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
type Config struct {
	ListenerAddress    string        // UDP address to listen on, e.g. ":9002"
	WorkingDir         string        // Persistent storage path for keys
	MaxSessions        int           // Maximum concurrent sessions (0 = DefaultMaxSessions)
	KeepaliveInterval  time.Duration // How often keepalive packets are sent (0 = DefaultKeepaliveInterval)
	MaxRetransmissions int           // I2NP retransmission attempts before teardown (0 = DefaultMaxRetransmissions)
	HolePunchDelay     time.Duration // Delay before sending SessionRequest after RelayResponse (0 = default 150ms)

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
func (c *Config) GetMaxSessions() int {
	if c.MaxSessions <= 0 {
		return DefaultMaxSessions
	}
	return c.MaxSessions
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
		SSU2Config:      nil,
	}, nil
}

// Validate checks the configuration for correctness.
func (c *Config) Validate() error {
	if c.ListenerAddress == "" {
		return ErrInvalidListenerAddress
	}
	return nil
}
