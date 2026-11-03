package ntcp2

import (
	"time"

	"github.com/go-i2p/go-noise/ntcp2"
	"github.com/go-i2p/logger"
)

// DefaultMaxSessions is the default maximum number of concurrent NTCP2 sessions.
// This prevents resource exhaustion under heavy load.
const DefaultMaxSessions = 512

// DefaultMaxInflightHandshakes is the default cap on concurrent inbound
// handshakes, authenticated or not. See [Config.MaxInflightHandshakes].
//
// Sized well below DefaultMaxSessions: a handshake is unauthenticated work, so
// its budget must be smaller than the session budget it feeds, and a flood that
// spends it should shed connections rather than queue goroutines.
const DefaultMaxInflightHandshakes = 64

// DefaultMaxHandshakesPerSource is the default cap on concurrent inbound
// handshakes from one source IP. See [Config.MaxHandshakesPerSource].
//
// Routers legitimately share an address behind NAT or in a hosting facility, so
// this is generous enough for a small cluster of peers while still preventing
// one host from consuming the whole transport-wide budget.
const DefaultMaxHandshakesPerSource = 8

// Config holds the configuration parameters for an NTCP2 transport instance, including listener address, working directory, and session limits.
// It is passed to NewNTCP2Transport and validated before the transport starts.
// See also [NewConfig] and [DefaultMaxSessions].
type Config struct {
	ListenerAddress         string // Address to listen on, e.g., ":42069"
	WorkingDir              string // Working directory for persistent storage (e.g., ~/.go-i2p/config)
	MaxSessions             int    // Maximum number of concurrent sessions (0 = use DefaultMaxSessions)
	PendingConnQueueTimeout time.Duration
	// MaxInflightHandshakes bounds how many inbound NTCP2 handshakes the
	// transport will run at the same time, before any of them authenticates.
	// Zero (the default) selects [DefaultMaxInflightHandshakes]; a negative
	// value disables the bound.
	//
	// A handshake costs the router a goroutine, a socket, and the buffers the
	// handshake allocates, and the requester pays nothing for it. Without this
	// cap, an unauthenticated host can grow that cost without limit — the 512
	// session ceiling cannot help, because it is only checked after a handshake
	// succeeds.
	MaxInflightHandshakes int
	// MaxHandshakesPerSource bounds how many of those concurrent handshakes may
	// come from one source IP. Zero selects [DefaultMaxHandshakesPerSource]; a
	// negative value disables the per-source bound.
	MaxHandshakesPerSource int
	*ntcp2.Config
}

// GetMaxInflightHandshakes returns the effective inbound handshake concurrency
// cap. Zero selects [DefaultMaxInflightHandshakes]; a negative value means the
// bound is disabled and is returned as -1.
func (c *Config) GetMaxInflightHandshakes() int {
	if c == nil || c.MaxInflightHandshakes == 0 {
		return DefaultMaxInflightHandshakes
	}
	return c.MaxInflightHandshakes
}

// GetMaxHandshakesPerSource returns the effective per-source inbound handshake
// cap. Zero selects [DefaultMaxHandshakesPerSource]; a negative value means the
// bound is disabled and is returned as -1.
func (c *Config) GetMaxHandshakesPerSource() int {
	if c == nil || c.MaxHandshakesPerSource == 0 {
		return DefaultMaxHandshakesPerSource
	}
	return c.MaxHandshakesPerSource
}

// GetMaxSessions returns the effective maximum session limit.
// Returns DefaultMaxSessions if MaxSessions is not set (0 or negative).
func (c *Config) GetMaxSessions() int {
	if c.MaxSessions <= 0 {
		return DefaultMaxSessions
	}
	return c.MaxSessions
}

// NewConfig creates a new Config with the specified listener address and default values for other fields.
// It validates the listener address up front so misconfiguration is caught at
// construction time rather than when the transport tries to bind. See also [Config].
func NewConfig(listenerAddress string) (*Config, error) {
	log.WithFields(logger.Fields{
		"at":               "NewConfig",
		"reason":           "initialization",
		"phase":            "startup",
		"listener_address": listenerAddress,
	}).Debug("creating new NTCP2 config")
	return &Config{
		ListenerAddress:         listenerAddress,
		WorkingDir:              "", // Must be set before use
		PendingConnQueueTimeout: 5 * time.Second,
		Config:                  nil, // Will be set when identity is provided
	}, nil
}

// Validate checks the Config for required fields and returns an error if the configuration is invalid.
func (c *Config) Validate() error {
	log.WithFields(logger.Fields{
		"at":               "(Config) Validate",
		"reason":           "verifying_configuration",
		"phase":            "startup",
		"listener_address": c.ListenerAddress,
	}).Debug("validating NTCP2 config")
	// Add any necessary validation logic for the configuration
	if c.ListenerAddress == "" {
		log.WithFields(logger.Fields{
			"at":     "(Config) Validate",
			"reason": "empty_listener_address",
			"phase":  "startup",
		}).Error("NTCP2 config validation failed")
		return ErrInvalidListenerAddress
	}
	log.WithFields(logger.Fields{
		"at":     "(Config) Validate",
		"reason": "validation_successful",
		"phase":  "startup",
	}).Debug("NTCP2 config validated successfully")
	return nil
}
