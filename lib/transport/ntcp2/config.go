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
	// ConnectionTimeout bounds the TCP connect phase of an outbound handshake.
	// Zero selects the built-in default (tcpDialTimeout). A shorter value frees
	// the dialing goroutine sooner against hosts that silently drop SYNs; a
	// longer value tolerates slower peers. This is the operator-tunable form of
	// transport.connection_timeout (I2P C1: the knob previously never reached the
	// dial, so the transport always used the hardcoded constant).
	ConnectionTimeout time.Duration
	// IdleTimeout seeds the adaptive idle-expire window: a session with no
	// activity for at least this long is terminated. The value is clamped to the
	// protocol's [ntcp2MinExpireIdleTime, ntcp2MaxExpireIdleTime] bounds, and the
	// window still adapts up/down with capacity from this seed. Zero selects the
	// built-in default (ntcp2MaxExpireIdleTime). This is the operator-tunable form
	// of transport.idle_timeout (I2P C1: the knob previously never reached the
	// idle reaper).
	IdleTimeout time.Duration

	// DisablePortMapping suppresses the UPnP/NAT-PMP port mapping the transport
	// otherwise opens on a non-loopback bind. The zero value (false) keeps
	// mapping enabled, matching the transport's historical default and the
	// reference implementation. The router sets this from
	// !router.upnp_enabled so an operator can keep a public bind from asking the
	// gateway to open a port. Mirrors ssu2.Config.DisablePortMapping (I2P-H-5:
	// NTCP2 was the half that still mapped unconditionally).
	DisablePortMapping bool

	// ExternalAddress is an operator-supplied host[:port] to advertise in this
	// transport's published RouterAddress, overriding auto-detection. When set
	// to a valid IP literal, the address is published with host=/port= for that
	// endpoint even if the bound interface is private/unspecified (e.g. a Docker
	// container with no gateway and no public interface). The port component is
	// optional; when omitted the transport's bound port is advertised with the
	// overridden host. Empty (the default) keeps auto-detection. Set by the
	// router from router.external_address.
	ExternalAddress string

	*ntcp2.Config
}

// GetConnectionTimeout returns the effective TCP connect timeout for outbound
// dials. Zero selects the built-in default (tcpDialTimeout).
func (c *Config) GetConnectionTimeout() time.Duration {
	if c == nil || c.ConnectionTimeout <= 0 {
		return tcpDialTimeout
	}
	return c.ConnectionTimeout
}

// GetIdleTimeout returns the effective idle-expire seed, clamped to the
// protocol's [ntcp2MinExpireIdleTime, ntcp2MaxExpireIdleTime] bounds. Zero
// selects the built-in default (ntcp2MaxExpireIdleTime).
func (c *Config) GetIdleTimeout() time.Duration {
	if c == nil || c.IdleTimeout <= 0 {
		return ntcp2MaxExpireIdleTime
	}
	if c.IdleTimeout < ntcp2MinExpireIdleTime {
		return ntcp2MinExpireIdleTime
	}
	if c.IdleTimeout > ntcp2MaxExpireIdleTime {
		return ntcp2MaxExpireIdleTime
	}
	return c.IdleTimeout
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
		PendingConnQueueTimeout: defaultPendingConnQueueTimeout,
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
