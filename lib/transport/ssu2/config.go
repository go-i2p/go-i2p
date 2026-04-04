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

// DefaultKeepaliveInterval is the SSU2 keepalive interval per the spec (15 s).
// Shorter values help aggressive NATs at the cost of extra traffic.
const DefaultKeepaliveInterval = 15 * time.Second

// DefaultMaxRetransmissions is the number of I2NP message retransmission attempts
// before the session is torn down.
const DefaultMaxRetransmissions = 3

// Config holds SSU2 transport configuration, extending the go-noise SSU2Config
// with transport-layer settings needed by the go-i2p router.
type Config struct {
	ListenerAddress    string        // UDP address to listen on, e.g. ":9002"
	WorkingDir         string        // Persistent storage path for keys
	MaxSessions        int           // Maximum concurrent sessions (0 = DefaultMaxSessions)
	KeepaliveInterval  time.Duration // How often keepalive packets are sent (0 = DefaultKeepaliveInterval)
	MaxRetransmissions int           // I2NP retransmission attempts before teardown (0 = DefaultMaxRetransmissions)

	// RouterLookupFunc looks up a RouterInfo by identity hash.
	// Required for SSU2 via introducers: Alice looks up Bob (the introducer)
	// to get a direct dialable address before sending the RelayRequest.
	RouterLookupFunc func(hash data.Hash) (router_info.RouterInfo, error)

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
