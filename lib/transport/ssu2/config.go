package ssu2

import (
	ssu2noise "github.com/go-i2p/go-noise/ssu2"
	"github.com/go-i2p/logger"
)

// DefaultMaxSessions is the default maximum number of concurrent SSU2 sessions.
const DefaultMaxSessions = 512

// Config holds SSU2 transport configuration, extending the go-noise SSU2Config
// with transport-layer settings needed by the go-i2p router.
type Config struct {
	ListenerAddress string // UDP address to listen on, e.g. ":9002"
	WorkingDir      string // Persistent storage path for keys
	MaxSessions     int    // Maximum concurrent sessions (0 = DefaultMaxSessions)
	*ssu2noise.SSU2Config
}

// GetMaxSessions returns the effective maximum session limit.
func (c *Config) GetMaxSessions() int {
	if c.MaxSessions <= 0 {
		return DefaultMaxSessions
	}
	return c.MaxSessions
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
