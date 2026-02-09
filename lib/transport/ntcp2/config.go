package ntcp2

import (
	"github.com/go-i2p/go-noise/ntcp2"
	"github.com/go-i2p/logger"
)

// DefaultMaxSessions is the default maximum number of concurrent NTCP2 sessions.
// This prevents resource exhaustion under heavy load.
const DefaultMaxSessions = 512

type Config struct {
	ListenerAddress string // Address to listen on, e.g., ":42069"
	WorkingDir      string // Working directory for persistent storage (e.g., ~/.go-i2p/config)
	MaxSessions     int    // Maximum number of concurrent sessions (0 = use DefaultMaxSessions)
	*ntcp2.NTCP2Config
}

// GetMaxSessions returns the effective maximum session limit.
// Returns DefaultMaxSessions if MaxSessions is not set (0 or negative).
func (c *Config) GetMaxSessions() int {
	if c.MaxSessions <= 0 {
		return DefaultMaxSessions
	}
	return c.MaxSessions
}

func NewConfig(listenerAddress string) (*Config, error) {
	log.WithFields(logger.Fields{
		"at":               "NewConfig",
		"reason":           "initialization",
		"phase":            "startup",
		"listener_address": listenerAddress,
	}).Debug("creating new NTCP2 config")
	return &Config{
		ListenerAddress: listenerAddress,
		WorkingDir:      "",  // Must be set before use
		NTCP2Config:     nil, // Will be set when identity is provided
	}, nil
}

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
