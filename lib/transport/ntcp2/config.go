package ntcp2

import "github.com/go-i2p/go-noise/ntcp2"

type Config struct {
	ListenerAddress string // Address to listen on, e.g., ":42069"
	WorkingDir      string // Working directory for persistent storage (e.g., ~/.go-i2p/config)
	*ntcp2.NTCP2Config
}

func NewConfig(listenerAddress string) (*Config, error) {
	return &Config{
		ListenerAddress: listenerAddress,
		WorkingDir:      "",  // Must be set before use
		NTCP2Config:     nil, // Will be set when identity is provided
	}, nil
}

func (c *Config) Validate() error {
	// Add any necessary validation logic for the configuration
	if c.ListenerAddress == "" {
		return ErrInvalidListenerAddress
	}
	return nil
}
