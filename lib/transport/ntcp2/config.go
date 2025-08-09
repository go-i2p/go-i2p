package ntcp2

import "github.com/go-i2p/go-noise/ntcp2"

type Config struct {
	ListenerAddress string // Address to listen on, e.g., ":42069"
	*ntcp2.NTCP2Config
}

func NewConfig(listenerAddress string) (*Config, error) {
	ntcp2Config, err := ntcp2.NewNTCP2Config(nil, false)
	if err != nil {
		return nil, err
	}
	return &Config{
		ListenerAddress: listenerAddress,
		NTCP2Config:     ntcp2Config,
	}, nil
}

func (c *Config) Validate() error {
	// Add any necessary validation logic for the configuration
	if c.ListenerAddress == "" {
		return ErrInvalidListenerAddress
	}
	return nil
}
