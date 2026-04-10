package reseed

import (
	"net"
	"time"
)

const (
	DefaultDialTimeout = 30 * time.Second // 30 seconds for HTTP requests
	DefaultKeepAlive   = 30 * time.Second // 30 seconds keep-alive
)

// NewReseed creates a new Reseed instance with default dial timeout and keep-alive settings.
func NewReseed() *Reseed {
	return &Reseed{
		Dialer: net.Dialer{
			Timeout:   DefaultDialTimeout,
			KeepAlive: DefaultKeepAlive,
		},
	}
}
