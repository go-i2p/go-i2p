package reseed

import "net"

const (
	DefaultDialTimeout = 5 * 1000 // 5 seconds
	DefaultKeepAlive   = 5 * 1000 // 5 seconds
)

func NewReseed() *Reseed {
	return &Reseed{
		Dialer: net.Dialer{
			Timeout:   DefaultDialTimeout,
			KeepAlive: DefaultKeepAlive,
		},
	}
}
