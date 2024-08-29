package noise

import (
	"net"
	"sync"

	"github.com/flynn/noise"
)

type NoiseListener struct {
	Noise
	net.Listener
	sync.Mutex
	lock bool
}

// Addr implements net.Listener.
func (ns *NoiseListener) Addr() net.Addr {
	return ns.Noise.Addr()
}

// Close implements net.Listener.
func (ns *NoiseListener) Close() error {
	return ns.Listener.Close()
}

// Accept implements net.Listener.
func (ns *NoiseListener) Accept() (net.Conn, error) {
	cfg := ns.Noise
	cfg.Initiator = false
	accept, err := ns.Listener.Accept()
	if err != nil {
		return nil, err
	}
	hs, err := noise.NewHandshakeState(ns.Config)
	if err != nil {
		return nil, err
	}
	cfg.HandshakeState = hs
	return &NoiseConn{
		Noise: cfg,
		Conn:  accept,
	}, nil
}
