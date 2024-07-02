package noise

import (
	"net"
	"strings"
)

type NoiseListener struct {
	*Noise
	net.Listener
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
	return ns.Listener.Accept()
}

func (ns *Noise) ListenNoise() (list NoiseListener, err error) {
	ns.Config.Initiator = false
	network := "tcp"
	if strings.HasPrefix(strings.ToLower(ns.Network()), "ssu") {
		network = "udp"
	}
	host, err := ns.Host()
	if err != nil {
		return
	}
	port, err := ns.Port()
	if err != nil {
		return
	}
	hostip := net.JoinHostPort(host.String(), port)
	listener, err := net.Listen(network, hostip)
	if err != nil {
		return
	}
	return NoiseListener{
		Noise:    ns,
		Listener: listener,
	}, nil
}