package noise

import (
	"net"
	"strings"
	"time"

	"github.com/flynn/noise"
)

type NoiseConn struct {
	*Noise
	net.Conn
}

// Close implements net.Conn.
func (n *NoiseConn) Close() error {
	panic("unimplemented")
}

// LocalAddr implements net.Conn.
func (n *NoiseConn) LocalAddr() net.Addr {
	panic("unimplemented")
}

// Read implements net.Conn.
func (*NoiseConn) Read(b []byte) (n int, err error) {
	panic("unimplemented")
}

// RemoteAddr implements net.Conn.
func (n *NoiseConn) RemoteAddr() net.Addr {
	panic("unimplemented")
}

// SetDeadline implements net.Conn.
func (n *NoiseConn) SetDeadline(t time.Time) error {
	panic("unimplemented")
}

// SetReadDeadline implements net.Conn.
func (n *NoiseConn) SetReadDeadline(t time.Time) error {
	panic("unimplemented")
}

// SetWriteDeadline implements net.Conn.
func (n *NoiseConn) SetWriteDeadline(t time.Time) error {
	panic("unimplemented")
}

// Write implements net.Conn.
func (*NoiseConn) Write(b []byte) (n int, err error) {
	panic("unimplemented")
}

func (ns *Noise) DialNoise(n, addr string) (conn NoiseConn, err error) {
	ns.Config.Initiator = true
	ns.HandshakeState, err = noise.NewHandshakeState(ns.Config)
	if err != nil {
		return
	}
	network := "tcp"
	if strings.HasPrefix(strings.ToLower(ns.Network()), "ssu") {
		network = "udp"
	}
	netConn, err := net.Dial(network, addr)
	if err != nil {
		return
	}
	return NoiseConn{
		Conn: netConn,
	}, nil
}
