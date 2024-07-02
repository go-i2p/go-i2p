package noise

import (
	"net"
	"time"
)

type NoisePacketConn struct {
	*Noise
	net.PacketConn
}

// Close implements net.PacketConn.
// Subtle: this method shadows the method (PacketConn).Close of NoisePacketConn.PacketConn.
func (n *NoisePacketConn) Close() error {
	return n.PacketConn.Close()
}

// LocalAddr implements net.PacketConn.
func (n *NoisePacketConn) LocalAddr() net.Addr {
	return &n.Noise.RouterAddress
}

// ReadFrom implements net.PacketConn.
func (*NoisePacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	panic("unimplemented")
}

// SetDeadline implements net.PacketConn.
// Subtle: this method shadows the method (PacketConn).SetDeadline of NoisePacketConn.PacketConn.
func (n *NoisePacketConn) SetDeadline(t time.Time) error {
	panic("unimplemented")
}

// SetReadDeadline implements net.PacketConn.
// Subtle: this method shadows the method (PacketConn).SetReadDeadline of NoisePacketConn.PacketConn.
func (n *NoisePacketConn) SetReadDeadline(t time.Time) error {
	panic("unimplemented")
}

// SetWriteDeadline implements net.PacketConn.
// Subtle: this method shadows the method (PacketConn).SetWriteDeadline of NoisePacketConn.PacketConn.
func (n *NoisePacketConn) SetWriteDeadline(t time.Time) error {
	panic("unimplemented")
}

// WriteTo implements net.PacketConn.
func (*NoisePacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	panic("unimplemented")
}
