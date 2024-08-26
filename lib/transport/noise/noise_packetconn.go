package noise

import (
	"net"
	"time"
)

type NoisePacketConn struct {
	*Noise
	// this is always a actually a PacketConn
	net.Conn
}

// Read implements net.Conn.
func (*NoisePacketConn) Read(b []byte) (n int, err error) {
	panic("unimplemented")
}

// RemoteAddr implements net.Conn.
func (n *NoisePacketConn) RemoteAddr() net.Addr {
	panic("unimplemented")
}

// Write implements net.Conn.
func (*NoisePacketConn) Write(b []byte) (n int, err error) {
	panic("unimplemented")
}

// Close implements net.PacketConn.
// Subtle: this method shadows the method (Conn).Close of NoisePacketConn.Conn.
func (n *NoisePacketConn) Close() error {
	return n.Conn.Close()
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
