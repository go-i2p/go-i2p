package noise

import (
	"net"
	"sync"
	"time"

	"github.com/flynn/noise"
	"github.com/go-i2p/go-i2p/lib/common/router_address"
)

const FlushLimit = 640 * 1024

type NoiseConn struct {
	Noise
	net.Conn
	sync.Mutex
	laddr, raddr router_address.RouterAddress
	lock         bool
}

func (ns *NoiseConn) unlockMutex() {
	if ns.lock {
		ns.lock = false
		ns.Mutex.Unlock()
	}
}

func (ns *NoiseConn) lockMutex() {
	if !ns.lock {
		ns.lock = true
		ns.Mutex.Lock()
	}
}

// Close implements net.Conn.
func (nc *NoiseConn) Close() error {
	return nc.Conn.Close()
}

// LocalAddr implements net.Conn.
func (nc *NoiseConn) LocalAddr() net.Addr {
	return &nc.laddr
}

// Write implements net.Conn.
func (nc *NoiseConn) Write(b []byte) (n int, err error) {
	nc.lockMutex()
	if nc.HandshakeState != nil {
		defer nc.unlockMutex()
		for nc.HandshakeState != nil && len(b) > 0 {
			if !nc.Initiator {
				// If we're the initiator, then we set that in advance and we already know.
				// If not, we need to read the handshake state first.
				err = nc.HandshakeStateRead()
				if err != nil {
					return n, err
				}
			}
			// if the HandshakeState is not populated here we are the initiator.
			// we could(should? shouldn't?) check both but for now I'm sticking with what
			// NoiseConn does
			if nc.HandshakeState != nil {
				// choose either the length of b or the maximum length of a message
				l := min(noise.MaxMsgLen, len(b))
				// update the HandshakeState using l number of bytes to the write message buffer
				nc.writeMsgBuf, err = nc.HandshakeStateCreate(nc.writeMsgBuf[:0], b[:l])
				if err != nil {
					return n, err
				}
				// write the message buffer to the socket
				_, err = nc.Conn.Write(nc.writeMsgBuf)
				if err != nil {
					return n, err
				}
				n += l
				b = b[l:]
			}
		}
	}
	nc.unlockMutex()
	// zero-out the write buffer
	nc.writeMsgBuf = nc.writeMsgBuf[:0]
	for len(b) > 0 {
		outlen := len(nc.writeMsgBuf)
		l := min(noise.MaxMsgLen, len(b))
		nc.writeMsgBuf, err = nc.send.Encrypt(append(nc.writeMsgBuf, make([]byte, 4)...), nil, b[:l])
		if err != nil {
			return n, err
		}
		err = nc.Frame(nc.writeMsgBuf[outlen:], nc.writeMsgBuf[outlen+4:])
		if err != nil {
			return n, err
		}
		n += l
		b = b[l:]
		if len(nc.writeMsgBuf) > FlushLimit {
			_, err = nc.Conn.Write(nc.writeMsgBuf)
			if err != nil {
				return n, err
			}
			nc.writeMsgBuf = nc.writeMsgBuf[:0]
		}
	}
	if len(nc.writeMsgBuf) > 0 {
		_, err = nc.Conn.Write(nc.writeMsgBuf)
		if err != nil {
			return n, err
		}
		nc.writeMsgBuf = nc.writeMsgBuf[:0]
	}
	return n, nil
}

// Read implements net.Conn.
func (nc *NoiseConn) Read(b []byte) (n int, err error) {
	panic("unimplemented")
}

// RemoteAddr implements net.Conn.
func (nc *NoiseConn) RemoteAddr() net.Addr {
	panic("unimplemented")
}

// SetDeadline implements net.Conn.
func (nc *NoiseConn) SetDeadline(t time.Time) error {
	panic("unimplemented")
}

// SetReadDeadline implements net.Conn.
func (nc *NoiseConn) SetReadDeadline(t time.Time) error {
	panic("unimplemented")
}

// SetWriteDeadline implements net.Conn.
func (nc *NoiseConn) SetWriteDeadline(t time.Time) error {
	panic("unimplemented")
}
