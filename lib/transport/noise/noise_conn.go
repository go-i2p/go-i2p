package noise

import (
	"net"
	"time"

	"github.com/flynn/noise"
)

const FlushLimit = 640 * 1024

type NoiseConn struct {
	*Noise
	net.Conn
}

// Close implements net.Conn.
func (nc *NoiseConn) Close() error {
	return nc.Conn.Close()
}

// LocalAddr implements net.Conn.
func (nc *NoiseConn) LocalAddr() net.Addr {
	return &nc.Noise.RouterAddress
}

// Write implements net.Conn.
func (nc *NoiseConn) Write(b []byte) (n int, err error) {
	nc.lockMutex()
	if nc.HandshakeState == nil {
		nc.unlockMutex()
	} else {
		defer nc.unlockMutex()
		for nc.HandshakeState != nil && len(b) > 0 {
			if !nc.Initiator {
				err = nc.HandshakeStateRead()
				if err != nil {
					return n, err
				}
			}
			if nc.HandshakeState != nil {
				l := min(noise.MaxMsgLen, len(b))
				nc.writeMsgBuf, err = nc.HandshakeStateCreate(nc.writeMsgBuf[:0], b[:l])
				if err != nil {
					return n, err
				}
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
