package noise

import (
	"bytes"
	"net"
	"sync"
	"time"

	cb "github.com/emirpasic/gods/queues/circularbuffer"
	"github.com/flynn/noise"

	"github.com/go-i2p/go-i2p/lib/common/router_info"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/transport"
)

type NoiseSession struct {
	*cb.Queue
	router_info.RouterInfo
	*noise.CipherState
	sync.Mutex
	*sync.Cond
	*NoiseTransport
	handshakeBuffer   bytes.Buffer
	activeCall        int32
	handshakeComplete bool
	Conn              net.Conn
}

// Read implements net.Conn
func (*NoiseSession) Read(b []byte) (n int, err error) {
	panic("unimplemented")
}

// RemoteAddr implements net.Conn
func (*NoiseSession) RemoteAddr() net.Addr {
	panic("unimplemented")
}

// SetDeadline implements net.Conn
func (*NoiseSession) SetDeadline(t time.Time) error {
	panic("unimplemented")
}

// SetReadDeadline implements net.Conn
func (*NoiseSession) SetReadDeadline(t time.Time) error {
	panic("unimplemented")
}

// SetWriteDeadline implements net.Conn
func (*NoiseSession) SetWriteDeadline(t time.Time) error {
	panic("unimplemented")
}

var exampleNoiseSession transport.TransportSession = &NoiseSession{}
var ExampleNoiseSession net.Conn = exampleNoiseSession.(*NoiseSession)

func (s *NoiseSession) LocalAddr() net.Addr {
	return s.Conn.LocalAddr()
}

func (s *NoiseSession) QueueSendI2NP(msg i2np.I2NPMessage) {
	s.Queue.Enqueue(msg)
}

func (s *NoiseSession) SendQueueSize() int {
	return s.Queue.Size()
}

func (s *NoiseSession) ReadNextI2NP() (i2np.I2NPMessage, error) {
	return i2np.I2NPMessage{}, nil
}

func (s *NoiseSession) Close() error {
	s.Queue.Clear()
	return nil
}

func NewNoiseTransportSession(ri router_info.RouterInfo, socket net.Conn) (transport.TransportSession, error) {
	return &NoiseSession{
		Queue:      cb.New(1024),
		RouterInfo: ri,
		Conn:       socket,
	}, nil
}
