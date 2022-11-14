package noise

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	"time"

	cb "github.com/emirpasic/gods/queues/circularbuffer"
	"github.com/flynn/noise"
	log "github.com/sirupsen/logrus"

	"github.com/go-i2p/go-i2p/lib/common/router_info"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/transport"
)

type NoiseSession struct {
	router_info.RouterInfo
	*noise.CipherState
	sync.Mutex
	*sync.Cond
	*NoiseTransport
	noise.DHKey
	RecvQueue         *cb.Queue
	SendQueue         *cb.Queue
	VerifyCallback    VerifyCallbackFunc
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
	s.SendQueue.Enqueue(msg)
}

func (s *NoiseSession) SendQueueSize() int {
	return s.SendQueue.Size()
}

func (s *NoiseSession) ReadNextI2NP() (i2np.I2NPMessage, error) {
	return i2np.I2NPMessage{}, nil
}

func (s *NoiseSession) Close() error {
	s.SendQueue.Clear()
	s.RecvQueue.Clear()
	return nil
}

func (c *NoiseSession) processCallback(publicKey []byte, payload []byte) error {
	if c.VerifyCallback == nil {
		return nil
	}

	err := c.VerifyCallback(publicKey, payload)
	return err
}

// newBlock allocates a new packet, from hc's free list if possible.
func newBlock() []byte {
	return make([]byte, MaxPayloadSize)
}

type VerifyCallbackFunc func(publicKey []byte, data []byte) error

func NewNoiseTransportSession(ri router_info.RouterInfo) (transport.TransportSession, error) {
	socket, err := DialNoise("noise", ri)
	if err != nil {
		return nil, err
	}
	return &NoiseSession{
		SendQueue:  cb.New(1024),
		RecvQueue:  cb.New(1024),
		RouterInfo: ri,
		Conn:       socket,
	}, nil
}

// DialNoise initiates a session with a remote Noise transport, using a
// routerinfo to derive the address to connect to. It doesn't have any chance of
// working yet.
func DialNoise(network string, addr router_info.RouterInfo) (net.Conn, error) {
	for _, addr := range addr.RouterAddresses() {
		log.WithFields(log.Fields{
			"at":   "(DialNoise)",
			"addr": addr,
		}).Error("error parsing router info")
		Dial("noise", string(addr.TransportStyle()))
	}
	return nil, fmt.Errorf("No valid transport discovered.")
}

// Dial initiates a session with a remote Noise transport at a host:port
// or ip:port
func Dial(network, addr string) (net.Conn, error) {
	return net.Dial("tcp", addr)
}
