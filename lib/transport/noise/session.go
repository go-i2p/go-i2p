package noise

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	"time"

	cb "github.com/emirpasic/gods/queues/circularbuffer"
	"github.com/flynn/noise"

	"github.com/go-i2p/go-i2p/lib/common/router_info"
	"github.com/go-i2p/go-i2p/lib/transport"
)

type NoiseSession struct {
	router_info.RouterInfo
	*noise.CipherState
	sync.Mutex
	*sync.Cond
	*NoiseTransport   // The parent transport, which "Dialed" the connection to the peer whith whom we established the session
	RecvQueue         *cb.Queue
	SendQueue         *cb.Queue
	SendKey           noise.DHKey
	RecvKey           noise.DHKey
	HandKey           noise.DHKey
	VerifyCallback    VerifyCallbackFunc
	handshakeBuffer   bytes.Buffer
	activeCall        int32
	handshakeComplete bool
	Conn              net.Conn
}

// RemoteAddr implements net.Conn
func (noise_session *NoiseSession) RemoteAddr() net.Addr {
	return &noise_session.RouterInfo
}

// SetDeadline implements net.Conn
func (noise_session *NoiseSession) SetDeadline(t time.Time) error {
	return noise_session.Conn.SetDeadline(t)
}

// SetReadDeadline implements net.Conn
func (noise_session *NoiseSession) SetReadDeadline(t time.Time) error {
	return noise_session.Conn.SetReadDeadline(t)
}

// SetWriteDeadline implements net.Conn
func (noise_session *NoiseSession) SetWriteDeadline(t time.Time) error {
	return noise_session.Conn.SetWriteDeadline(t)
}

var exampleNoiseSession transport.TransportSession = &NoiseSession{}
var ExampleNoiseSession net.Conn = exampleNoiseSession.(*NoiseSession)

func (s *NoiseSession) LocalAddr() net.Addr {
	return s.Conn.LocalAddr()
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
	//socket, err := DialNoise("noise", ri)
	for _, addr := range ri.RouterAddresses() {
		socket, err := net.Dial("tcp", string(addr.Bytes()))
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
	return nil, fmt.Errorf("Transport constructor error")
}
