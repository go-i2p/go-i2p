package noise

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	cb "github.com/emirpasic/gods/queues/circularbuffer"
	"github.com/flynn/noise"

	"github.com/go-i2p/go-i2p/lib/common/router_info"
	"github.com/go-i2p/go-i2p/lib/transport"
)

type NoiseSession struct {
	router_info.RouterInfo
	*noise.CipherState
	*sync.Cond
	*NoiseTransport // The parent transport, which "Dialed" the connection to the peer with whom we established the session
	*HandshakeState
	RecvQueue      *cb.Queue
	SendQueue      *cb.Queue
	VerifyCallback VerifyCallbackFunc
	activeCall     int32
	Conn           net.Conn
}

// RemoteAddr implements net.Conn
func (noise_session *NoiseSession) RemoteAddr() net.Addr {
	log.WithField("remote_addr", noise_session.RouterInfo.String()).Debug("Getting RemoteAddr")
	return &noise_session.RouterInfo
}

// SetDeadline implements net.Conn
func (noise_session *NoiseSession) SetDeadline(t time.Time) error {
	log.WithField("deadline", t).Debug("Setting deadline")
	return noise_session.Conn.SetDeadline(t)
}

// SetReadDeadline implements net.Conn
func (noise_session *NoiseSession) SetReadDeadline(t time.Time) error {
	log.WithField("read_deadline", t).Debug("Setting read deadline")
	return noise_session.Conn.SetReadDeadline(t)
}

// SetWriteDeadline implements net.Conn
func (noise_session *NoiseSession) SetWriteDeadline(t time.Time) error {
	log.WithField("write_deadline", t).Debug("Setting write deadline")
	return noise_session.Conn.SetWriteDeadline(t)
}

var (
	exampleNoiseSession transport.TransportSession = &NoiseSession{}
	ExampleNoiseSession net.Conn                   = exampleNoiseSession.(*NoiseSession)
)

func (s *NoiseSession) LocalAddr() net.Addr {
	localAddr := s.Conn.LocalAddr()
	log.WithField("local_addr", localAddr.String()).Debug("Getting LocalAddr")
	return s.Conn.LocalAddr()
}

func (s *NoiseSession) Close() error {
	log.Debug("Closing NoiseSession")
	s.SendQueue.Clear()
	s.RecvQueue.Clear()
	log.Debug("SendQueue and RecvQueue cleared")
	return nil
}

func (c *NoiseSession) processCallback(publicKey []byte, payload []byte) error {
	log.WithFields(logrus.Fields{
		"public_key_length": len(publicKey),
		"payload_length":    len(payload),
	}).Debug("Processing callback")

	if c.VerifyCallback == nil {
		log.Debug("VerifyCallback is nil, skipping verification")
		return nil
	}
	err := c.VerifyCallback(publicKey, payload)
	if err != nil {
		log.WithError(err).Error("VerifyCallback failed")
	} else {
		log.Debug("VerifyCallback succeeded")
	}
	return err
}

// PeerStaticKey is equal to the NTCP2 peer's static public key, found in their router info
func (s *NoiseSession) peerStaticKey() ([32]byte, error) {
	for _, addr := range s.RouterInfo.RouterAddresses() {
		transportStyle, err := addr.TransportStyle().Data()
		if err != nil {
			continue
		}
		if transportStyle == NOISE_PROTOCOL_NAME {
			return addr.StaticKey()
		}
	}
	return [32]byte{}, fmt.Errorf("Remote static key error")
}

func (s *NoiseSession) peerStaticIV() ([16]byte, error) {
	for _, addr := range s.RouterInfo.RouterAddresses() {
		transportStyle, err := addr.TransportStyle().Data()
		if err != nil {
			continue
		}
		if transportStyle == NOISE_PROTOCOL_NAME {
			return addr.InitializationVector()
		}
	}
	return [16]byte{}, fmt.Errorf("Remote static IV error")
}

// newBlock allocates a new packet, from hc's free list if possible.
func newBlock() []byte {
	// return make([]byte, MaxPayloadSize)
	block := make([]byte, MaxPayloadSize)
	log.WithField("block_size", MaxPayloadSize).Debug("Created new block")
	return block
}

type VerifyCallbackFunc func(publicKey []byte, data []byte) error

func NewNoiseTransportSession(ri router_info.RouterInfo) (transport.TransportSession, error) {
	log.WithField("router_info", ri.String()).Debug("Creating new NoiseTransportSession")
	// socket, err := DialNoise("noise", ri)
	for _, addr := range ri.RouterAddresses() {
		log.WithField("address", string(addr.Bytes())).Debug("Attempting to dial")
		socket, err := net.Dial("tcp", string(addr.Bytes()))
		if err != nil {
			log.WithError(err).Error("Failed to dial address")
			return nil, err
		}
		session := &NoiseSession{
			SendQueue:  cb.New(1024),
			RecvQueue:  cb.New(1024),
			RouterInfo: ri,
			Conn:       socket,
		}
		log.WithField("local_addr", socket.LocalAddr().String()).Debug("NoiseTransportSession created successfully")
		return session, nil
	}
	log.Error("Failed to create NoiseTransportSession, all addresses failed")
	return nil, fmt.Errorf("Transport constructor error")
}

func NewNoiseSession(ri router_info.RouterInfo) (*NoiseSession, error) {
	ns, err := NewNoiseTransportSession(ri)
	if err != nil {
		return nil, err
	}
	return ns.(*NoiseSession), err
}
