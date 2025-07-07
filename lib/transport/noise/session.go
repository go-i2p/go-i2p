package noise

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	cb "github.com/emirpasic/gods/queues/circularbuffer"
	"github.com/flynn/noise"
	"github.com/samber/oops"

	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/transport"
	"github.com/go-i2p/go-i2p/lib/transport/handshake"
)

type NoiseSession struct {
	router_info.RouterInfo
	handshake.HandshakeState

	*noise.CipherState
	*sync.Cond
	*NoiseTransport // The parent transport, which "Dialed" the connection to the peer with whom we established the session

	sendCipherState *noise.CipherState
	recvCipherState *noise.CipherState

	RecvQueue      *cb.Queue
	SendQueue      *cb.Queue
	VerifyCallback VerifyCallbackFunc
	activeCall     int32
	mutex          sync.Mutex
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
	return localAddr
}

func (s *NoiseSession) Close() error {
	log.Debug("Closing NoiseSession")

	// Set the closed flag for atomic interlocking with Write
	atomic.StoreInt32(&s.activeCall, 1)

	// Clear the queues
	s.SendQueue.Clear()
	s.RecvQueue.Clear()
	log.Debug("SendQueue and RecvQueue cleared")

	// Close the underlying TCP connection
	var err error
	if s.Conn != nil {
		err = s.Conn.Close()
		if err != nil {
			log.WithError(err).Warn("Error closing underlying connection")
		} else {
			log.Debug("Underlying connection closed successfully")
		}
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
	return [32]byte{}, oops.Errorf("Remote static key error")
}

type VerifyCallbackFunc func(publicKey []byte, data []byte) error

func NewNoiseTransportSession(ri router_info.RouterInfo) (transport.TransportSession, error) {
	log.WithField("router_info", ri.String()).Debug("Creating new NoiseTransportSession")

	addresses := ri.RouterAddresses()
	for i, addr := range addresses {
		log.WithField("address", string(addr.Bytes())).Debug("Attempting to dial")
		socket, err := net.Dial("tcp", string(addr.Bytes()))
		if err != nil {
			log.WithError(err).Error("Failed to dial address")
			// Only return error if this is the last address to try
			if i == len(addresses)-1 {
				log.Error("Failed to create NoiseTransportSession, all addresses failed")
				return nil, oops.Errorf("Transport constructor error")
			}
			continue
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

	// If we get here, it means there were no addresses to try
	log.Error("No addresses available to create NoiseTransportSession")
	return nil, oops.Errorf("No router addresses available")
}

func NewNoiseSession(ri router_info.RouterInfo) (*NoiseSession, error) {
	ns, err := NewNoiseTransportSession(ri)
	if err != nil {
		return nil, err
	}
	return ns.(*NoiseSession), err
}
