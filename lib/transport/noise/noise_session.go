package noise

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	cb "github.com/emirpasic/gods/queues/circularbuffer"
	"github.com/flynn/noise"
	"github.com/samber/oops"
	"github.com/sirupsen/logrus"

	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/transport"
	"github.com/go-i2p/go-i2p/lib/transport/handshake"
	noisehs "github.com/go-i2p/go-i2p/lib/transport/noise/handshake"
)

// NoiseSession represents a Noise protocol session between two I2P routers
// Moved from: session.go
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

// NewNoiseTransportSession creates a new noise transport session with the given router info
// Moved from: session.go
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

// NewNoiseSession creates a new NoiseSession with the given router info
// Moved from: session.go
func NewNoiseSession(ri router_info.RouterInfo) (*NoiseSession, error) {
	ns, err := NewNoiseTransportSession(ri)
	if err != nil {
		return nil, err
	}
	return ns.(*NoiseSession), err
}

// RemoteAddr implements net.Conn
// Moved from: session.go
func (noise_session *NoiseSession) RemoteAddr() net.Addr {
	log.WithField("remote_addr", noise_session.RouterInfo.String()).Debug("Getting RemoteAddr")
	return &noise_session.RouterInfo
}

// LocalAddr returns the local address of the session connection
// Moved from: session.go
func (s *NoiseSession) LocalAddr() net.Addr {
	localAddr := s.Conn.LocalAddr()
	log.WithField("local_addr", localAddr.String()).Debug("Getting LocalAddr")
	return localAddr
}

// SetDeadline implements net.Conn
// Moved from: session.go
func (noise_session *NoiseSession) SetDeadline(t time.Time) error {
	log.WithField("deadline", t).Debug("Setting deadline")
	return noise_session.Conn.SetDeadline(t)
}

// SetReadDeadline implements net.Conn
// Moved from: session.go
func (noise_session *NoiseSession) SetReadDeadline(t time.Time) error {
	log.WithField("read_deadline", t).Debug("Setting read deadline")
	return noise_session.Conn.SetReadDeadline(t)
}

// SetWriteDeadline implements net.Conn
// Moved from: session.go
func (noise_session *NoiseSession) SetWriteDeadline(t time.Time) error {
	log.WithField("write_deadline", t).Debug("Setting write deadline")
	return noise_session.Conn.SetWriteDeadline(t)
}

// Close closes the NoiseSession and cleans up resources
// Moved from: session.go
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

// peerStaticKey is equal to the NTCP2 peer's static public key, found in their router info
// Moved from: session.go
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

// QueueSendI2NP queues an I2NP message for sending
// Moved from: i2np.go
func (s *NoiseSession) QueueSendI2NP(msg i2np.I2NPMessage) {
	s.SendQueue.Enqueue(msg)
}

// SendQueueSize returns the current size of the send queue
// Moved from: i2np.go
func (s *NoiseSession) SendQueueSize() int {
	return s.SendQueue.Size()
}

// ReadNextI2NP reads the next I2NP message from the session
// Moved from: i2np.go
func (s *NoiseSession) ReadNextI2NP() (i2np.I2NPMessage, error) {
	return i2np.I2NPMessage{}, nil
}

// Read implements net.Conn Read method
// Moved from: read_session.go
func (c *NoiseSession) Read(b []byte) (int, error) {
	log.WithField("buffer_length", len(b)).Debug("Starting NoiseSession Read")
	// interlock with Close below
	for {
		x := atomic.LoadInt32(&c.activeCall)
		if x&1 != 0 {
			log.WithFields(logrus.Fields{
				"at":     "(NoiseSession) Read",
				"reason": "session is closed",
			}).Error("session is closed")
			return 0, oops.Errorf("session is closed")
		}
		if atomic.CompareAndSwapInt32(&c.activeCall, x, x+2) {
			defer atomic.AddInt32(&c.activeCall, -2)
			break
		}
		log.Debug("NoiseSession Read: retrying atomic operation")
	}
	if !c.HandshakeComplete() {
		log.Debug("NoiseSession Read: handshake not complete, running incoming handshake")
		if err := c.RunIncomingHandshake(); err != nil {
			log.WithError(err).Error("NoiseSession Read: failed to run incoming handshake")
			return 0, err
		}
	}
	c.Mutex.Lock()
	defer c.Mutex.Unlock()
	if !c.HandshakeComplete() {
		log.Error("NoiseSession Read: internal error - handshake still not complete after running")
		return 0, oops.Errorf("internal error")
	}
	n, err := c.readPacketLocked(b)
	if err != nil {
		log.WithError(err).Error("NoiseSession Read: failed to read packet")
	} else {
		log.WithField("bytes_read", n).Debug("NoiseSession Read: successfully read packet")
	}
	return n, err
}

// Write implements net.Conn Write method
// Moved from: write_session.go
func (c *NoiseSession) Write(b []byte) (int, error) {
	log.WithField("data_length", len(b)).Debug("NoiseSession: Starting Write operation")
	// interlock with Close below
	for {
		x := atomic.LoadInt32(&c.activeCall)
		if x&1 != 0 {
			log.WithFields(logrus.Fields{
				"at":     "(NoiseSession) Write",
				"reason": "session is closed",
			}).Error("session is closed")
			return 0, oops.Errorf("session is closed")
		}
		if atomic.CompareAndSwapInt32(&c.activeCall, x, x+2) {
			defer atomic.AddInt32(&c.activeCall, -2)
			break
		}
		log.Debug("NoiseSession: Write - retrying atomic operation")
	}
	if !c.HandshakeComplete() {
		log.Debug("NoiseSession: Write - handshake not complete, running outgoing handshake")
		if err := c.RunOutgoingHandshake(); err != nil {
			log.WithError(err).Error("NoiseSession: Write - failed to run outgoing handshake")
			return 0, err
		}
	}
	c.Mutex.Lock()
	defer c.Mutex.Unlock()
	if !c.HandshakeComplete() {
		log.Error("NoiseSession: Write - internal error, handshake still not complete")
		return 0, oops.Errorf("internal error")
	}
	n, err := c.writePacketLocked(b)
	if err != nil {
		log.WithError(err).Error("NoiseSession: Write - failed to write packet")
	} else {
		log.WithField("bytes_written", n).Debug("NoiseSession: Write - successfully wrote packet")
	}
	return n, err
}

// decryptPacket decrypts a noise protocol packet
// Moved from: read_session.go
func (c *NoiseSession) decryptPacket(data []byte) (int, []byte, error) {
	log.WithField("data_length", len(data)).Debug("NoiseSession: Starting packet decryption")

	if c.CipherState == nil {
		log.Error("NoiseSession: decryptPacket - readState is nil")
		return 0, nil, oops.Errorf("readState is nil")
	}

	if len(data) < 2 {
		log.Error("NoiseSession: decryptPacket - packet too short")
		return 0, nil, oops.Errorf("packet too short")
	}

	// Extract payload length from prefix
	payloadLen := binary.BigEndian.Uint16(data[:2])
	if len(data[2:]) < int(payloadLen) {
		log.Error("NoiseSession: decryptPacket - incomplete packet")
		return 0, nil, oops.Errorf("incomplete packet")
	}

	// Decrypt payload
	decryptedData, err := c.CipherState.Decrypt(nil, nil, data[2:2+payloadLen])
	if err != nil {
		log.WithError(err).Error("NoiseSession: decryptPacket - failed to decrypt data")
		return 0, nil, oops.Errorf("failed to decrypt: %w", err)
	}

	m := len(decryptedData)
	log.WithFields(logrus.Fields{
		"encrypted_length": payloadLen,
		"decrypted_length": m,
	}).Debug("NoiseSession: decryptPacket - packet decrypted successfully")

	return m, decryptedData, nil
}

// encryptPacket encrypts data into a noise protocol packet
// Moved from: write_session.go
func (c *NoiseSession) encryptPacket(data []byte) (int, []byte, error) {
	log.WithField("data_length", len(data)).Debug("NoiseSession: Starting packet encryption")

	m := len(data)
	if c.CipherState == nil {
		log.Error("NoiseSession: encryptPacket - writeState is nil")
		return 0, nil, oops.Errorf("writeState is nil")
	}

	// Create length prefix first
	lengthPrefix := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthPrefix, uint16(m))

	// Encrypt the data
	encryptedData, err := c.CipherState.Encrypt(nil, nil, data)
	if err != nil {
		log.WithError(err).Error("NoiseSession: encryptPacket - failed to encrypt data")
		return 0, nil, oops.Errorf("failed to encrypt: %w", err)
	}

	// Combine length prefix and encrypted data
	packet := make([]byte, 0, len(lengthPrefix)+len(encryptedData))
	packet = append(packet, lengthPrefix...)
	packet = append(packet, encryptedData...)

	log.WithFields(logrus.Fields{
		"original_length":  m,
		"encrypted_length": len(encryptedData),
		"packet_length":    len(packet),
	}).Debug("NoiseSession: encryptPacket - packet encrypted successfully")

	return m, packet, nil
}

// readPacketLocked reads and decrypts a packet with the session lock held
// Moved from: read_session.go
func (c *NoiseSession) readPacketLocked(data []byte) (int, error) {
	log.WithField("data_length", len(data)).Debug("Starting readPacketLocked")

	var n int
	if len(data) == 0 { // Handle special case where data length is zero during handshake
		log.Debug("readPacketLocked: special case - reading 2 bytes during handshake")
		if _, err := c.Conn.Read(make([]byte, 2)); err != nil {
			log.WithError(err).Error("readPacketLocked: failed to read 2 bytes during handshake")
			return 0, err
		}
	}
	for len(data) > 0 {
		_, b, err := c.decryptPacket(data)
		if err != nil {
			log.WithError(err).Error("readPacketLocked: failed to encrypt packet")
			return 0, err
		}
		bytesRead, err := c.Conn.Read(b)
		if err != nil {
			log.WithError(err).WithField("bytes_read", bytesRead).Error("readPacketLocked: failed to read from connection")
			return bytesRead, err
		}
		n += bytesRead
		data = data[bytesRead:]
		log.WithFields(logrus.Fields{
			"bytes_read":     n,
			"remaining_data": len(data),
		}).Debug("readPacketLocked: read packet chunk")
	}
	return n, nil
}

// writePacketLocked encrypts and writes a packet with the session lock held
// Moved from: write_session.go
func (c *NoiseSession) writePacketLocked(data []byte) (int, error) {
	log.WithField("data_length", len(data)).Debug("NoiseSession: Starting writePacketLocked")

	var n int
	if len(data) == 0 { // special case to answer when everything is ok during handshake
		log.Debug("NoiseSession: writePacketLocked - special case, writing 2 empty bytes")
		if _, err := c.Conn.Write(make([]byte, 2)); err != nil {
			log.WithError(err).Error("NoiseSession: writePacketLocked - failed to write empty bytes")
			return 0, err
		}
	}
	for len(data) > 0 {
		m, b, err := c.encryptPacket(data)
		if err != nil {
			log.WithError(err).Error("NoiseSession: writePacketLocked - failed to encrypt packet")
			return 0, err
		}
		if n, err := c.Conn.Write(b); err != nil {
			log.WithError(err).WithField("bytes_written", n).Error("NoiseSession: writePacketLocked - failed to write to connection")
			return n, err
		} else {
			n += m
			data = data[m:]
			log.WithFields(logrus.Fields{
				"bytes_written":  n,
				"remaining_data": len(data),
			}).Debug("NoiseSession: writePacketLocked - wrote packet chunk")
		}
	}

	log.WithField("total_bytes_written", n).Debug("NoiseSession: writePacketLocked - completed writing all packets")
	return n, nil
}

// RunOutgoingHandshake performs the outgoing handshake for the session
// Moved from: outgoing_handshake.go
func (c *NoiseSession) RunOutgoingHandshake() error {
	log.Debug("Starting outgoing handshake")

	negData, msg, state, err := c.ComposeInitiatorHandshakeMessage(nil, nil)
	if err != nil {
		log.WithError(err).Error("Failed to compose initiator handshake message")
		return err
	}
	log.WithFields(logrus.Fields{
		"negData_length": len(negData),
		"msg_length":     len(msg),
	}).Debug("Initiator handshake message composed")
	c.HandshakeState = &noisehs.NoiseHandshakeState{
		HandshakeState: state,
	}

	if _, err = c.Write(negData); err != nil {
		log.WithError(err).Error("Failed to write negotiation data")
		return err
	}
	log.Debug("Negotiation data written successfully")

	if _, err = c.Write(msg); err != nil {
		log.WithError(err).Error("Failed to write handshake message")
		return err
	}
	log.Debug("Handshake message written successfully")
	log.WithField("state", state).Debug("Handshake state after message write")
	log.Println(state)
	c.CompleteHandshake()
	log.Debug("Outgoing handshake completed successfully")
	return nil
}

// RunIncomingHandshake performs the incoming handshake for the session
// Moved from: incoming_handshake.go
func (c *NoiseSession) RunIncomingHandshake() error {
	log.Debug("Starting incoming handshake")

	negData, msg, state, err := c.ComposeReceiverHandshakeMessage(*c.HandshakeKey(), nil, nil, nil)
	if err != nil {
		log.WithError(err).Error("Failed to compose receiver handshake message")
		return err
	}
	c.HandshakeState = &noisehs.NoiseHandshakeState{
		HandshakeState: state,
	}
	log.WithFields(logrus.Fields{
		"negData_length": len(negData),
		"msg_length":     len(msg),
	}).Debug("Receiver handshake message composed")
	if _, err = c.Write(negData); err != nil {
		log.WithError(err).Error("Failed to write negotiation data")
		return err
	}
	log.Debug("Negotiation data written successfully")
	if _, err = c.Write(msg); err != nil {
		log.WithError(err).Error("Failed to write handshake message")
		return err
	}
	log.Debug("Handshake message written successfully")
	log.WithField("state", state).Debug("Handshake state after message write")
	log.Println(state)
	c.CompleteHandshake()
	log.Debug("Incoming handshake completed successfully")
	return nil
}

// ComposeInitiatorHandshakeMessage composes the initiator handshake message
// Moved from: outgoing_handshake.go
func (c *NoiseSession) ComposeInitiatorHandshakeMessage(
	payload []byte,
	ephemeralPrivate []byte,
) (
	negotiationData,
	handshakeMessage []byte,
	handshakeState *noise.HandshakeState,
	err error,
) {
	log.Debug("Starting ComposeInitiatorHandshakeMessage")

	remoteStatic, err := c.peerStaticKey()
	if err != nil {
		return nil, nil, nil, oops.Errorf("Peer static key retrieval error: %s", err)
	}

	localStaticDH := *c.HandshakeKey()

	if len(remoteStatic) != 0 && len(remoteStatic) != noise.DH25519.DHLen() {
		return nil, nil, nil, oops.Errorf("only 32 byte curve25519 public keys are supported")
	}

	negotiationData = make([]byte, 6)
	copy(negotiationData, initNegotiationData(nil))
	pattern := noise.HandshakeXK
	negotiationData[5] = NOISE_PATTERN_XK

	var random io.Reader
	if len(ephemeralPrivate) == 0 {
		random = rand.Reader
	} else {
		random = bytes.NewBuffer(ephemeralPrivate)
	}

	config := noise.Config{
		CipherSuite:   noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256),
		Pattern:       pattern,
		Initiator:     true,
		StaticKeypair: localStaticDH,
		Random:        random,
	}

	handshakeState, err = noise.NewHandshakeState(config)
	if err != nil {
		return nil, nil, nil, err
	}

	// Write message, expecting no CipherStates yet since this is message 1
	handshakeMessage, cs0, cs1, err := handshakeState.WriteMessage(nil, payload)
	if err != nil {
		return nil, nil, nil, err
	}

	// Verify no CipherStates are returned yet
	if cs0 != nil || cs1 != nil {
		return nil, nil, nil, oops.Errorf("unexpected cipher states in message 1")
	}

	return negotiationData, handshakeMessage, handshakeState, nil
}

// ComposeReceiverHandshakeMessage composes the receiver handshake message
// Moved from: incoming_handshake.go
func (c *NoiseSession) ComposeReceiverHandshakeMessage(localStatic noise.DHKey, remoteStatic []byte, payload []byte, ephemeralPrivate []byte) (negData, msg []byte, state *noise.HandshakeState, err error) {
	log.Debug("Starting ComposeReceiverHandshakeMessage")

	if len(remoteStatic) != 0 && len(remoteStatic) != noise.DH25519.DHLen() {
		log.WithField("rs_length", len(remoteStatic)).Error("Invalid remote static key length")
		return nil, nil, nil, oops.Errorf("only 32 byte curve25519 public keys are supported")
	}

	negData = make([]byte, 6)
	copy(negData, initNegotiationData(nil))
	pattern := noise.HandshakeXK
	negData[5] = NOISE_PATTERN_XK

	var random io.Reader
	if len(ephemeralPrivate) == 0 {
		random = rand.Reader
		log.Debug("Using crypto/rand as random source")
	} else {
		random = bytes.NewBuffer(ephemeralPrivate)
	}

	config := noise.Config{
		CipherSuite:   noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256),
		Pattern:       pattern,
		Initiator:     false,
		StaticKeypair: localStatic,
		Random:        random,
	}

	state, err = noise.NewHandshakeState(config)
	if err != nil {
		return nil, nil, nil, err
	}

	// Write message 2, expecting no CipherStates yet
	msg, cs0, cs1, err := state.WriteMessage(nil, payload)
	if err != nil {
		return nil, nil, nil, err
	}

	// Verify no CipherStates are returned yet
	if cs0 != nil || cs1 != nil {
		return nil, nil, nil, oops.Errorf("unexpected cipher states in message 2")
	}

	return negData, msg, state, nil
}
