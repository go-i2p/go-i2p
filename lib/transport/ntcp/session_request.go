package ntcp

import (
	"crypto/rand"
	"io"
	"math/big"
	mrand "math/rand"
	"net"
	"time"

	"github.com/go-i2p/go-i2p/lib/common/data"
	"github.com/go-i2p/go-i2p/lib/crypto/curve25519"
	"github.com/go-i2p/go-i2p/lib/transport/ntcp/messages"
	"github.com/samber/oops"
)

func (s *NTCP2Session) CreateSessionRequest() (*messages.SessionRequest, error) {
	// Get our ephemeral key pair
	ephemeralKey := make([]byte, 32)
	if _, err := rand.Read(ephemeralKey); err != nil {
		return nil, err
	}

	// Add random padding (implementation specific)
	randomInt, err := rand.Int(rand.Reader, big.NewInt(16))
	if err != nil {
		return nil, err
	}

	padding := make([]byte, randomInt.Int64()) // Up to 16 bytes of padding
	if err != nil {
		return nil, err
	}

	netId, err := data.NewIntegerFromInt(2, 1)
	if err != nil {
		return nil, err
	}
	version, err := data.NewIntegerFromInt(2, 1)
	if err != nil {
		return nil, err
	}
	paddingLen, _, err := data.NewInteger([]byte{byte(len(padding))}, 1)
	if err != nil {
		return nil, err
	}
	//message3Part2Len, err := data.NewInteger()
	//if err != nil {
	//	return nil, err
	//}
	timestamp, err := data.DateFromTime(s.GetCurrentTime())
	if err != nil {
		return nil, err
	}
	requestOptions := &messages.RequestOptions{
		NetworkID:       netId,
		ProtocolVersion: version,
		PaddingLength:   paddingLen,
		// Message3Part2Length: ,
		Timestamp: timestamp,
	}

	return &messages.SessionRequest{
		XContent: [32]byte(ephemeralKey),
		Options:  *requestOptions,
		Padding:  padding,
	}, nil
}

// sendSessionRequest sends Message 1 (SessionRequest) to the remote peer
func (c *NTCP2Session) sendSessionRequest(conn net.Conn, hs *HandshakeState) error {
	// Implement according to NTCP2 spec
	// 1. Create and send X (ephemeral key) | Padding
	// uses CreateSessionRequest from session_request.go
	sessionRequestMessage, err := c.CreateSessionRequest()
	if err != nil {
		return oops.Errorf("failed to create session request: %v", err)
	}
	// 2. Set deadline for the connection
	if err := conn.SetDeadline(time.Now().Add(NTCP2_HANDSHAKE_TIMEOUT)); err != nil {
		return oops.Errorf("failed to set deadline: %v", err)
	}
	// 3. Obfuscate the session request message
	obfuscatedX, err := c.ObfuscateEphemeral(sessionRequestMessage.XContent[:])
	if err != nil {
		return oops.Errorf("failed to obfuscate ephemeral key: %v", err)
	}
	// 4. ChaChaPoly Frame
	// Encrypt options block and authenticate both options and padding
	ciphertext, err := c.encryptSessionRequestOptions(sessionRequestMessage, obfuscatedX)
	if err != nil {
		return err
	}

	// Combine all components into final message
	// 1. Obfuscated X (already in obfuscatedX)
	// 2. ChaCha20-Poly1305 encrypted options with auth tag
	// 3. Authenticated but unencrypted padding
	message := append(obfuscatedX, ciphertext...)
	message = append(message, sessionRequestMessage.Padding...)

	// 5. Write the message to the connection
	if _, err := conn.Write(message); err != nil {
		return oops.Errorf("failed to send session request: %v", err)
	}
	return nil
}

// receiveSessionRequest processes Message 1 (SessionRequest) from remote
func (c *NTCP2Session) receiveSessionRequest(conn net.Conn, hs *HandshakeState) error {
	log.Debugf("NTCP2: Processing incoming SessionRequest message")

	// Read the ephemeral key (X)
	ephemeralKey, err := c.readEphemeralKey(conn)
	if err != nil {
		return err
	}

	// Process the ephemeral key
	deobfuscatedX, err := c.processEphemeralKey(ephemeralKey, hs)
	if err != nil {
		return err
	}

	// Read and decrypt the options block
	optionsBlock, err := c.readOptionsBlock(conn)
	if err != nil {
		return err
	}

	// Process the options block
	requestOptions, err := c.processOptionsBlock(optionsBlock, ephemeralKey, deobfuscatedX, hs)
	if err != nil {
		return err
	}

	// Read and validate padding if present
	if requestOptions.PaddingLength.Int() > 0 {
		if err := c.readAndValidatePadding(conn, requestOptions.PaddingLength.Int()); err != nil {
			return err
		}
	}

	log.Debugf("NTCP2: SessionRequest processed successfully")
	return nil
}

// readEphemeralKey reads the ephemeral key (X) from the connection
func (c *NTCP2Session) readEphemeralKey(conn net.Conn) ([]byte, error) {
	ephemeralKey := make([]byte, 32)
	if _, err := io.ReadFull(conn, ephemeralKey); err != nil {
		if err == io.ErrUnexpectedEOF {
			return nil, oops.Errorf("incomplete ephemeral key: connection closed prematurely")
		}
		return nil, oops.Errorf("failed to read ephemeral key: %w", err)
	}
	return ephemeralKey, nil
}

// processEphemeralKey deobfuscates and validates the ephemeral key
func (c *NTCP2Session) processEphemeralKey(obfuscatedX []byte, hs *HandshakeState) ([]byte, error) {
	deobfuscatedX, err := c.DeobfuscateEphemeral(obfuscatedX)
	if err != nil {
		c.addDelayForSecurity()
		return nil, oops.Errorf("failed to deobfuscate ephemeral key: %w", err)
	}

	// Validate key for curve25519 (MSB must be cleared)
	if deobfuscatedX[31]&0x80 != 0 {
		log.Warnf("NTCP2: Rejecting SessionRequest - invalid ephemeral key format")
		c.addDelayForSecurity()
		return nil, oops.Errorf("invalid ephemeral key format")
	}

	// Store in handshake state
	pubKey := curve25519.Curve25519PublicKey(deobfuscatedX)
	hs.remoteEphemeral = pubKey

	return deobfuscatedX, nil
}

// readOptionsBlock reads the encrypted options block from the connection
func (c *NTCP2Session) readOptionsBlock(conn net.Conn) ([]byte, error) {
	// Options block with auth tag is 16 bytes minimum
	optionsBlock := make([]byte, 16)
	if _, err := io.ReadFull(conn, optionsBlock); err != nil {
		if err == io.ErrUnexpectedEOF {
			return nil, oops.Errorf("incomplete options block: connection closed prematurely")
		}
		return nil, oops.Errorf("failed to read options block: %w", err)
	}
	return optionsBlock, nil
}

// processOptionsBlock decrypts and processes the options block
func (c *NTCP2Session) processOptionsBlock(
	encryptedOptions []byte,
	obfuscatedX []byte,
	deobfuscatedX []byte,
	hs *HandshakeState,
) (*messages.RequestOptions, error) {
	// Decrypt options block
	decryptedOptions, err := c.DecryptOptionsBlock(encryptedOptions, obfuscatedX, deobfuscatedX)
	if err != nil {
		c.addDelayForSecurity()
		return nil, oops.Errorf("failed to decrypt options block: %w", err)
	}

	// Minimum size for valid options
	if len(decryptedOptions) < 9 {
		return nil, oops.Errorf("options block too small: %d bytes", len(decryptedOptions))
	}

	// Parse network ID
	networkID, _, err := data.NewInteger([]byte{decryptedOptions[0]}, 1)
	if err != nil {
		return nil, oops.Errorf("failed to parse network ID: %w", err)
	}

	if networkID.Int() != 2 {
		return nil, oops.Errorf("invalid network ID: %d", networkID.Int())
	}

	// Parse protocol version
	protocolVersion, _, err := data.NewInteger([]byte{decryptedOptions[1]}, 1)
	if err != nil {
		return nil, oops.Errorf("failed to parse protocol version: %w", err)
	}

	if protocolVersion.Int() != 2 {
		return nil, oops.Errorf("unsupported protocol version: %d", protocolVersion.Int())
	}

	// Parse padding length
	paddingLength, _, err := data.NewInteger([]byte{decryptedOptions[2]}, 1)
	if err != nil {
		return nil, oops.Errorf("failed to parse padding length: %w", err)
	}

	// Parse message 3 part 2 length (2 bytes)
	msg3p2Len, _, err := data.NewInteger(decryptedOptions[3:5], 2)
	if err != nil {
		return nil, oops.Errorf("failed to parse message 3 part 2 length: %w", err)
	}

	// Parse timestamp (4 bytes)
	timestamp, _, err := data.NewDate(decryptedOptions[5:9])
	if err != nil {
		return nil, oops.Errorf("failed to parse timestamp: %w", err)
	}

	// Validate timestamp
	if err := c.validateTimestamp(*timestamp); err != nil {
		return nil, err
	}

	// Update handshake state
	timestampVal := timestamp.Time()
	hs.timestamp = uint32(timestampVal.Unix())

	// Construct the RequestOptions object
	requestOptions := &messages.RequestOptions{
		NetworkID:           networkID,
		ProtocolVersion:     protocolVersion,
		PaddingLength:       paddingLength,
		Message3Part2Length: msg3p2Len,
		Timestamp:           timestamp,
	}

	return requestOptions, nil
}

// validateTimestamp checks if the timestamp is within acceptable range
func (c *NTCP2Session) validateTimestamp(timestamp data.Date) error {
	timestampTime := timestamp.Time()

	now := c.GetCurrentTime()
	diff := now.Sub(timestampTime)

	// Allow ±60 seconds clock skew
	if diff < -60*time.Second || diff > 60*time.Second {
		log.Warnf("NTCP2: Rejecting SessionRequest - clock skew too large: %v", diff)
		return oops.Errorf("clock skew too large: %v", diff)
	}

	return nil
}

// readAndValidatePadding reads the padding from the connection
func (c *NTCP2Session) readAndValidatePadding(conn net.Conn, paddingLen int) error {
	// Check reasonable padding size to prevent DoS
	if paddingLen > 64 {
		return oops.Errorf("excessive padding size: %d bytes", paddingLen)
	}

	padding := make([]byte, paddingLen)
	n, err := io.ReadFull(conn, padding)
	if err != nil {
		if err == io.ErrUnexpectedEOF {
			return oops.Errorf("incomplete padding: got %d bytes, expected %d", n, paddingLen)
		}
		return oops.Errorf("failed to read padding: %w", err)
	}

	// No need to validate padding content - it's random data
	return nil
}

// addDelayForSecurity adds a small random delay to resist probing
func (c *NTCP2Session) addDelayForSecurity() {
	// Sleep between 50-250ms to make timing attacks harder
	delay := time.Duration(50+mrand.Intn(200)) * time.Millisecond
	time.Sleep(delay)
}
