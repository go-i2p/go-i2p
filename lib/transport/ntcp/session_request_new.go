package ntcp

import (
	"crypto/rand"
	"io"
	"math/big"
	"net"

	"github.com/go-i2p/go-i2p/lib/common/data"
	"github.com/go-i2p/go-i2p/lib/crypto/curve25519"
	"github.com/go-i2p/go-i2p/lib/transport/ntcp/handshake"
	"github.com/go-i2p/go-i2p/lib/transport/ntcp/messages"
	_ "github.com/go-i2p/logger"
	"github.com/samber/oops"
)

/*
SessionRequestProcessor implements NTCP2 Message 1 (SessionRequest):
1. Create session request message with options block (version, padding length, etc.)
2. Set timeout deadline for the connection
3. Obfuscate ephemeral key (X) using AES with Bob's router hash as key
4. Encrypt options block using ChaCha20-Poly1305
5. Assemble final message: obfuscated X + encrypted options + padding
6. Write complete message to connection

SessionRequestProcessor processes incoming NTCP2 Message 1 (SessionRequest):
1. Read and buffer the fixed-length ephemeral key portion (X)
2. Deobfuscate X using AES with local router hash as key
3. Validate the ephemeral key (X) is a valid Curve25519 point
4. Read the ChaCha20-Poly1305 encrypted options block
5. Derive KDF for handshake message 1 using X and local static key
6. Decrypt and authenticate the options block
7. Extract and validate handshake parameters (timestamp, version, padding length)
8. Read and validate any padding bytes
9. Check timestamp for acceptable clock skew (±60 seconds?)
*/
type SessionRequestProcessor struct {
	*NTCP2Session
}

// EncryptPayload encrypts the payload portion of the message
func (p *SessionRequestProcessor) EncryptPayload(
	message messages.Message,
	obfuscatedKey []byte,
	hs *handshake.HandshakeState,
) ([]byte, error) {
	req, ok := message.(*messages.SessionRequest)
	if !ok {
		return nil, oops.Errorf("expected SessionRequest message, got %T", message)
	}

	// Use the central AEAD operation instead of custom encryption
	// The key material would be derived in this case
	return p.NTCP2Session.EncryptWithDerivedKey(
		hs.LocalEphemeral.Bytes(),
		req.Options.Data(),
		obfuscatedKey, // Using obfuscated key as associated data
		0,             // First message uses nonce counter 0
	)
}

// MessageType implements handshake.HandshakeMessageProcessor.
func (s *SessionRequestProcessor) MessageType() messages.MessageType {
	return messages.MessageTypeSessionRequest
}

// ProcessMessage implements handshake.HandshakeMessageProcessor.
func (s *SessionRequestProcessor) ProcessMessage(message messages.Message, hs *handshake.HandshakeState) error {
	req, ok := message.(*messages.SessionRequest)
	if !ok {
		return oops.Errorf("expected SessionRequest message, got %T", message)
	}

	// Validate timestamp using existing method
	if err := s.NTCP2Session.ValidateTimestamp(req.Options.Timestamp.Time()); err != nil {
		return err
	}

	// Store padding length for message 3 if provided
	if req.Options.PaddingLength != nil {
		paddingLen := req.Options.PaddingLength.Int()
		hs.RemotePaddingLen = paddingLen
	}

	// Store message 3 part 2 length if provided
	if req.Options.Message3Part2Length != nil {
		hs.Message3Length = req.Options.Message3Part2Length.Int()
	}

	return nil
}

// ReadMessage reads a SessionRequest message from the connection
func (p *SessionRequestProcessor) ReadMessage(conn net.Conn, hs *handshake.HandshakeState) (messages.Message, error) {
	// 1. Read ephemeral key
	obfuscatedX, err := p.NTCP2Session.ReadEphemeralKey(conn)
	if err != nil {
		return nil, oops.Errorf("failed to read ephemeral key: %w", err)
	}

	// 2. Process ephemeral key
	deobfuscatedX, err := p.NTCP2Session.ProcessEphemeralKey(obfuscatedX, hs)
	if err != nil {
		return nil, oops.Errorf("failed to process ephemeral key: %w", err)
	}

	// 3. Read options block
	encryptedOptions, err := p.readOptionsBlock(conn)
	if err != nil {
		return nil, oops.Errorf("failed to read options block: %w", err)
	}

	// 4. Process options block
	options, err := p.processOptionsBlock(encryptedOptions, obfuscatedX, deobfuscatedX, hs)
	if err != nil {
		return nil, oops.Errorf("failed to process options block: %w", err)
	}

	// 5. Read padding if present
	paddingLen := options.PaddingLength.Int()
	if paddingLen > 0 {
		if err := p.NTCP2Session.ReadAndValidatePadding(conn, paddingLen); err != nil {
			return nil, oops.Errorf("failed to read and validate padding: %w", err)
		}
	}

	// Construct the full message
	return &messages.SessionRequest{
		XContent: [32]byte{}, // We've already processed this
		Options:  *options,
		Padding:  make([]byte, paddingLen), // Padding content doesn't matter after validation
	}, nil
}

// CreateMessage implements HandshakeMessageProcessor.
func (s *SessionRequestProcessor) CreateMessage(hs *handshake.HandshakeState) (messages.Message, error) {
	// Get our ephemeral key pair
	ephemeralKey := make([]byte, 32)
	if _, err := rand.Read(ephemeralKey); err != nil {
		return nil, oops.Errorf("failed to generate ephemeral key: %w", err)
	}

	// Add random padding (implementation specific)
	randomInt, err := rand.Int(rand.Reader, big.NewInt(16))
	if err != nil {
		return nil, oops.Errorf("failed to generate random padding length: %w", err)
	}

	padding := make([]byte, randomInt.Int64()) // Up to 16 bytes of padding
	if err != nil {
		return nil, oops.Errorf("failed to generate random padding: %w", err)
	}

	netId, err := data.NewIntegerFromInt(2, 1)
	if err != nil {
		return nil, oops.Errorf("failed to parse network ID: %w", err)
	}
	version, err := data.NewIntegerFromInt(2, 1)
	if err != nil {
		return nil, oops.Errorf("failed to parse protocol version: %w", err)
	}
	paddingLen, _, err := data.NewInteger([]byte{byte(len(padding))}, 1)
	if err != nil {
		return nil, oops.Errorf("failed to parse padding length: %w", err)
	}
	//message3Part2Len, err := data.NewInteger()
	//if err != nil {
	//	return nil, err
	//}
	timestamp, err := data.DateFromTime(s.GetCurrentTime())
	if err != nil {
		return nil, oops.Errorf("failed to get current time: %w", err)
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

// GetPadding retrieves padding from a message
func (p *SessionRequestProcessor) GetPadding(message messages.Message) []byte {
	req, ok := message.(*messages.SessionRequest)
	if !ok {
		return nil
	}

	return req.Padding
}

// ObfuscateKey obfuscates the ephemeral key for transmission
func (p *SessionRequestProcessor) ObfuscateKey(message messages.Message, hs *handshake.HandshakeState) ([]byte, error) {
	req, ok := message.(*messages.SessionRequest)
	if !ok {
		return nil, oops.Errorf("expected SessionRequest message")
	}

	// Store the ephemeral key in the handshake state for reuse
	hs.LocalEphemeral = curve25519.Curve25519PrivateKey(req.XContent[:])

	return p.NTCP2Session.ObfuscateEphemeral(req.XContent[:])
}

// processOptionsBlock decrypts and processes the options block from the session request
func (p *SessionRequestProcessor) processOptionsBlock(
	encryptedOptions []byte,
	obfuscatedX []byte,
	deobfuscatedX []byte,
	hs *handshake.HandshakeState,
) (*messages.RequestOptions, error) {
	// Decrypt options block
	decryptedOptions, err := p.NTCP2Session.DecryptOptionsBlock(encryptedOptions, obfuscatedX, deobfuscatedX)
	if err != nil {
		p.AddDelayForSecurity()
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
	if err := p.ValidateTimestamp(timestamp.Time()); err != nil {
		return nil, err
	}

	// Update handshake state
	timestampVal := timestamp.Time()
	hs.Timestamp = uint32(timestampVal.Unix())

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

var _ handshake.HandshakeMessageProcessor = (*SessionRequestProcessor)(nil)

// readOptionsBlock reads the encrypted options block from the connection
func (c *SessionRequestProcessor) readOptionsBlock(conn net.Conn) ([]byte, error) {
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
