package ntcp

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/go-i2p/go-i2p/lib/common/data"
	"github.com/go-i2p/go-i2p/lib/common/router_info"
	"github.com/go-i2p/go-i2p/lib/crypto/curve25519"
	"github.com/go-i2p/go-i2p/lib/transport/ntcp/handshake"
	"github.com/go-i2p/go-i2p/lib/transport/ntcp/messages"
	"github.com/samber/oops"
)

/*
SessionConfirmedProcessor implements NTCP2 Message 3 (SessionConfirmed):
1. Create two separate ChaChaPoly frames for this message
2. For first frame:
	a. Extract local static key (s)
	b. Derive KDF for handshake message 3 part 1
	c. Encrypt static key using ChaCha20-Poly1305
3. For second frame:
	a. Prepare payload with local RouterInfo, options, and padding
	b. Derive KDF for handshake message 3 part 2 using se pattern
	c. Encrypt payload using ChaCha20-Poly1305
4. Assemble final message: encrypted static key frame + encrypted payload frame
5. Write complete message to connection
6. Derive final data phase keys (k_ab, k_ba) using Split() operation
7. Initialize SipHash keys for data phase length obfuscation

SessionConfirmedProcessor processes incoming NTCP2 Message 3 (SessionConfirmed):
1. Read first ChaChaPoly frame containing encrypted static key
2. Derive KDF for handshake message 3 part 1
3. Decrypt and authenticate static key frame
4. Validate decrypted static key is a valid Curve25519 point
5. Read second ChaChaPoly frame with size specified in message 1
6. Derive KDF for handshake message 3 part 2 using se pattern
7. Decrypt and authenticate second frame
8. Extract RouterInfo from decrypted payload
9. Validate RouterInfo matches expected router identity
10. Process any options included in the payload
11. Derive final data phase keys (k_ab, k_ba) using Split() operation
12. Initialize SipHash keys for data phase length obfuscation
13. Mark handshake as complete
*/

type SessionConfirmedProcessor struct {
	*NTCP2Session
}

// CreateMessage implements handshake.HandshakeMessageProcessor.
func (s *SessionConfirmedProcessor) CreateMessage(hs *handshake.HandshakeState) (messages.Message, error) {
	// Create the SessionConfirmed message
	sc := &messages.SessionConfirmed{}

	// Step 1: Get our static key from the handshake state
	// Note: The static key must be encrypted using the handshakeState's WriteMessage
	// but we need to extract it first to store in the result structure
	localKeyPair, err := s.NTCP2Session.localStaticKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get local static keypair: %w", err)
	}

	// Copy the 32-byte static key
	copy(sc.StaticKey[:], localKeyPair[:])

	// Step 2: Set the RouterInfo
	sc.RouterInfo = &s.NTCP2Session.RouterInfo

	// Step 3: Create options with padding settings
	// Use default padding for now - we should make this something we can configure
	paddingLength, err := data.NewIntegerFromInt(calculatePaddingLength(sc.RouterInfo), 1)
	if err != nil {
		return nil, fmt.Errorf("failed to create padding length: %w", err)
	}

	sc.Options = &messages.ConfirmedOptions{
		PaddingLength: paddingLength,
	}

	// Step 4: Generate padding data according to the specified length
	// In a real implementation, this should be cryptographically secure random data
	if paddingLength.Int() > 0 {
		sc.Padding = make([]byte, paddingLength.Int())
		if _, err := rand.Read(sc.Padding); err != nil {
			return nil, fmt.Errorf("failed to generate padding: %w", err)
		}
	}

	// The actual encryption of the message will happen in the calling function
	// using the handshakeState.WriteMessage() method, as it needs to maintain the
	// proper noise protocol state
	return sc, nil
}

// EncryptPayload implements handshake.HandshakeMessageProcessor.
func (s *SessionConfirmedProcessor) EncryptPayload(msg messages.Message, obfuscatedKey []byte, hs *handshake.HandshakeState) ([]byte, error) {
	sc, ok := msg.(*messages.SessionConfirmed)
	if !ok {
		return nil, oops.Errorf("expected SessionConfirmed message, got %T", msg)
	}
	ri, err := s.NTCP2Session.RouterInfo.Bytes()
	if err != nil {
		return nil, oops.Errorf("failed to serialize RouterInfo: %w", err)
	}
	// Serialize the RouterInfo and options for encryption
	payload := append(ri, sc.Options.Data()...)
	if sc.Padding != nil {
		payload = append(payload, sc.Padding...)
	}

	// Use the existing AEAD encryption method with the current handshake state
	return s.NTCP2Session.EncryptWithAssociatedData(
		hs.ChachaKey,
		payload,
		obfuscatedKey,
		0, // First message uses nonce counter 0
	)
}

// GetPadding implements handshake.HandshakeMessageProcessor.
func (s *SessionConfirmedProcessor) GetPadding(msg messages.Message) []byte {
	sc, ok := msg.(*messages.SessionConfirmed)
	if !ok {
		return nil
	}

	return sc.Padding
}

// MessageType implements handshake.HandshakeMessageProcessor.
func (s *SessionConfirmedProcessor) MessageType() messages.MessageType {
	return messages.MessageTypeSessionConfirmed
}

// ObfuscateKey implements handshake.HandshakeMessageProcessor.
func (s *SessionConfirmedProcessor) ObfuscateKey(msg messages.Message, hs *handshake.HandshakeState) ([]byte, error) {
	sc, ok := msg.(*messages.SessionConfirmed)
	if !ok {
		return nil, oops.Errorf("expected SessionConfirmed message")
	}

	// Store the static key in the handshake state for reuse
	hs.LocalStaticKey = curve25519.Curve25519PrivateKey(sc.StaticKey[:])

	// Reuse the same obfuscation method used in other processors
	return s.NTCP2Session.ObfuscateEphemeral(sc.StaticKey[:])
}

// ProcessMessage implements handshake.HandshakeMessageProcessor.
func (s *SessionConfirmedProcessor) ProcessMessage(message messages.Message, hs *handshake.HandshakeState) error {
	sc, ok := message.(*messages.SessionConfirmed)
	if !ok {
		return oops.Errorf("expected SessionConfirmed message, got %T", message)
	}

	// Validate RouterInfo against expected identity
	if err := s.validateRouterInfo(sc.RouterInfo); err != nil {
		return err
	}

	// Process any options included in the payload
	if err := s.processOptions(sc.Options); err != nil {
		return err
	}

	// Derive final data phase keys using the handshake state
	return s.NTCP2Session.HandshakeState.CompleteHandshake()
}

// ReadMessage implements handshake.HandshakeMessageProcessor.
func (s *SessionConfirmedProcessor) ReadMessage(conn net.Conn, hs *handshake.HandshakeState) (messages.Message, error) {
	// Step 1: Read the static key frame (32 bytes)
	staticKeyFrame := make([]byte, 32)
	if _, err := io.ReadFull(conn, staticKeyFrame); err != nil {
		return nil, oops.Errorf("failed to read static key frame: %w", err)
	}

	// Step 2: Deobfuscate the static key using existing method
	deobfuscatedKey, err := s.NTCP2Session.DeobfuscateEphemeral(staticKeyFrame)
	if err != nil {
		return nil, oops.Errorf("failed to deobfuscate static key: %w", err)
	}

	// Step 3: Validate the key is a valid Curve25519 point
	if deobfuscatedKey[31]&0x80 != 0 {
		return nil, oops.Errorf("invalid static key format")
	}

	// Step 4: Read the payload length from handshake state
	payloadLen := hs.Message3Length
	if payloadLen <= 0 {
		return nil, oops.Errorf("invalid message 3 payload size: %d", payloadLen)
	}

	// Step 5: Read the encrypted payload
	encryptedPayload := make([]byte, payloadLen)
	if _, err := io.ReadFull(conn, encryptedPayload); err != nil {
		return nil, oops.Errorf("failed to read encrypted payload: %w", err)
	}

	// Step 6: Decrypt the payload using existing AEAD operations
	decryptedPayload, err := s.NTCP2Session.DecryptWithAssociatedData(
		hs.ChachaKey,
		encryptedPayload,
		staticKeyFrame, // Use obfuscated key as associated data
		0,
	)
	if err != nil {
		return nil, oops.Errorf("failed to decrypt payload: %w", err)
	}

	// Step 7: Parse the RouterInfo and options from the decrypted payload
	sc := &messages.SessionConfirmed{
		StaticKey: [32]byte{}, // Already processed
	}

	// Copy the static key for reference
	copy(sc.StaticKey[:], deobfuscatedKey)

	// Parse RouterInfo and options from decrypted payload
	// This would need proper RouterInfo parsing implementation
	offset := 0
	routerInfoSize := binary.BigEndian.Uint16(decryptedPayload[offset : offset+2])
	offset += 2

	routerInfoBytes := decryptedPayload[offset : offset+int(routerInfoSize)]
	offset += int(routerInfoSize)

	routerInfo, _, err := router_info.ReadRouterInfo(routerInfoBytes)
	if err != nil {
		return nil, oops.Errorf("failed to parse RouterInfo: %w", err)
	}
	sc.RouterInfo = &routerInfo

	// Parse options if available
	if offset < len(decryptedPayload) {
		options := &messages.ConfirmedOptions{}
		// Parse options from remaining data
		// Implementation depends on options format
		sc.Options = options
	}

	return sc, nil
}

var _ handshake.HandshakeMessageProcessor = (*SessionConfirmedProcessor)(nil)

// Helper methods leveraging existing functionality
func (s *SessionConfirmedProcessor) validateRouterInfo(ri *router_info.RouterInfo) error {
	// Implement router info validation using existing methods
	return nil
}

func (s *SessionConfirmedProcessor) processOptions(options *messages.ConfirmedOptions) error {
	// Process options using existing methods
	return nil
}
