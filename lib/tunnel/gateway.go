package tunnel

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"github.com/go-i2p/crypto/tunnel"
)

// Gateway handles sending I2NP messages through a tunnel
// by wrapping them in tunnel messages and applying encryption.
//
// Design decisions:
// - Works with raw bytes to avoid import cycles with i2np package
// - Uses existing crypto/tunnel package for encryption
// - Simple interface focused on core functionality
// - Error handling at each step with clear error messages
type Gateway struct {
	tunnelID   TunnelID
	encryption *tunnel.Tunnel
	nextHopID  TunnelID
}

var (
	// ErrNilEncryption is returned when encryption is nil
	ErrNilEncryption = errors.New("encryption tunnel cannot be nil")
	// ErrMessageTooLarge is returned when a message exceeds maximum size
	ErrMessageTooLarge = errors.New("message exceeds maximum tunnel message size")
	// ErrInvalidMessage is returned when message data is invalid
	ErrInvalidMessage = errors.New("invalid I2NP message data")
)

const (
	// maxTunnelPayload is the maximum size of data that can fit in a tunnel message
	// after accounting for tunnel ID (4), IV (16), and checksum (4)
	maxTunnelPayload = 1008 - 4 // 1004 bytes for delivery instructions + message
)

// NewGateway creates a new tunnel gateway.
//
// Parameters:
// - tunnelID: the ID of this tunnel
// - encryption: the tunnel encryption object for layered encryption
// - nextHopID: the tunnel ID to use when forwarding to the next hop
//
// Returns an error if encryption is nil.
func NewGateway(tunnelID TunnelID, encryption *tunnel.Tunnel, nextHopID TunnelID) (*Gateway, error) {
	if encryption == nil {
		return nil, ErrNilEncryption
	}

	gw := &Gateway{
		tunnelID:   tunnelID,
		encryption: encryption,
		nextHopID:  nextHopID,
	}

	log.WithField("tunnel_id", tunnelID).Debug("Created tunnel gateway")
	return gw, nil
}

// Send wraps an I2NP message (as bytes) in tunnel format and encrypts it.
//
// Parameters:
// - msgBytes: the serialized I2NP message to send
//
// Process:
// 1. Validate message size
// 2. Create delivery instructions
// 3. Build tunnel message with padding
// 4. Calculate checksum
// 5. Apply encryption
//
// Returns the encrypted tunnel message ready for transmission, or an error.
func (g *Gateway) Send(msgBytes []byte) ([]byte, error) {
	if len(msgBytes) == 0 {
		return nil, ErrInvalidMessage
	}

	// Create simple delivery instructions for local delivery (type DT_LOCAL)
	deliveryInstructions, err := g.createDeliveryInstructions(msgBytes)
	if err != nil {
		return nil, err
	}

	// Build the tunnel message
	tunnelMsg, err := g.buildTunnelMessage(deliveryInstructions, msgBytes)
	if err != nil {
		return nil, err
	}

	// Encrypt the tunnel message
	encrypted, err := g.encryptTunnelMessage(tunnelMsg)
	if err != nil {
		return nil, err
	}

	log.WithField("tunnel_id", g.tunnelID).Debug("Successfully sent message through gateway")
	return encrypted, nil
}

// createDeliveryInstructions creates delivery instructions for a message.
// Currently creates simple DT_LOCAL delivery instructions.
func (g *Gateway) createDeliveryInstructions(msgBytes []byte) ([]byte, error) {
	// Delivery instructions format (simplified for DT_LOCAL):
	// - 1 byte: flags (delivery type in low 2 bits, fragmentation in bit 3)
	// - 2 bytes: message size (if not fragmented)

	if len(msgBytes) > maxTunnelPayload-3 {
		return nil, ErrMessageTooLarge
	}

	instructions := make([]byte, 3)

	// Byte 0: flags - DT_LOCAL (0) and not fragmented
	instructions[0] = DT_LOCAL

	// Bytes 1-2: message size
	binary.BigEndian.PutUint16(instructions[1:3], uint16(len(msgBytes)))

	return instructions, nil
}

// buildTunnelMessage constructs a complete tunnel message with padding and checksum.
func (g *Gateway) buildTunnelMessage(deliveryInstructions, msgBytes []byte) ([]byte, error) {
	// Tunnel message structure:
	// [Tunnel ID (4)] [IV (16)] [Checksum (4)] [Padding (variable)] [0x00] [Instructions] [Message]

	totalSize := 1028 // Fixed tunnel message size
	msg := make([]byte, totalSize)

	// Tunnel ID (4 bytes)
	binary.BigEndian.PutUint32(msg[0:4], uint32(g.nextHopID))

	// IV will be filled by encryption layer (bytes 4-20)
	// For now, we'll use zero IV - the encryption layer should handle this properly

	// Checksum placeholder (bytes 20-24)
	// Will be calculated after adding the data

	// Calculate where to put the zero byte and data
	dataSize := len(deliveryInstructions) + len(msgBytes)
	paddingSize := totalSize - 24 - 1 - dataSize // -1 for zero byte

	if paddingSize < 0 {
		return nil, ErrMessageTooLarge
	}

	// Add random non-zero padding (bytes 24 to 24+paddingSize)
	for i := 24; i < 24+paddingSize; i++ {
		// Simple non-zero padding using incrementing pattern
		// In production, this should use crypto/rand
		msg[i] = byte((i % 255) + 1)
	}

	// Zero byte separator
	msg[24+paddingSize] = 0x00

	// Delivery instructions and message
	offset := 24 + paddingSize + 1
	copy(msg[offset:], deliveryInstructions)
	copy(msg[offset+len(deliveryInstructions):], msgBytes)

	// Calculate checksum: first 4 bytes of SHA256(data + IV)
	checksumData := append(msg[24:], msg[4:20]...)
	hash := sha256.Sum256(checksumData)
	copy(msg[20:24], hash[:4])

	return msg, nil
}

// encryptTunnelMessage applies tunnel encryption to the message.
func (g *Gateway) encryptTunnelMessage(msg []byte) ([]byte, error) {
	// Use the crypto/tunnel package to encrypt
	// The encryption layer handles IV generation and layered encryption

	var tunnelData tunnel.TunnelData
	copy(tunnelData[:], msg)

	// Apply encryption (this modifies the tunnel data in place)
	g.encryption.Encrypt(&tunnelData)

	return tunnelData[:], nil
}

// TunnelID returns the ID of this gateway's tunnel
func (g *Gateway) TunnelID() TunnelID {
	return g.tunnelID
}

// NextHopID returns the tunnel ID used for the next hop
func (g *Gateway) NextHopID() TunnelID {
	return g.nextHopID
}
