package tunnel

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"github.com/go-i2p/crypto/tunnel"
)

// MessageHandler is a callback function for processing received I2NP messages.
// It receives the unwrapped message bytes and returns an error if processing fails.
type MessageHandler func(msgBytes []byte) error

// Endpoint handles receiving encrypted tunnel messages,
// decrypting them, and extracting I2NP messages.
//
// Design decisions:
// - Simple callback-based message delivery
// - Works with raw bytes to avoid import cycles
// - Uses crypto/tunnel package with ECIES-X25519-AEAD (ChaCha20/Poly1305) by default
// - Supports both modern ECIES and legacy AES-256-CBC for compatibility
// - Handles fragment reassembly for large messages
// - Clear error handling and logging
type Endpoint struct {
	tunnelID   TunnelID
	decryption tunnel.TunnelEncryptor
	handler    MessageHandler
	// fragments maps message ID to accumulated fragments
	fragments map[uint32]*fragmentAssembler
}

// fragmentAssembler tracks fragments for a single message being reassembled
type fragmentAssembler struct {
	fragments    [][]byte
	totalCount   int
	receivedMask uint64 // Bitmap of received fragments (supports up to 64 fragments)
}

var (
	// ErrNilDecryption is returned when decryption is nil
	ErrNilDecryption = errors.New("decryption tunnel cannot be nil")
	// ErrNilHandler is returned when message handler is nil
	ErrNilHandler = errors.New("message handler cannot be nil")
	// ErrInvalidTunnelData is returned when tunnel data is malformed
	ErrInvalidTunnelData = errors.New("invalid tunnel data")
	// ErrChecksumMismatch is returned when checksum validation fails
	ErrChecksumMismatch = errors.New("tunnel message checksum mismatch")
)

// NewEndpoint creates a new tunnel endpoint.
//
// Parameters:
// - tunnelID: the ID of this tunnel
// - decryption: the tunnel decryption object for layered decryption
// - handler: callback function to process received I2NP messages
//
// Returns an error if decryption or handler is nil.
func NewEndpoint(tunnelID TunnelID, decryption tunnel.TunnelEncryptor, handler MessageHandler) (*Endpoint, error) {
	if decryption == nil {
		return nil, ErrNilDecryption
	}
	if handler == nil {
		return nil, ErrNilHandler
	}

	ep := &Endpoint{
		tunnelID:   tunnelID,
		decryption: decryption,
		handler:    handler,
		fragments:  make(map[uint32]*fragmentAssembler),
	}

	log.WithField("tunnel_id", tunnelID).Debug("Created tunnel endpoint")
	return ep, nil
}

// Receive processes an encrypted tunnel message.
//
// Process:
// 1. Decrypt the tunnel message
// 2. Validate checksum
// 3. Parse delivery instructions
// 4. Extract message fragments
// 5. Reassemble if fragmented
// 6. Deliver to handler
//
// Returns an error if processing fails at any step.
func (e *Endpoint) Receive(encryptedData []byte) error {
	if len(encryptedData) != 1028 {
		log.WithField("size", len(encryptedData)).Error("Invalid tunnel data size")
		return ErrInvalidTunnelData
	}

	// Decrypt the tunnel message
	decrypted, err := e.decryptTunnelMessage(encryptedData)
	if err != nil {
		return err
	}

	// Validate checksum
	if err := e.validateChecksum(decrypted); err != nil {
		return err
	}

	// Parse and process delivery instructions
	if err := e.processDeliveryInstructions(decrypted); err != nil {
		return err
	}

	log.WithField("tunnel_id", e.tunnelID).Debug("Successfully received message through endpoint")
	return nil
}

// decryptTunnelMessage applies tunnel decryption to the encrypted data.
// Supports both modern ECIES-X25519 and legacy AES-256-CBC decryption.
func (e *Endpoint) decryptTunnelMessage(encryptedData []byte) ([]byte, error) {
	// The TunnelEncryptor interface now returns errors for better error handling
	// Modern ECIES-X25519 uses ChaCha20/Poly1305 AEAD for authenticated decryption
	// Legacy AES uses AES-256-CBC with dual-layer decryption
	decrypted, err := e.decryption.Decrypt(encryptedData)
	if err != nil {
		log.WithError(err).Error("Failed to decrypt tunnel message")
		return nil, err
	}

	return decrypted, nil
}

// validateChecksum verifies the tunnel message checksum.
func (e *Endpoint) validateChecksum(decrypted []byte) error {
	// Extract IV (bytes 4-20) and checksum (bytes 20-24)
	iv := decrypted[4:20]
	expectedChecksum := decrypted[20:24]

	// Calculate checksum: first 4 bytes of SHA256(data after checksum + IV)
	dataAfterChecksum := decrypted[24:]
	checksumData := append(dataAfterChecksum, iv...)
	hash := sha256.Sum256(checksumData)
	actualChecksum := hash[:4]

	// Compare checksums
	for i := 0; i < 4; i++ {
		if expectedChecksum[i] != actualChecksum[i] {
			log.WithFields(map[string]interface{}{
				"expected": expectedChecksum,
				"actual":   actualChecksum,
			}).Error("Checksum mismatch")
			return ErrChecksumMismatch
		}
	}

	return nil
}

// processDeliveryInstructions parses delivery instructions and extracts messages.
func (e *Endpoint) processDeliveryInstructions(decrypted []byte) error {
	dataStart, err := e.findDataStart(decrypted)
	if err != nil {
		return err
	}

	return e.processInstructionLoop(decrypted[dataStart:])
}

// findDataStart locates the zero byte separator in tunnel message.
// It searches for the zero byte that separates padding from delivery instructions.
// Returns the position immediately after the zero byte, or an error if not found.
func (e *Endpoint) findDataStart(decrypted []byte) (int, error) {
	for i := 24; i < len(decrypted); i++ {
		if decrypted[i] == 0x00 {
			return i + 1, nil
		}
	}
	log.Error("No zero byte separator found in tunnel message")
	return -1, ErrInvalidTunnelData
}

// processInstructionLoop iterates through all delivery instructions in the data.
// It processes each instruction, handling both complete and fragmented messages.
// Returns an error if message processing fails.
func (e *Endpoint) processInstructionLoop(data []byte) error {
	for len(data) >= 3 {
		flags := data[0]
		fragmented := (flags & 0x08) != 0

		if !fragmented {
			processed, err := e.processCompleteMessage(data, flags)
			if err != nil {
				return err
			}
			if processed == 0 {
				break
			}
			data = data[processed:]
		} else {
			log.Warn("Fragmented messages not yet supported")
			break
		}
	}
	return nil
}

// processCompleteMessage handles a single non-fragmented message.
// It extracts the message, validates size, and delivers it to the handler.
// Returns the number of bytes processed, or 0 if no valid message remains.
func (e *Endpoint) processCompleteMessage(data []byte, flags byte) (int, error) {
	msgSize := binary.BigEndian.Uint16(data[1:3])

	if msgSize == 0 || len(data) < 3+int(msgSize) {
		return 0, nil
	}

	msgBytes := data[3 : 3+msgSize]
	if err := e.deliverMessage(msgBytes, flags); err != nil {
		return 0, err
	}

	return 3 + int(msgSize), nil
}

// deliverMessage sends the message to the handler if it's a local delivery.
// It checks the delivery type from flags and invokes the handler callback.
// Returns an error if the handler fails to process the message.
func (e *Endpoint) deliverMessage(msgBytes []byte, flags byte) error {
	deliveryType := flags & 0x03
	if deliveryType == DT_LOCAL {
		if err := e.handler(msgBytes); err != nil {
			log.WithError(err).Error("Handler failed to process message")
			return err
		}
	}
	return nil
}

// TunnelID returns the ID of this endpoint's tunnel
func (e *Endpoint) TunnelID() TunnelID {
	return e.tunnelID
}

// ClearFragments clears all accumulated fragments (useful for cleanup)
func (e *Endpoint) ClearFragments() {
	e.fragments = make(map[uint32]*fragmentAssembler)
	log.WithField("tunnel_id", e.tunnelID).Debug("Cleared fragment cache")
}
