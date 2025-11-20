package tunnel

import (
	"encoding/binary"
	"errors"

	"github.com/go-i2p/crypto/tunnel"
)

// Participant represents an intermediate hop in an I2P tunnel.
// It receives encrypted tunnel messages, decrypts one layer,
// and forwards them to the next hop.
//
// Design decisions:
// - Simple relay logic: decrypt and forward
// - Uses crypto/tunnel with ECIES-X25519-AEAD (ChaCha20/Poly1305) by default
// - Supports both modern ECIES and legacy AES-256-CBC for compatibility
// - No message inspection (maintains tunnel privacy)
// - Stateless processing for better performance
type Participant struct {
	// tunnelID is this participant's tunnel ID (not used for processing,
	// but kept for logging and debugging)
	tunnelID TunnelID

	// decryption handles removing one layer of encryption
	decryption tunnel.TunnelEncryptor
}

var (
	// ErrNilDecryption is returned when decryption is nil
	ErrNilParticipantDecryption = errors.New("participant decryption cannot be nil")

	// ErrInvalidParticipantData is returned when tunnel data is malformed
	ErrInvalidParticipantData = errors.New("invalid participant tunnel data")
)

// NewParticipant creates a new tunnel participant.
//
// Parameters:
// - tunnelID: the tunnel ID for this participant hop
// - decryption: the tunnel decryption object for removing one encryption layer
//
// Returns an error if decryption is nil.
//
// Design note: We use TunnelEncryptor interface even though it's called
// "decryption" because the interface supports both encrypt and decrypt operations.
// The crypto/tunnel package uses the same interface for both directions.
func NewParticipant(tunnelID TunnelID, decryption tunnel.TunnelEncryptor) (*Participant, error) {
	if decryption == nil {
		return nil, ErrNilParticipantDecryption
	}

	p := &Participant{
		tunnelID:   tunnelID,
		decryption: decryption,
	}

	log.WithField("tunnel_id", tunnelID).Debug("Created tunnel participant")
	return p, nil
}

// Process handles an incoming encrypted tunnel message.
//
// This function implements the core participant functionality:
// 1. Validate the tunnel message format
// 2. Decrypt one layer of encryption
// 3. Extract the next hop tunnel ID
// 4. Return the partially-decrypted message ready for forwarding
//
// Parameters:
// - encryptedData: the 1028-byte encrypted tunnel message
//
// Returns:
// - nextHopID: the tunnel ID for the next hop
// - decryptedData: the message with one layer removed (still encrypted for next hops)
// - error: any processing error
//
// Design notes:
// - This is a stateless operation - no state is maintained between messages
// - The participant doesn't inspect message contents (privacy by design)
// - The tunnel ID in the message header specifies the next hop, not this hop
// - All 1028 bytes are returned; the next hop will decrypt further
func (p *Participant) Process(encryptedData []byte) (nextHopID TunnelID, decryptedData []byte, err error) {
	// Validate input size
	if len(encryptedData) != 1028 {
		log.WithField("size", len(encryptedData)).Error("Invalid tunnel message size")
		return 0, nil, ErrInvalidParticipantData
	}

	// Decrypt one layer of encryption
	// Modern ECIES-X25519 uses ChaCha20/Poly1305 AEAD for authenticated decryption
	// Legacy AES uses AES-256-CBC with dual-layer decryption and IV handling
	decrypted, err := p.decryption.Decrypt(encryptedData)
	if err != nil {
		log.WithError(err).Error("Failed to decrypt tunnel layer")
		return 0, nil, err
	}

	// Validate decrypted size
	if len(decrypted) < 4 {
		log.WithField("size", len(decrypted)).Error("Decrypted data too small for tunnel ID")
		return 0, nil, ErrInvalidParticipantData
	}

	// Extract next hop tunnel ID from decrypted header
	// After decryption, bytes 0-3 contain the tunnel ID for the next hop
	nextHopID = TunnelID(binary.BigEndian.Uint32(decrypted[:4]))

	log.WithFields(map[string]interface{}{
		"tunnel_id":   p.tunnelID,
		"next_hop_id": nextHopID,
	}).Debug("Participant processed tunnel message")

	// Return the decrypted data (which still contains inner encryption layers)
	// and the next hop ID for routing
	return nextHopID, decrypted, nil
}

// TunnelID returns this participant's tunnel ID
func (p *Participant) TunnelID() TunnelID {
	return p.tunnelID
}
