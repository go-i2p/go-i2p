package i2np

import (
	"crypto/sha256"
	"encoding/binary"
	"time"

	datalib "github.com/go-i2p/common/data"
	"github.com/go-i2p/crypto/rand"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// I2NPMessage interface represents any I2NP message that can be marshaled/unmarshaled
// This is the primary interface that combines all core message behaviors
type I2NPMessage interface {
	MessageSerializer
	MessageIdentifier
	MessageExpiration
}

// I2NPMessageFactory provides methods to create I2NP messages as interfaces
type I2NPMessageFactory struct{}

// NewI2NPMessageFactory creates a new message factory
func NewI2NPMessageFactory() *I2NPMessageFactory {
	return &I2NPMessageFactory{}
}

// CreateDataMessage creates a new data message
func (f *I2NPMessageFactory) CreateDataMessage(payload []byte) I2NPMessage {
	return NewDataMessage(payload)
}

// CreateDeliveryStatusMessage creates a new delivery status message
func (f *I2NPMessageFactory) CreateDeliveryStatusMessage(messageID int, timestamp time.Time) I2NPMessage {
	return NewDeliveryStatusMessage(messageID, timestamp)
}

// CreateTunnelDataMessage creates a new tunnel data message with the given tunnel ID and data.
func (f *I2NPMessageFactory) CreateTunnelDataMessage(tunnelID tunnel.TunnelID, data [1024]byte) I2NPMessage {
	return NewTunnelDataMessage(tunnelID, data)
}

// CreateTunnelBuildMessage creates a new tunnel build message
func (f *I2NPMessageFactory) CreateTunnelBuildMessage(records [8]BuildRequestRecord) I2NPMessage {
	return NewTunnelBuildMessage(records)
}

// BaseI2NPMessage provides a basic implementation of I2NPMessage
type BaseI2NPMessage struct {
	type_      int
	messageID  int
	expiration time.Time
	data       []byte
}

// generateRandomMessageID creates a random 4-byte message ID.
// The result is masked to 31 bits (0x7FFFFFFF) to ensure a positive value
// on all platforms, including 32-bit systems where int is 32 bits.
// Returns an error if the system's secure random number generator fails.
func generateRandomMessageID() (int, error) {
	msgIDBytes := make([]byte, 4)
	if _, err := rand.Read(msgIDBytes); err != nil {
		return 0, oops.Errorf("i2np: crypto/rand failed: %w", err)
	}
	// Mask to 31 bits to guarantee positive int on 32-bit platforms.
	// On 32-bit systems, int(uint32(x)) with the high bit set wraps to negative.
	return int(binary.BigEndian.Uint32(msgIDBytes) & 0x7FFFFFFF), nil
}

// NewBaseI2NPMessage creates a new base I2NP message.
// If crypto/rand fails to generate a message ID, falls back to a
// time-based ID and logs a critical warning. This avoids panicking
// in library code while still providing a usable (if less random) ID.
func NewBaseI2NPMessage(msgType int) *BaseI2NPMessage {
	msgID, err := generateRandomMessageID()
	if err != nil {
		// Fallback: use lower 31 bits of UnixNano timestamp.
		// Less random than CSPRNG but avoids crashing the process.
		msgID = int(time.Now().UnixNano() & 0x7FFFFFFF)
		log.WithFields(logger.Fields{
			"at":          "NewBaseI2NPMessage",
			"error":       err.Error(),
			"fallback_id": msgID,
		}).Error("CSPRNG failed, using time-based message ID fallback — system entropy may be exhausted")
	}
	return &BaseI2NPMessage{
		type_:      msgType,
		messageID:  msgID,
		expiration: time.Now().Add(60 * time.Second), // Default 60s per spec recommendation
		data:       []byte{},
	}
}

// NewI2NPMessage creates a new base I2NP message and returns it as I2NPMessage interface
func NewI2NPMessage(msgType int) I2NPMessage {
	return NewBaseI2NPMessage(msgType)
}

// Type returns the message type
func (m *BaseI2NPMessage) Type() int {
	return m.type_
}

// MessageID returns the message ID
func (m *BaseI2NPMessage) MessageID() int {
	return m.messageID
}

// SetMessageID sets the message ID
func (m *BaseI2NPMessage) SetMessageID(id int) {
	m.messageID = id
}

// Expiration returns the expiration time
func (m *BaseI2NPMessage) Expiration() time.Time {
	return m.expiration
}

// SetExpiration sets the expiration time
func (m *BaseI2NPMessage) SetExpiration(exp time.Time) {
	m.expiration = exp
}

// SetData sets the message data
func (m *BaseI2NPMessage) SetData(data []byte) {
	m.data = data
}

// GetData returns the message data
func (m *BaseI2NPMessage) GetData() []byte {
	return m.data
}

// MaxI2NPStandardPayload is the maximum payload size for I2NP messages using
// the standard 16-byte header. The size field is 2 bytes (uint16), so the
// maximum representable value is 65535.
const MaxI2NPStandardPayload = 65535

// MarshalBinary serializes the I2NP message according to NTCP format.
// Returns an error if the payload exceeds 65535 bytes (the 2-byte size field limit).
func (m *BaseI2NPMessage) MarshalBinary() ([]byte, error) {
	// Validate payload size against the 2-byte (uint16) size field limit.
	// Without this check, payloads >65535 silently truncate via integer
	// overflow, producing corrupted wire format.
	if len(m.data) > MaxI2NPStandardPayload {
		return nil, oops.Errorf("i2np: payload size %d exceeds maximum %d for standard header",
			len(m.data), MaxI2NPStandardPayload)
	}

	// Calculate checksum of data
	hash := sha256.Sum256(m.data)
	checksum := hash[0]

	// Build the complete message
	// Header: type(1) + msgID(4) + expiration(8) + size(2) + checksum(1) = 16 bytes
	headerSize := 16
	totalSize := headerSize + len(m.data)
	result := make([]byte, totalSize)

	// Type (1 byte)
	result[0] = byte(m.type_)

	// Message ID (4 bytes, big endian)
	result[1] = byte(m.messageID >> 24)
	result[2] = byte(m.messageID >> 16)
	result[3] = byte(m.messageID >> 8)
	result[4] = byte(m.messageID)

	// Expiration (8 bytes)
	exp, err := datalib.DateFromTime(m.expiration)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to convert expiration time")
	}
	copy(result[5:13], exp[:])

	// Size (2 bytes, big endian)
	size := len(m.data)
	result[13] = byte(size >> 8)
	result[14] = byte(size)

	// Checksum (1 byte)
	result[15] = checksum

	// Data
	copy(result[16:], m.data)

	return result, nil
}

// UnmarshalBinary deserializes the I2NP message from NTCP format
func (m *BaseI2NPMessage) UnmarshalBinary(data []byte) error {
	if len(data) < 16 {
		return oops.Errorf("i2np message too short: %d bytes", len(data))
	}

	// Parse header
	m.type_ = int(data[0])
	// Mask to 31 bits to guarantee positive int on 32-bit platforms
	m.messageID = (int(data[1])<<24 | int(data[2])<<16 | int(data[3])<<8 | int(data[4])) & 0x7FFFFFFF

	// Parse expiration
	var expDate datalib.Date
	copy(expDate[:], data[5:13])
	m.expiration = expDate.Time()

	// Parse size
	size := int(data[13])<<8 | int(data[14])

	// Parse checksum
	expectedChecksum := data[15]

	// Validate total length
	if len(data) < 16+size {
		return oops.Errorf("i2np message data truncated: expected %d bytes, got %d", 16+size, len(data))
	}

	// Extract and validate data
	m.data = make([]byte, size)
	copy(m.data, data[16:16+size])

	// Verify checksum
	hash := sha256.Sum256(m.data)
	actualChecksum := hash[0]
	if actualChecksum != expectedChecksum {
		return oops.Errorf("i2np message checksum mismatch: expected 0x%02x, got 0x%02x", expectedChecksum, actualChecksum)
	}

	return nil
}
