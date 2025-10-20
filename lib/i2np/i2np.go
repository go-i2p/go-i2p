package i2np

import (
	"crypto/sha256"
	"time"

	datalib "github.com/go-i2p/common/data"
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

// CreateTunnelDataMessage creates a new tunnel data message
func (f *I2NPMessageFactory) CreateTunnelDataMessage(data [1024]byte) I2NPMessage {
	return NewTunnelDataMessage(data)
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

// NewBaseI2NPMessage creates a new base I2NP message
func NewBaseI2NPMessage(msgType int) *BaseI2NPMessage {
	return &BaseI2NPMessage{
		type_:      msgType,
		messageID:  0,                                // Will be set by caller
		expiration: time.Now().Add(10 * time.Minute), // Default 10 minute expiration
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

// MarshalBinary serializes the I2NP message according to NTCP format
func (m *BaseI2NPMessage) MarshalBinary() ([]byte, error) {
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
	m.messageID = int(data[1])<<24 | int(data[2])<<16 | int(data[3])<<8 | int(data[4])

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
