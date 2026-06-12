package i2np

import (
	"encoding/binary"
	"sync"
	"time"

	"github.com/go-i2p/crypto/types"

	datalib "github.com/go-i2p/common/data"
	"github.com/go-i2p/crypto/rand"
	"github.com/go-i2p/go-i2p/lib/tunnel/buildrecord"
	"github.com/samber/oops"
)

// M-2 FIX: Package-level variable and mutex for RNG function injection (testing only).
// Tests can set testInjectRNGError to inject errors when validating CSPRNG failure behavior.
// Protected by testInjectMutex to prevent race detector errors.
var (
	testInjectRNGError error
	testInjectMutex    sync.Mutex
)

// Message interface represents any I2NP message that can be marshaled/unmarshaled
// This is the primary interface that combines all core message behaviors
type Message interface {
	MessageSerializer
	MessageIdentifier
	MessageExpiration
}

// MessageFactory provides methods to create I2NP messages as interfaces
type MessageFactory struct{}

// NewMessageFactory creates a new message factory
func NewMessageFactory() *MessageFactory {
	return &MessageFactory{}
}

// CreateDataMessage creates a new data message
func (f *MessageFactory) CreateDataMessage(payload []byte) Message {
	return NewDataMessage(payload)
}

// CreateDeliveryStatusMessage creates a new delivery status message
func (f *MessageFactory) CreateDeliveryStatusMessage(messageID int, timestamp time.Time) Message {
	return NewDeliveryStatusMessage(messageID, timestamp)
}

// CreateTunnelDataMessage creates a new tunnel data message with the given tunnel ID and data.
func (f *MessageFactory) CreateTunnelDataMessage(tunnelID buildrecord.TunnelID, data [1024]byte) Message {
	return NewTunnelDataMessage(tunnelID, data)
}

// CreateTunnelBuildMessage creates a new tunnel build message
func (f *MessageFactory) CreateTunnelBuildMessage(records [8]BuildRequestRecord) Message {
	return &TunnelBuildMessage{
		BaseI2NPMessage: NewBaseI2NPMessage(I2NPMessageTypeTunnelBuild),
		Records:         TunnelBuild(records),
	}
}

// BaseI2NPMessage provides a basic implementation of Message
type BaseI2NPMessage struct {
	type_      int
	messageID  int
	expiration time.Time
	data       []byte
}

// generateRandomMessageID creates a random 4-byte message ID.
// The result is masked to 31 bits (0x7FFFFFFF) to ensure a positive value
// on all platforms, including 32-bit systems where int is 32 bits.
// M-2 FIX: Rejects CSPRNG failure rather than silently degrading to predictable IDs.
// Returns an error if the system's secure random number generator fails,
// or if testInjectRNGError is set (for testing crash-fast behavior).
func generateRandomMessageID() (int, error) {
	// M-2 FIX: Allow tests to inject RNG failures (with mutex protection)
	testInjectMutex.Lock()
	injectedErr := testInjectRNGError
	testInjectMutex.Unlock()
	if injectedErr != nil {
		return 0, injectedErr
	}

	msgIDBytes := make([]byte, 4)
	if _, err := rand.Read(msgIDBytes); err != nil {
		return 0, oops.Errorf("i2np: crypto/rand failed: %w", err)
	}
	// L-2 FIX: Documents secondary identifier space masking pattern (see M-2 for primary CSPRNG failure).
	// Mask to 31 bits to guarantee positive int on 32-bit platforms.
	// On 32-bit systems, int(uint32(x)) with the high bit set wraps to negative.
	// This reduces the effective ID space but is necessary for Go int compatibility.
	return int(binary.BigEndian.Uint32(msgIDBytes) & 0x7FFFFFFF), nil
}

// NewBaseI2NPMessage creates a new base I2NP message.
// Panics if the system CSPRNG is unavailable. An I2P router cannot safely
// generate message IDs without a cryptographically secure source of randomness;
// proceeding with predictable IDs would silently leak anonymity.
func NewBaseI2NPMessage(msgType int) *BaseI2NPMessage {
	msgID, err := generateRandomMessageID()
	if err != nil {
		panic("i2np: crypto/rand unavailable — cannot safely generate message IDs: " + err.Error())
	}
	return &BaseI2NPMessage{
		type_:      msgType,
		messageID:  msgID,
		expiration: time.Now().Add(60 * time.Second), // Default 60s per spec recommendation
		data:       []byte{},
	}
}

// NewI2NPMessage creates a new base I2NP message and returns it as Message interface
func NewI2NPMessage(msgType int) Message {
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

// ShortI2NPHeaderSize is the size of the short I2NP header used in NTCP2 blocks.
// Format: type(1) + msgID(4) + shortExpiration(4) = 9 bytes
const ShortI2NPHeaderSize = 9

// MarshalShortI2NP serializes the I2NP message using the 9-byte short header
// format used in NTCP2 block type 3 (I2NP message blocks).
//
// Short header format:
//   - Type (1 byte)
//   - Message ID (4 bytes, big-endian)
//   - Short Expiration (4 bytes, big-endian, seconds since epoch)
//
// The payload follows the header. No checksum is included (AEAD provides integrity).
func (m *BaseI2NPMessage) MarshalShortI2NP() ([]byte, error) {
	totalSize := ShortI2NPHeaderSize + len(m.data)
	result := make([]byte, totalSize)

	// Type (1 byte)
	result[0] = byte(m.type_)

	// Message ID (4 bytes, big-endian)
	binary.BigEndian.PutUint32(result[1:5], uint32(m.messageID))

	// Short Expiration (4 bytes, big-endian, seconds since epoch)
	binary.BigEndian.PutUint32(result[5:9], uint32(m.expiration.Unix()))

	// Data
	copy(result[ShortI2NPHeaderSize:], m.data)

	return result, nil
}

// UnmarshalShortI2NP deserializes an I2NP message from the 9-byte short header
// format used in NTCP2 block type 3.
func (m *BaseI2NPMessage) UnmarshalShortI2NP(data []byte) error {
	if len(data) < ShortI2NPHeaderSize {
		return oops.Errorf("i2np short header too short: %d bytes, need at least %d", len(data), ShortI2NPHeaderSize)
	}

	// Type (1 byte)
	m.type_ = int(data[0])

	// Message ID (4 bytes, big-endian); preserve all 32 bits from the wire — masking
	// inbound IDs truncates half the peer ID space and breaks message correlation.
	m.messageID = int(binary.BigEndian.Uint32(data[1:5]))

	// Short Expiration (4 bytes, big-endian, seconds since epoch)
	expSecs := binary.BigEndian.Uint32(data[5:9])
	m.expiration = time.Unix(int64(expSecs), 0)

	// Data (remaining bytes after header)
	m.data = make([]byte, len(data)-ShortI2NPHeaderSize)
	copy(m.data, data[ShortI2NPHeaderSize:])

	return nil
}

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
	hash := types.SHA256(m.data)
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
	// Preserve all 32 bits from the wire; masking inbound IDs breaks message correlation.
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
	hash := types.SHA256(m.data)
	actualChecksum := hash[0]
	if actualChecksum != expectedChecksum {
		return oops.Errorf("i2np message checksum mismatch: expected 0x%02x, got 0x%02x", expectedChecksum, actualChecksum)
	}

	return nil
}
