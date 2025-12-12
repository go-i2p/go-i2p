package i2cp

import (
	"encoding/binary"
	"fmt"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/logger"
)

// SendMessagePayload represents the payload structure of a SendMessage (type 7) message.
// This structure follows the I2CP v2.10.0 specification for client-to-router message delivery.
//
// Format:
//
//	SessionID: uint16 (already in Message header)
//	Destination: Hash (32 bytes) - SHA256 hash of target destination
//	Payload: []byte (variable length) - actual message data to send
//
// The router will wrap this payload in garlic encryption and route it through
// the outbound tunnel pool to the specified destination.
//
// IMPORTANT: Per I2CP wire format, the total payload size is limited to MaxPayloadSize
// (currently 256 KB for i2psnark compatibility). Client applications like i2psnark may
// send payloads larger than the original 64 KB limit. Applications requiring larger
// messages should fragment them at the application layer, though i2psnark file transfers
// can use the full 256 KB limit.
type SendMessagePayload struct {
	Destination data.Hash // 32-byte SHA256 hash of target destination
	Payload     []byte    // Message data to send (variable length, max 256 KB)
}

// ParseSendMessagePayload deserializes a SendMessage payload from wire format.
// Returns an error if the payload is too short or malformed.
//
// Wire format:
//
//	bytes 0-31:  Destination hash (32 bytes)
//	bytes 32+:   Message payload (variable length)
func ParseSendMessagePayload(data []byte) (*SendMessagePayload, error) {
	// Minimum size: 32 bytes for destination hash
	// Payload can be empty (0 bytes), so minimum is exactly 32
	if len(data) < 32 {
		log.WithFields(logger.Fields{
			"at":       "i2cp.ParseSendMessagePayload",
			"dataSize": len(data),
			"required": 32,
		}).Error("send_message_payload_too_short")
		return nil, fmt.Errorf("send message payload too short: need at least 32 bytes for destination, got %d", len(data))
	}

	smp := &SendMessagePayload{}

	// Parse destination hash (first 32 bytes)
	copy(smp.Destination[:], data[0:32])

	// Parse message payload (remaining bytes)
	payloadLen := len(data) - 32
	if payloadLen > 0 {
		smp.Payload = make([]byte, payloadLen)
		copy(smp.Payload, data[32:])
	} else {
		smp.Payload = []byte{}
	}

	log.WithFields(logger.Fields{
		"at":          "i2cp.ParseSendMessagePayload",
		"destination": fmt.Sprintf("%x", smp.Destination[:8]),
		"payloadSize": payloadLen,
	}).Debug("parsed_send_message_payload")

	return smp, nil
}

// MarshalBinary serializes the SendMessagePayload to wire format.
// Returns the serialized bytes ready to be sent as an I2CP message payload.
func (smp *SendMessagePayload) MarshalBinary() ([]byte, error) {
	// Calculate total size: 32 (destination) + len(payload)
	totalSize := 32 + len(smp.Payload)
	result := make([]byte, totalSize)

	// Write destination hash
	copy(result[0:32], smp.Destination[:])

	// Write payload
	if len(smp.Payload) > 0 {
		copy(result[32:], smp.Payload)
	}

	log.WithFields(logger.Fields{
		"at":          "i2cp.SendMessagePayload.MarshalBinary",
		"destination": fmt.Sprintf("%x", smp.Destination[:8]),
		"payloadSize": len(smp.Payload),
		"totalSize":   totalSize,
	}).Debug("marshaled_send_message_payload")

	return result, nil
}

// MessagePayloadPayload represents the payload structure of a MessagePayload (type 8) message.
// This structure follows the I2CP v2.10.0 specification for router-to-client message delivery.
//
// Format:
//
//	SessionID: uint16 (already in Message header)
//	MessageID: uint32 (4 bytes) - unique identifier for this message
//	Payload: []byte (variable length) - decrypted message data
//
// The router sends this to the client after receiving and decrypting a message
// from the I2P network destined for the client's destination.
//
// IMPORTANT: Per I2CP wire format, the total payload size is limited to MaxPayloadSize
// (currently 256 KB for i2psnark compatibility). Messages larger than this limit cannot
// be delivered via I2CP and must be fragmented at the application layer by the sender.
type MessagePayloadPayload struct {
	MessageID uint32 // Unique message identifier
	Payload   []byte // Decrypted message data (variable length, max 256 KB)
}

// ParseMessagePayloadPayload deserializes a MessagePayload payload from wire format.
// Returns an error if the payload is too short or malformed.
//
// Wire format:
//
//	bytes 0-3:   MessageID (4 bytes, big endian)
//	bytes 4+:    Message payload (variable length)
func ParseMessagePayloadPayload(data []byte) (*MessagePayloadPayload, error) {
	// Minimum size: 4 bytes for message ID
	// Payload can be empty (0 bytes), so minimum is exactly 4
	if len(data) < 4 {
		log.WithFields(logger.Fields{
			"at":       "i2cp.ParseMessagePayloadPayload",
			"dataSize": len(data),
			"required": 4,
		}).Error("message_payload_too_short")
		return nil, fmt.Errorf("message payload too short: need at least 4 bytes for message ID, got %d", len(data))
	}

	mpp := &MessagePayloadPayload{}

	// Parse message ID (first 4 bytes, big endian)
	mpp.MessageID = binary.BigEndian.Uint32(data[0:4])

	// Parse message payload (remaining bytes)
	payloadLen := len(data) - 4
	if payloadLen > 0 {
		mpp.Payload = make([]byte, payloadLen)
		copy(mpp.Payload, data[4:])
	} else {
		mpp.Payload = []byte{}
	}

	log.WithFields(logger.Fields{
		"at":          "i2cp.ParseMessagePayloadPayload",
		"messageID":   mpp.MessageID,
		"payloadSize": payloadLen,
	}).Debug("parsed_message_payload")

	return mpp, nil
}

// MarshalBinary serializes the MessagePayloadPayload to wire format.
// Returns the serialized bytes ready to be sent as an I2CP message payload.
func (mpp *MessagePayloadPayload) MarshalBinary() ([]byte, error) {
	// Calculate total size: 4 (message ID) + len(payload)
	totalSize := 4 + len(mpp.Payload)
	result := make([]byte, totalSize)

	// Write message ID (big endian)
	binary.BigEndian.PutUint32(result[0:4], mpp.MessageID)

	// Write payload
	if len(mpp.Payload) > 0 {
		copy(result[4:], mpp.Payload)
	}

	log.WithFields(logger.Fields{
		"at":          "i2cp.MessagePayloadPayload.MarshalBinary",
		"messageID":   mpp.MessageID,
		"payloadSize": len(mpp.Payload),
		"totalSize":   totalSize,
	}).Debug("marshaled_message_payload")

	return result, nil
}

// SendMessageExpiresPayload represents the payload structure of a SendMessageExpires (type 36) message.
// This is an enhanced version of SendMessage that includes expiration time and delivery flags.
//
// Format per I2CP v2.10.0 specification:
//
//	Destination: Hash (32 bytes) - SHA256 hash of target destination
//	Payload: []byte (variable length) - actual message data to send
//	Nonce: uint32 (4 bytes) - random nonce for message identification
//	Flags: uint16 (2 bytes) - delivery flags (currently unused, set to 0)
//	Expiration: uint64 (6 bytes) - expiration timestamp (milliseconds since epoch, only lower 48 bits used)
//
// The Expiration field is a 48-bit timestamp (6 bytes) representing milliseconds since Unix epoch.
// Messages that have passed their expiration time will not be sent and will receive a failure status.
//
// Flags field is reserved for future use (e.g., priority, encryption options).
// Currently should be set to 0.
type SendMessageExpiresPayload struct {
	Destination data.Hash // 32-byte SHA256 hash of target destination
	Payload     []byte    // Message data to send (variable length, max 256 KB)
	Nonce       uint32    // Random nonce for message identification
	Flags       uint16    // Delivery flags (reserved, set to 0)
	Expiration  uint64    // Expiration time in milliseconds since epoch (48-bit)
}

// ParseSendMessageExpiresPayload deserializes a SendMessageExpires payload from wire format.
// Returns an error if the payload is too short or malformed.
//
// Wire format:
//
//	bytes 0-31:      Destination hash (32 bytes)
//	bytes 32-(N-13): Message payload (variable length)
//	bytes (N-12)-(N-9): Nonce (4 bytes, big endian)
//	bytes (N-8)-(N-7):  Flags (2 bytes, big endian)
//	bytes (N-6)-(N-1):  Expiration (6 bytes, big endian, 48-bit timestamp)
//
// Where N is the total payload size.
func ParseSendMessageExpiresPayload(data []byte) (*SendMessageExpiresPayload, error) {
	// Minimum size: 32 (destination) + 0 (payload) + 4 (nonce) + 2 (flags) + 6 (expiration) = 44 bytes
	minSize := 32 + 4 + 2 + 6 // 44 bytes
	if len(data) < minSize {
		log.WithFields(logger.Fields{
			"at":       "i2cp.ParseSendMessageExpiresPayload",
			"dataSize": len(data),
			"required": minSize,
		}).Error("send_message_expires_payload_too_short")
		return nil, fmt.Errorf("send message expires payload too short: need at least %d bytes, got %d", minSize, len(data))
	}

	smp := &SendMessageExpiresPayload{}

	// Parse destination hash (first 32 bytes)
	copy(smp.Destination[:], data[0:32])

	// Parse message payload (variable middle section)
	// The fixed fields (nonce, flags, expiration) are at the end
	payloadLen := len(data) - 32 - 12 // total - destination - (nonce+flags+expiration)
	if payloadLen > 0 {
		smp.Payload = make([]byte, payloadLen)
		copy(smp.Payload, data[32:32+payloadLen])
	} else {
		smp.Payload = []byte{}
	}

	// Parse fixed fields at the end
	offset := 32 + payloadLen
	smp.Nonce = binary.BigEndian.Uint32(data[offset : offset+4])
	smp.Flags = binary.BigEndian.Uint16(data[offset+4 : offset+6])

	// Parse 48-bit expiration (6 bytes) into uint64
	// Read 6 bytes and shift into 64-bit value
	expBytes := data[offset+6 : offset+12]
	smp.Expiration = uint64(expBytes[0])<<40 |
		uint64(expBytes[1])<<32 |
		uint64(expBytes[2])<<24 |
		uint64(expBytes[3])<<16 |
		uint64(expBytes[4])<<8 |
		uint64(expBytes[5])

	log.WithFields(logger.Fields{
		"at":          "i2cp.ParseSendMessageExpiresPayload",
		"destination": fmt.Sprintf("%x", smp.Destination[:8]),
		"payloadSize": payloadLen,
		"nonce":       smp.Nonce,
		"flags":       smp.Flags,
		"expiration":  smp.Expiration,
	}).Debug("parsed_send_message_expires_payload")

	return smp, nil
}

// MarshalBinary serializes the SendMessageExpiresPayload to wire format.
// Returns the serialized bytes ready to be sent as an I2CP message payload.
func (smp *SendMessageExpiresPayload) MarshalBinary() ([]byte, error) {
	// Calculate total size: 32 (destination) + len(payload) + 4 (nonce) + 2 (flags) + 6 (expiration)
	totalSize := 32 + len(smp.Payload) + 12
	result := make([]byte, totalSize)

	// Write destination hash
	copy(result[0:32], smp.Destination[:])

	// Write payload
	offset := 32
	if len(smp.Payload) > 0 {
		copy(result[offset:], smp.Payload)
		offset += len(smp.Payload)
	}

	// Write nonce (4 bytes, big endian)
	binary.BigEndian.PutUint32(result[offset:offset+4], smp.Nonce)

	// Write flags (2 bytes, big endian)
	binary.BigEndian.PutUint16(result[offset+4:offset+6], smp.Flags)

	// Write expiration (6 bytes, big endian, 48-bit)
	result[offset+6] = byte(smp.Expiration >> 40)
	result[offset+7] = byte(smp.Expiration >> 32)
	result[offset+8] = byte(smp.Expiration >> 24)
	result[offset+9] = byte(smp.Expiration >> 16)
	result[offset+10] = byte(smp.Expiration >> 8)
	result[offset+11] = byte(smp.Expiration)

	log.WithFields(logger.Fields{
		"at":          "i2cp.SendMessageExpiresPayload.MarshalBinary",
		"destination": fmt.Sprintf("%x", smp.Destination[:8]),
		"payloadSize": len(smp.Payload),
		"nonce":       smp.Nonce,
		"flags":       smp.Flags,
		"expiration":  smp.Expiration,
		"totalSize":   totalSize,
	}).Debug("marshaled_send_message_expires_payload")

	return result, nil
}
