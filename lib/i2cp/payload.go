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
// IMPORTANT: Per I2CP specification, the total payload size (destination + message data)
// is limited to approximately 64 KB. Client applications are responsible for fragmenting
// larger messages at the application layer. The I2CP protocol does NOT provide automatic
// fragmentation - this must be handled by the client application itself.
type SendMessagePayload struct {
	Destination data.Hash // 32-byte SHA256 hash of target destination
	Payload     []byte    // Message data to send (variable length, max ~64 KB total)
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
// IMPORTANT: Per I2CP specification, the total payload size is limited to approximately
// 64 KB. Messages larger than this limit cannot be delivered via I2CP and must be
// fragmented at the application layer by the sender.
type MessagePayloadPayload struct {
	MessageID uint32 // Unique message identifier
	Payload   []byte // Decrypted message data (variable length, max ~64 KB total)
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
