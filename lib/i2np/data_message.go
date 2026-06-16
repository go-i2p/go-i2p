package i2np

import (
	"encoding/binary"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// MaxI2NPMessageSize is the maximum size for an I2NP message payload.
// Per I2P specification, messages are typically limited to 32 KB.
const MaxI2NPMessageSize = 32 * 1024 // 32 KB

// DataMessage represents an I2NP Data message
// Moved from: messages.go
type DataMessage struct {
	*BaseI2NPMessage
	PayloadLength int
	Payload       []byte
}

// NewDataMessage creates a new Data message
func NewDataMessage(payload []byte) *DataMessage {
	log.WithFields(logger.Fields{
		"at":           "NewDataMessage",
		"payload_size": len(payload),
	}).Debug("Creating new data message")

	msg := &DataMessage{
		BaseI2NPMessage: NewBaseI2NPMessage(I2NPMessageTypeData),
		PayloadLength:   len(payload),
		Payload:         payload,
	}

	// Set the data payload
	data := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(data[0:4], uint32(len(payload)))
	copy(data[4:], payload)
	msg.SetData(data)

	return msg
}

// NewDataMessageWithPayload creates a new Data message and returns it as PayloadCarrier interface
func NewDataMessageWithPayload(payload []byte) PayloadCarrier {
	return NewDataMessage(payload)
}

// GetPayload returns the actual payload data
func (d *DataMessage) GetPayload() []byte {
	return d.Payload
}

// UnmarshalBinary deserializes a Data message
func (d *DataMessage) UnmarshalBinary(data []byte) error {
	log.WithFields(logger.Fields{
		"at":        "DataMessage.UnmarshalBinary",
		"data_size": len(data),
	}).Debug("Unmarshaling data message")

	// First unmarshal the base message
	if err := d.BaseI2NPMessage.UnmarshalBinary(data); err != nil {
		log.WithError(err).Error("Failed to unmarshal base message")
		return err
	}

	// Extract the data payload and parse it
	messageData := d.BaseI2NPMessage.GetData()
	if len(messageData) < 4 {
		log.WithFields(logger.Fields{
			"at":     "DataMessage.UnmarshalBinary",
			"got":    len(messageData),
			"need":   4,
			"reason": "payload too short",
		}).Error("Invalid data message")
		return oops.Errorf("data message payload too short: %d bytes", len(messageData))
	}

	// Read payload length as uint32 to prevent overflow on 32-bit platforms
	payloadLengthRaw := binary.BigEndian.Uint32(messageData[0:4])
	if payloadLengthRaw > MaxI2NPMessageSize {
		log.WithFields(logger.Fields{
			"at":           "DataMessage.UnmarshalBinary",
			"payload_size": payloadLengthRaw,
			"max_allowed":  MaxI2NPMessageSize,
			"reason":       "payload size exceeds maximum",
		}).Error("Data message payload exceeds maximum size")
		return oops.Errorf("data message payload size %d exceeds maximum %d", payloadLengthRaw, MaxI2NPMessageSize)
	}

	d.PayloadLength = int(payloadLengthRaw)
	if len(messageData) < 4+d.PayloadLength {
		log.WithFields(logger.Fields{
			"at":       "DataMessage.UnmarshalBinary",
			"expected": 4 + d.PayloadLength,
			"got":      len(messageData),
			"reason":   "payload truncated",
		}).Error("Truncated data message")
		return oops.Errorf("data message payload truncated: expected %d bytes, got %d", 4+d.PayloadLength, len(messageData))
	}

	d.Payload = make([]byte, d.PayloadLength)
	copy(d.Payload, messageData[4:4+d.PayloadLength])

	log.WithFields(logger.Fields{
		"at":             "DataMessage.UnmarshalBinary",
		"payload_length": d.PayloadLength,
	}).Debug("Successfully unmarshaled data message")
	return nil
}

// Compile-time interface satisfaction check
var _ PayloadCarrier = (*DataMessage)(nil)
