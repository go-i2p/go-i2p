package i2np

import (
	"encoding/binary"

	"github.com/samber/oops"
)

// DataMessage represents an I2NP Data message
// Moved from: messages.go
type DataMessage struct {
	*BaseI2NPMessage
	PayloadLength int
	Payload       []byte
}

// NewDataMessage creates a new Data message
func NewDataMessage(payload []byte) *DataMessage {
	msg := &DataMessage{
		BaseI2NPMessage: NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_DATA),
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
	// First unmarshal the base message
	if err := d.BaseI2NPMessage.UnmarshalBinary(data); err != nil {
		return err
	}

	// Extract the data payload and parse it
	messageData := d.BaseI2NPMessage.GetData()
	if len(messageData) < 4 {
		return oops.Errorf("data message payload too short: %d bytes", len(messageData))
	}

	d.PayloadLength = int(binary.BigEndian.Uint32(messageData[0:4]))
	if len(messageData) < 4+d.PayloadLength {
		return oops.Errorf("data message payload truncated: expected %d bytes, got %d", 4+d.PayloadLength, len(messageData))
	}

	d.Payload = make([]byte, d.PayloadLength)
	copy(d.Payload, messageData[4:4+d.PayloadLength])

	return nil
}

// Compile-time interface satisfaction check
var _ PayloadCarrier = (*DataMessage)(nil)
