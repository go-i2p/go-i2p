package i2np

import (
	"encoding/binary"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/samber/oops"
)

// DataMessage represents an I2NP Data message
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

// Compile-time interface satisfaction check
var _ PayloadCarrier = (*DataMessage)(nil)

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

// DeliveryStatusMessage represents an I2NP DeliveryStatus message
type DeliveryStatusMessage struct {
	*BaseI2NPMessage
	StatusMessageID int
	Timestamp       time.Time
}

// NewDeliveryStatusMessage creates a new DeliveryStatus message
func NewDeliveryStatusMessage(messageID int, timestamp time.Time) *DeliveryStatusMessage {
	msg := &DeliveryStatusMessage{
		BaseI2NPMessage: NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_DELIVERY_STATUS),
		StatusMessageID: messageID,
		Timestamp:       timestamp,
	}

	// Set the data payload
	data := make([]byte, 12) // 4 bytes for message ID + 8 bytes for timestamp
	binary.BigEndian.PutUint32(data[0:4], uint32(messageID))

	// Convert timestamp to I2P Date format
	date, err := common.DateFromTime(timestamp)
	if err != nil {
		// Use current time if conversion fails
		date, _ = common.DateFromTime(time.Now())
	}
	copy(data[4:12], date[:])

	msg.SetData(data)
	return msg
}

// NewDeliveryStatusReporter creates a new DeliveryStatus message and returns it as StatusReporter interface
func NewDeliveryStatusReporter(messageID int, timestamp time.Time) StatusReporter {
	return NewDeliveryStatusMessage(messageID, timestamp)
}

// UnmarshalBinary deserializes a DeliveryStatus message
func (d *DeliveryStatusMessage) UnmarshalBinary(data []byte) error {
	// First unmarshal the base message
	if err := d.BaseI2NPMessage.UnmarshalBinary(data); err != nil {
		return err
	}

	// Extract the data payload and parse it
	messageData := d.BaseI2NPMessage.GetData()
	if len(messageData) < 12 {
		return oops.Errorf("delivery status message payload too short: %d bytes", len(messageData))
	}

	d.StatusMessageID = int(binary.BigEndian.Uint32(messageData[0:4]))

	// Parse timestamp from I2P Date format
	var date common.Date
	copy(date[:], messageData[4:12])
	d.Timestamp = date.Time()

	return nil
}

// GetStatusMessageID returns the status message ID
func (d *DeliveryStatusMessage) GetStatusMessageID() int {
	return d.StatusMessageID
}

// GetTimestamp returns the timestamp
func (d *DeliveryStatusMessage) GetTimestamp() time.Time {
	return d.Timestamp
}

// Compile-time interface satisfaction check
var _ StatusReporter = (*DeliveryStatusMessage)(nil)

// TunnelDataMessage represents an I2NP TunnelData message
type TunnelDataMessage struct {
	*BaseI2NPMessage
	Data [1024]byte // Fixed size tunnel data
}

// NewTunnelDataMessage creates a new TunnelData message
func NewTunnelDataMessage(data [1024]byte) *TunnelDataMessage {
	msg := &TunnelDataMessage{
		BaseI2NPMessage: NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_TUNNEL_DATA),
		Data:            data,
	}

	// Set the data payload (just copy the 1024 bytes)
	msg.SetData(data[:])
	return msg
}

// NewTunnelCarrier creates a new TunnelData message and returns it as TunnelCarrier interface
func NewTunnelCarrier(data [1024]byte) TunnelCarrier {
	return NewTunnelDataMessage(data)
}

// UnmarshalBinary deserializes a TunnelData message
func (t *TunnelDataMessage) UnmarshalBinary(data []byte) error {
	// First unmarshal the base message
	if err := t.BaseI2NPMessage.UnmarshalBinary(data); err != nil {
		return err
	}

	// Extract the data payload and parse it
	messageData := t.BaseI2NPMessage.GetData()
	if len(messageData) != 1024 {
		return oops.Errorf("tunnel data message payload wrong size: expected 1024 bytes, got %d", len(messageData))
	}

	copy(t.Data[:], messageData)
	return nil
}

// GetTunnelData returns the tunnel data
func (t *TunnelDataMessage) GetTunnelData() []byte {
	return t.Data[:]
}

// Compile-time interface satisfaction check
var _ TunnelCarrier = (*TunnelDataMessage)(nil)
