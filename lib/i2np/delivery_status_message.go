package i2np

import (
	"encoding/binary"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/samber/oops"
)

// DeliveryStatusMessage represents an I2NP DeliveryStatus message
// Moved from: messages.go
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
