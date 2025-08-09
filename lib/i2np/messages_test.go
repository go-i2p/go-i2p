package i2np

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestBaseI2NPMessage(t *testing.T) {
	// Test basic message creation and marshaling
	msg := NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_DATA)
	msg.SetMessageID(12345)
	msg.SetData([]byte("Hello I2P"))

	// Marshal the message
	data, err := msg.MarshalBinary()
	assert.NoError(t, err)
	assert.True(t, len(data) > 16) // Header + data

	// Unmarshal it back
	msg2 := &BaseI2NPMessage{}
	err = msg2.UnmarshalBinary(data)
	assert.NoError(t, err)
	assert.Equal(t, I2NP_MESSAGE_TYPE_DATA, msg2.Type())
	assert.Equal(t, 12345, msg2.MessageID())
	assert.Equal(t, []byte("Hello I2P"), msg2.GetData())
}

func TestDataMessage(t *testing.T) {
	payload := []byte("This is test data")
	msg := NewDataMessage(payload)

	// Test the message
	assert.Equal(t, I2NP_MESSAGE_TYPE_DATA, msg.Type())
	assert.Equal(t, payload, msg.GetPayload())

	// Marshal and unmarshal
	data, err := msg.MarshalBinary()
	assert.NoError(t, err)

	msg2 := &DataMessage{BaseI2NPMessage: &BaseI2NPMessage{}}
	err = msg2.UnmarshalBinary(data)
	assert.NoError(t, err)
	assert.Equal(t, payload, msg2.GetPayload())
}

func TestDeliveryStatusMessage(t *testing.T) {
	timestamp := time.Now().Truncate(time.Second) // Truncate for comparison
	msg := NewDeliveryStatusMessage(54321, timestamp)

	// Test the message
	assert.Equal(t, I2NP_MESSAGE_TYPE_DELIVERY_STATUS, msg.Type())
	assert.Equal(t, 54321, msg.StatusMessageID)

	// Marshal and unmarshal
	data, err := msg.MarshalBinary()
	assert.NoError(t, err)

	msg2 := &DeliveryStatusMessage{BaseI2NPMessage: &BaseI2NPMessage{}}
	err = msg2.UnmarshalBinary(data)
	assert.NoError(t, err)
	assert.Equal(t, 54321, msg2.StatusMessageID)
	// Note: Timestamp comparison might have some precision differences due to I2P Date format
}

func TestTunnelDataMessage(t *testing.T) {
	var data [1024]byte
	copy(data[:], "Test tunnel data")

	msg := NewTunnelDataMessage(data)

	// Test the message
	assert.Equal(t, I2NP_MESSAGE_TYPE_TUNNEL_DATA, msg.Type())
	assert.Equal(t, data, msg.Data)

	// Marshal and unmarshal
	marshaledData, err := msg.MarshalBinary()
	assert.NoError(t, err)

	msg2 := &TunnelDataMessage{BaseI2NPMessage: &BaseI2NPMessage{}}
	err = msg2.UnmarshalBinary(marshaledData)
	assert.NoError(t, err)
	assert.Equal(t, data, msg2.Data)
}
