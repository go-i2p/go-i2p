package i2np

import (
	"github.com/samber/oops"
)

// TunnelDataMessage represents an I2NP TunnelData message
// Moved from: messages.go
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
