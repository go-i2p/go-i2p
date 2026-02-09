package i2np

import (
	"encoding/binary"

	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/samber/oops"
)

// TunnelDataMessage represents an I2NP TunnelData message.
// Per I2P spec, TunnelData is TunnelID(4 bytes) + Data(1024 bytes) = 1028 bytes.
//
// https://geti2p.net/spec/i2np#tunneldata
type TunnelDataMessage struct {
	*BaseI2NPMessage
	TunnelID tunnel.TunnelID // 4-byte tunnel identifier
	Data     [1024]byte      // Fixed size encrypted tunnel data
}

// NewTunnelDataMessage creates a new TunnelData message with the given tunnel ID and data.
func NewTunnelDataMessage(tunnelID tunnel.TunnelID, data [1024]byte) *TunnelDataMessage {
	msg := &TunnelDataMessage{
		BaseI2NPMessage: NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_TUNNEL_DATA),
		TunnelID:        tunnelID,
		Data:            data,
	}

	// Set the wire payload: 4-byte TunnelID + 1024-byte Data = 1028 bytes
	payload := make([]byte, 1028)
	binary.BigEndian.PutUint32(payload[0:4], uint32(tunnelID))
	copy(payload[4:], data[:])
	msg.SetData(payload)
	return msg
}

// NewTunnelCarrier creates a new TunnelData message and returns it as TunnelCarrier interface.
func NewTunnelCarrier(tunnelID tunnel.TunnelID, data [1024]byte) TunnelCarrier {
	return NewTunnelDataMessage(tunnelID, data)
}

// UnmarshalBinary deserializes a TunnelData message.
// The payload must be exactly 1028 bytes: 4-byte TunnelID + 1024-byte Data.
func (t *TunnelDataMessage) UnmarshalBinary(data []byte) error {
	// First unmarshal the base message
	if err := t.BaseI2NPMessage.UnmarshalBinary(data); err != nil {
		return err
	}

	// Extract the data payload and parse it
	messageData := t.BaseI2NPMessage.GetData()
	if len(messageData) != 1028 {
		return oops.Errorf("tunnel data message payload wrong size: expected 1028 bytes, got %d", len(messageData))
	}

	t.TunnelID = tunnel.TunnelID(binary.BigEndian.Uint32(messageData[0:4]))
	copy(t.Data[:], messageData[4:1028])
	return nil
}

// GetTunnelData returns the 1024-byte tunnel data (without the TunnelID prefix).
func (t *TunnelDataMessage) GetTunnelData() []byte {
	return t.Data[:]
}

// GetTunnelID returns the tunnel identifier for this message.
func (t *TunnelDataMessage) GetTunnelID() tunnel.TunnelID {
	return t.TunnelID
}

// Compile-time interface satisfaction check
var _ TunnelCarrier = (*TunnelDataMessage)(nil)
