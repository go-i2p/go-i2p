package i2np

import (
	"encoding/binary"

	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/samber/oops"
)

/*
I2P I2NP TunnelGateway
https://geti2p.net/spec/i2np
Accurate for version 0.9.28

+----+----+----+----+----+----+----+-//
| tunnelId          | length  | data...
+----+----+----+----+----+----+----+-//

tunnelId ::
         4 byte TunnelId
         identifies the tunnel this message is directed at

length ::
       2 byte Integer
       length of the payload

data ::
     $length bytes
     actual payload of this message
*/

type TunnelGatway struct {
	*BaseI2NPMessage
	TunnelID tunnel.TunnelID
	Length   int
	Data     []byte
}

// NewTunnelGatewayMessage creates a new TunnelGateway message
func NewTunnelGatewayMessage(tunnelID tunnel.TunnelID, payload []byte) *TunnelGatway {
	msg := &TunnelGatway{
		BaseI2NPMessage: NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_TUNNEL_GATEWAY),
		TunnelID:        tunnelID,
		Length:          len(payload),
		Data:            payload,
	}

	// Serialize: tunnelId (4 bytes) + length (2 bytes) + data
	data := make([]byte, 4+2+len(payload))
	binary.BigEndian.PutUint32(data[0:4], uint32(tunnelID))
	binary.BigEndian.PutUint16(data[4:6], uint16(len(payload)))
	copy(data[6:], payload)

	msg.SetData(data)
	return msg
}

// UnmarshalBinary deserializes a TunnelGateway message
func (t *TunnelGatway) UnmarshalBinary(data []byte) error {
	// First unmarshal the base message
	if err := t.BaseI2NPMessage.UnmarshalBinary(data); err != nil {
		return err
	}

	// Extract the data payload and parse it
	messageData := t.BaseI2NPMessage.GetData()
	if len(messageData) < 6 {
		return oops.Errorf("tunnel gateway message payload too short: %d bytes", len(messageData))
	}

	t.TunnelID = tunnel.TunnelID(binary.BigEndian.Uint32(messageData[0:4]))
	t.Length = int(binary.BigEndian.Uint16(messageData[4:6]))

	if len(messageData) < 6+t.Length {
		return oops.Errorf("tunnel gateway message payload truncated: expected %d bytes, got %d",
			6+t.Length, len(messageData))
	}

	t.Data = make([]byte, t.Length)
	copy(t.Data, messageData[6:6+t.Length])

	return nil
}
