package i2np

import (
	"encoding/binary"

	"github.com/go-i2p/go-i2p/lib/tunnel"
)

/*
I2P I2NP TunnelData
https://geti2p.net/spec/i2np
Accurate for version 0.9.28


+----+----+----+----+----+----+----+----+
|     tunnnelID     | data              |
+----+----+----+----+                   |
|                                       |
~                                       ~
~                                       ~
|                                       |
+                   +----+----+----+----+
|                   |
+----+----+----+----+

tunnelId ::
         4 byte TunnelId
         identifies the tunnel this message is directed at

data ::
     1024 bytes
     payload data.. fixed to 1024 bytes
*/

// TunnelData is a fixed-size 1028-byte representation of an I2NP TunnelData message.
// The first 4 bytes are the tunnel ID and the remaining 1024 bytes are encrypted tunnel data.
//
// For full I2NP message handling (with headers, serialization, etc.), see TunnelDataMessage.
type TunnelData [1028]byte

// TunnelID extracts the 4-byte tunnel identifier from the TunnelData.
func (td *TunnelData) TunnelID() tunnel.TunnelID {
	return tunnel.TunnelID(binary.BigEndian.Uint32(td[0:4]))
}

// Data returns the 1024-byte encrypted tunnel data payload (without the tunnel ID prefix).
func (td *TunnelData) Data() [1024]byte {
	var data [1024]byte
	copy(data[:], td[4:1028])
	return data
}

// SetTunnelID sets the 4-byte tunnel identifier in the TunnelData.
func (td *TunnelData) SetTunnelID(id tunnel.TunnelID) {
	binary.BigEndian.PutUint32(td[0:4], uint32(id))
}

// SetData copies the provided 1024-byte payload into the data portion of the TunnelData.
func (td *TunnelData) SetData(data [1024]byte) {
	copy(td[4:1028], data[:])
}
