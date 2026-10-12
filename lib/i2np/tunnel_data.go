package i2np

import (
	"encoding/binary"

	"github.com/go-i2p/go-i2p/lib/tunnel/buildrecord"
)

/*
I2P I2NP TunnelData
https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/i2np.rst
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
// The tunnel ID identifies which tunnel this message is directed at, so
// the receiving router can look up the tunnel state before decrypting.
// See also [TunnelData].
func (td *TunnelData) TunnelID() buildrecord.TunnelID {
	return buildrecord.TunnelID(binary.BigEndian.Uint32(td[0:4]))
}

// Data returns the 1024-byte encrypted tunnel data payload (without the
// tunnel ID prefix). The payload is encrypted with the tunnel's session
// keys and is opaque to routers that are not part of the tunnel.
// See also [TunnelData].
func (td *TunnelData) Data() [1024]byte {
	var data [1024]byte
	copy(data[:], td[4:1028])
	return data
}

// SetTunnelID sets the 4-byte tunnel identifier in the TunnelData. Routers
// set this when forwarding a message to the next hop of a tunnel.
// See also [TunnelData].
func (td *TunnelData) SetTunnelID(id buildrecord.TunnelID) {
	binary.BigEndian.PutUint32(td[0:4], uint32(id))
}

// SetData copies the provided 1024-byte payload into the data portion of
// the TunnelData. The payload must already be encrypted with the tunnel's
// session keys before transmission.
// See also [TunnelData].
func (td *TunnelData) SetData(data [1024]byte) {
	copy(td[4:1028], data[:])
}
