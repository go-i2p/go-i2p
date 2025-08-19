package i2np

import (
	common "github.com/go-i2p/common/data"
)

/*
I2P I2NP DatabaseStore
https://geti2p.net/spec/i2np
Accurate for version 0.9.28

with reply token:
+----+----+----+----+----+----+----+----+
| SHA256 Hash as key                    |
+                                       +
|                                       |
+                                       +
|                                       |
+                                       +
|                                       |
+----+----+----+----+----+----+----+----+
|type| reply token       | reply_tunnelId
+----+----+----+----+----+----+----+----+
     | SHA256 of the gateway RouterInfo |
+----+                                  +
|                                       |
+                                       +
|                                       |
+                                       +
|                                       |
+    +----+----+----+----+----+----+----+
|    | data ...
+----+-//

with reply token == 0:
+----+----+----+----+----+----+----+----+
| SHA256 Hash as key                    |
+                                       +
|                                       |
+                                       +
|                                       |
+                                       +
|                                       |
+----+----+----+----+----+----+----+----+
|type|         0         | data ...
+----+----+----+----+----+-//

key ::
    32 bytes
    SHA256 hash

type ::
     1 byte
     type identifier
     bit 0:
             0    RouterInfo
             1    LeaseSet
     bits 7-1:
            Through release 0.9.17, must be 0
            As of release 0.9.18, ignored, reserved for future options, set to 0 for compatibility

reply token ::
            4 bytes
            If greater than zero, a DeliveryStatusMessage
            is requested with the Message ID set to the value of the Reply Token.
            A floodfill router is also expected to flood the data to the closest floodfill peers
            if the token is greater than zero.

reply_tunnelId ::
               4 byte TunnelId
               Only included if reply token > 0
               This is the TunnelId of the inbound gateway of the tunnel the response should be sent to
               If $reply_tunnelId is zero, the reply is sent directy to the reply gateway router.

reply gateway ::
              32 bytes
              Hash of the RouterInfo entry to reach the gateway
              Only included if reply token > 0
              If $reply_tunnelId is nonzero, this is the router hash of the inbound gateway
              of the tunnel the response should be sent to.
              If $reply_tunnelId is zero, this is the router hash the response should be sent to.

data ::
     If type == 0, data is a 2-byte Integer specifying the number of bytes that follow,
                   followed by a gzip-compressed RouterInfo.
     If type == 1, data is an uncompressed LeaseSet.
*/

type DatabaseStore struct {
	Key           common.Hash
	Type          byte
	ReplyToken    [4]byte
	ReplyTunnelID [4]byte
	ReplyGateway  common.Hash
	Data          []byte
}

// NewDatabaseStore creates a new DatabaseStore message
func NewDatabaseStore(key common.Hash, data []byte, dataType byte) *DatabaseStore {
	return &DatabaseStore{
		Key:           key,
		Type:          dataType,
		ReplyToken:    [4]byte{0, 0, 0, 0}, // No reply token
		ReplyTunnelID: [4]byte{0, 0, 0, 0}, // Direct response
		ReplyGateway:  common.Hash{},       // No gateway
		Data:          data,
	}
}

// GetStoreKey returns the store key
func (d *DatabaseStore) GetStoreKey() common.Hash {
	return d.Key
}

// GetStoreData returns the store data
func (d *DatabaseStore) GetStoreData() []byte {
	return d.Data
}

// GetStoreType returns the store type
func (d *DatabaseStore) GetStoreType() byte {
	return d.Type
}

// MarshalBinary serializes the DatabaseStore message
func (d *DatabaseStore) MarshalBinary() ([]byte, error) {
	// Calculate the size: key(32) + type(1) + replyToken(4) + data
	// If replyToken > 0, add replyTunnelID(4) + replyGateway(32)
	hasReply := d.ReplyToken != [4]byte{0, 0, 0, 0}
	baseSize := 32 + 1 + 4 + len(d.Data) // key + type + replyToken + data
	if hasReply {
		baseSize += 4 + 32 // replyTunnelID + replyGateway
	}

	result := make([]byte, baseSize)
	offset := 0

	// Key (32 bytes)
	copy(result[offset:offset+32], d.Key[:])
	offset += 32

	// Type (1 byte)
	result[offset] = d.Type
	offset++

	// Reply Token (4 bytes)
	copy(result[offset:offset+4], d.ReplyToken[:])
	offset += 4

	// If reply token > 0, include reply tunnel ID and gateway
	if hasReply {
		copy(result[offset:offset+4], d.ReplyTunnelID[:])
		offset += 4
		copy(result[offset:offset+32], d.ReplyGateway[:])
		offset += 32
	}

	// Data
	copy(result[offset:], d.Data)

	return result, nil
}

// Compile-time interface satisfaction check
var _ DatabaseWriter = (*DatabaseStore)(nil)
