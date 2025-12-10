package i2np

import (
	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/logger"
)

// DatabaseStore type constants (bits 3-0 of type field)
const (
	// DATABASE_STORE_TYPE_ROUTER_INFO indicates a RouterInfo entry
	DATABASE_STORE_TYPE_ROUTER_INFO = 0
	// DATABASE_STORE_TYPE_LEASESET indicates original LeaseSet (deprecated)
	DATABASE_STORE_TYPE_LEASESET = 1
	// DATABASE_STORE_TYPE_LEASESET2 indicates LeaseSet2 (standard as of 0.9.38+)
	DATABASE_STORE_TYPE_LEASESET2 = 3
	// DATABASE_STORE_TYPE_ENCRYPTED_LEASESET indicates EncryptedLeaseSet (0.9.39+, not yet implemented)
	DATABASE_STORE_TYPE_ENCRYPTED_LEASESET = 5
	// DATABASE_STORE_TYPE_META_LEASESET indicates MetaLeaseSet (0.9.40+, not yet implemented)
	DATABASE_STORE_TYPE_META_LEASESET = 7
)

/*
I2P I2NP DatabaseStore
https://geti2p.net/spec/i2np
Accurate for version 0.9.66+

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
     bits 3-0: LeaseSet type variant
             0    RouterInfo
             1    LeaseSet (original, deprecated)
             3    LeaseSet2 (standard as of 0.9.38+)
             5    EncryptedLeaseSet (0.9.39+, not yet implemented)
             7    MetaLeaseSet (0.9.40+, not yet implemented)
     bits 7-4:
            Reserved for future use, set to 0 for compatibility

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
     If type == 1, data is an uncompressed LeaseSet (original, deprecated).
     If type == 3, data is an uncompressed LeaseSet2 (standard).
     If type == 5, data is an uncompressed EncryptedLeaseSet (not yet implemented).
     If type == 7, data is an uncompressed MetaLeaseSet (not yet implemented).
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
	log.WithFields(logger.Fields{
		"at":        "NewDatabaseStore",
		"data_size": len(data),
		"data_type": dataType,
		"key":       key.String(),
	}).Debug("Creating new DatabaseStore message")

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

// GetLeaseSetType returns the LeaseSet type variant from bits 3-0 of the type field.
// Returns one of: DATABASE_STORE_TYPE_ROUTER_INFO, DATABASE_STORE_TYPE_LEASESET,
// DATABASE_STORE_TYPE_LEASESET2, DATABASE_STORE_TYPE_ENCRYPTED_LEASESET,
// or DATABASE_STORE_TYPE_META_LEASESET.
func (d *DatabaseStore) GetLeaseSetType() int {
	// Extract bits 3-0 for LeaseSet variant
	typeField := int(d.Type & 0x0F)
	return typeField
}

// IsRouterInfo returns true if this DatabaseStore contains a RouterInfo
func (d *DatabaseStore) IsRouterInfo() bool {
	return d.GetLeaseSetType() == DATABASE_STORE_TYPE_ROUTER_INFO
}

// IsLeaseSet returns true if this DatabaseStore contains any type of LeaseSet
func (d *DatabaseStore) IsLeaseSet() bool {
	leaseSetType := d.GetLeaseSetType()
	return leaseSetType == DATABASE_STORE_TYPE_LEASESET ||
		leaseSetType == DATABASE_STORE_TYPE_LEASESET2 ||
		leaseSetType == DATABASE_STORE_TYPE_ENCRYPTED_LEASESET ||
		leaseSetType == DATABASE_STORE_TYPE_META_LEASESET
}

// IsLeaseSet2 returns true if this DatabaseStore contains a LeaseSet2
func (d *DatabaseStore) IsLeaseSet2() bool {
	return d.GetLeaseSetType() == DATABASE_STORE_TYPE_LEASESET2
}

// MarshalBinary serializes the DatabaseStore message
func (d *DatabaseStore) MarshalBinary() ([]byte, error) {
	log.WithFields(logger.Fields{
		"at":        "MarshalBinary",
		"data_type": d.Type,
		"data_size": len(d.Data),
		"key":       d.Key.String(),
	}).Debug("Marshaling DatabaseStore message")

	// Calculate the size: key(32) + type(1) + replyToken(4) + data
	// If replyToken > 0, add replyTunnelID(4) + replyGateway(32)
	hasReply := d.ReplyToken != [4]byte{0, 0, 0, 0}
	baseSize := 32 + 1 + 4 + len(d.Data) // key + type + replyToken + data
	if hasReply {
		log.WithFields(logger.Fields{
			"at": "MarshalBinary",
		}).Debug("DatabaseStore includes reply token and gateway")
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

	log.WithFields(logger.Fields{
		"at":          "MarshalBinary",
		"result_size": len(result),
		"has_reply":   hasReply,
	}).Debug("DatabaseStore marshaled successfully")

	return result, nil
}

// Compile-time interface satisfaction check
var _ DatabaseWriter = (*DatabaseStore)(nil)
