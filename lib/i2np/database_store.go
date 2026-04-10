package i2np

import (
	"fmt"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// DatabaseStore type constants (bits 3-0 of type field)
const (
	// DatabaseStoreTypeRouterInfo indicates a RouterInfo entry
	DatabaseStoreTypeRouterInfo = 0
	// DatabaseStoreTypeLeaseSet indicates original LeaseSet (deprecated)
	DatabaseStoreTypeLeaseSet = 1
	// DatabaseStoreTypeLeaseSet2 indicates LeaseSet2 (standard as of 0.9.38+)
	DatabaseStoreTypeLeaseSet2 = 3
	// DatabaseStoreTypeEncryptedLeaseSet indicates EncryptedLeaseSet (0.9.39+), handled by lib/netdb
	DatabaseStoreTypeEncryptedLeaseSet = 5
	// DatabaseStoreTypeMetaLeaseSet indicates MetaLeaseSet (0.9.40+), handled by lib/netdb
	DatabaseStoreTypeMetaLeaseSet = 7
)

// Size limits for DatabaseStore data payloads
const (
	// MaxRouterInfoSize is the maximum size for a RouterInfo (gzip-compressed)
	// Real RouterInfos are typically 2-6KB; 64KB provides large safety margin
	MaxRouterInfoSize = 65536 // 64KB

	// MaxLeaseSetSize is the maximum size for any LeaseSet type
	// LeaseSets are typically <2KB; 32KB provides large safety margin
	MaxLeaseSetSize = 32768 // 32KB
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
             5    EncryptedLeaseSet (0.9.39+), handled by lib/netdb
             7    MetaLeaseSet (0.9.40+), handled by lib/netdb
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
     If type == 5, data is an uncompressed EncryptedLeaseSet, handled by lib/netdb.
     If type == 7, data is an uncompressed MetaLeaseSet, handled by lib/netdb.
*/

// DatabaseStore represents an I2NP DatabaseStore message used to publish a RouterInfo or LeaseSet to the network database.
type DatabaseStore struct {
	*BaseI2NPMessage
	Key           common.Hash
	StoreType     byte
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
		BaseI2NPMessage: NewBaseI2NPMessage(I2NPMessageTypeDatabaseStore),
		Key:             key,
		StoreType:       dataType,
		ReplyToken:      [4]byte{0, 0, 0, 0}, // No reply token
		ReplyTunnelID:   [4]byte{0, 0, 0, 0}, // Direct response
		ReplyGateway:    common.Hash{},       // No gateway
		Data:            data,
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
	return d.StoreType
}

// GetLeaseSetType returns the LeaseSet type variant from bits 3-0 of the type field.
// Returns one of: DatabaseStoreTypeRouterInfo, DatabaseStoreTypeLeaseSet,
// DatabaseStoreTypeLeaseSet2, DatabaseStoreTypeEncryptedLeaseSet,
// or DatabaseStoreTypeMetaLeaseSet.
func (d *DatabaseStore) GetLeaseSetType() int {
	// Extract bits 3-0 for LeaseSet variant
	typeField := int(d.StoreType & 0x0F)
	return typeField
}

// IsRouterInfo returns true if this DatabaseStore contains a RouterInfo
func (d *DatabaseStore) IsRouterInfo() bool {
	return d.GetLeaseSetType() == DatabaseStoreTypeRouterInfo
}

// IsLeaseSet returns true if this DatabaseStore contains any type of LeaseSet
func (d *DatabaseStore) IsLeaseSet() bool {
	leaseSetType := d.GetLeaseSetType()
	return leaseSetType == DatabaseStoreTypeLeaseSet ||
		leaseSetType == DatabaseStoreTypeLeaseSet2 ||
		leaseSetType == DatabaseStoreTypeEncryptedLeaseSet ||
		leaseSetType == DatabaseStoreTypeMetaLeaseSet
}

// IsLeaseSet2 returns true if this DatabaseStore contains a LeaseSet2
func (d *DatabaseStore) IsLeaseSet2() bool {
	return d.GetLeaseSetType() == DatabaseStoreTypeLeaseSet2
}

// MarshalPayload serializes only the DatabaseStore-specific payload fields
// (without the I2NP header). Use MarshalBinary() for a complete I2NP message.
func (d *DatabaseStore) MarshalPayload() ([]byte, error) {
	// Calculate the size: key(32) + type(1) + replyToken(4) + data
	// If replyToken > 0, add replyTunnelID(4) + replyGateway(32)
	hasReply := d.ReplyToken != [4]byte{0, 0, 0, 0}
	baseSize := 32 + 1 + 4 + len(d.Data) // key + type + replyToken + data
	if hasReply {
		log.WithFields(logger.Fields{
			"at": "MarshalPayload",
		}).Debug("DatabaseStore includes reply token and gateway")
		baseSize += 4 + 32 // replyTunnelID + replyGateway
	}

	result := make([]byte, baseSize)
	offset := 0

	// Key (32 bytes)
	copy(result[offset:offset+32], d.Key[:])
	offset += 32

	// StoreType (1 byte)
	result[offset] = d.StoreType
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

// MarshalBinary serializes the DatabaseStore as a complete I2NP message including
// the 16-byte I2NP header (type, messageID, expiration, size, checksum).
func (d *DatabaseStore) MarshalBinary() ([]byte, error) {
	log.WithFields(logger.Fields{
		"at":        "MarshalBinary",
		"data_type": d.StoreType,
		"data_size": len(d.Data),
		"key":       d.Key.String(),
	}).Debug("Marshaling DatabaseStore message")

	// Serialize the type-specific payload
	payload, err := d.MarshalPayload()
	if err != nil {
		return nil, err
	}

	// Set the payload on the base message and delegate to produce the
	// complete I2NP message with header
	d.SetData(payload)

	result, err := d.BaseI2NPMessage.MarshalBinary()
	if err != nil {
		return nil, err
	}

	log.WithFields(logger.Fields{
		"at":          "MarshalBinary",
		"result_size": len(result),
	}).Debug("DatabaseStore marshaled successfully")

	return result, nil
}

// UnmarshalBinary deserializes the DatabaseStore message from I2NP message data
func (d *DatabaseStore) UnmarshalBinary(data []byte) error {
	if len(data) < 37 { // Minimum: key(32) + type(1) + replyToken(4)
		return oops.Errorf("DatabaseStore message too short: %d bytes", len(data))
	}

	remainder := data

	// Key (32 bytes)
	key, remainder, err := common.ReadHash(remainder)
	if err != nil {
		return oops.Wrapf(err, "DatabaseStore: failed to read key hash")
	}
	d.Key = key

	// StoreType (1 byte)
	d.StoreType = remainder[0]
	remainder = remainder[1:]

	// Reply Token (4 bytes)
	copy(d.ReplyToken[:], remainder[:4])
	remainder = remainder[4:]

	// Check if reply token > 0 (has reply routing info)
	hasReply := d.ReplyToken != [4]byte{0, 0, 0, 0}
	if hasReply {
		if len(remainder) < 36 { // Need replyTunnelID(4) + replyGateway(32)
			return oops.Errorf("DatabaseStore with reply token truncated")
		}
		// Reply Tunnel ID (4 bytes)
		copy(d.ReplyTunnelID[:], remainder[:4])
		remainder = remainder[4:]

		// Reply Gateway (32 bytes)
		gateway, rem, err := common.ReadHash(remainder)
		if err != nil {
			return oops.Wrapf(err, "DatabaseStore: failed to read reply gateway hash")
		}
		d.ReplyGateway = gateway
		remainder = rem
	}

	// Data (remaining bytes) - validate size before allocation
	dataLen := len(remainder)
	if err := validateDatabaseStoreSize(d.StoreType, dataLen); err != nil {
		log.WithFields(logger.Fields{
			"at":        "UnmarshalBinary",
			"data_type": d.StoreType,
			"data_size": dataLen,
			"error":     err.Error(),
		}).Error("DatabaseStore data size validation failed")
		return err
	}

	d.Data = make([]byte, dataLen)
	copy(d.Data, remainder)

	log.WithFields(logger.Fields{
		"at":        "UnmarshalBinary",
		"data_type": d.StoreType,
		"data_size": len(d.Data),
		"key":       fmt.Sprintf("%x", d.Key[:8]),
		"has_reply": hasReply,
	}).Debug("DatabaseStore unmarshaled successfully")

	return nil
}

// validateDatabaseStoreSize checks if the data size is within acceptable limits
// for the given DatabaseStore type to prevent memory exhaustion attacks.
func validateDatabaseStoreSize(dataType byte, size int) error {
	leaseSetType := dataType & 0x0F // Extract bits 3-0

	switch leaseSetType {
	case DatabaseStoreTypeRouterInfo:
		if size > MaxRouterInfoSize {
			return oops.Errorf("RouterInfo size %d exceeds maximum %d", size, MaxRouterInfoSize)
		}
	case DatabaseStoreTypeLeaseSet,
		DatabaseStoreTypeLeaseSet2,
		DatabaseStoreTypeEncryptedLeaseSet,
		DatabaseStoreTypeMetaLeaseSet:
		if size > MaxLeaseSetSize {
			return oops.Errorf("LeaseSet size %d exceeds maximum %d", size, MaxLeaseSetSize)
		}
	default:
		// Unknown type - use LeaseSet limit as conservative default
		if size > MaxLeaseSetSize {
			return oops.Errorf("unknown DatabaseStore type %d: size %d exceeds maximum %d",
				dataType, size, MaxLeaseSetSize)
		}
	}

	return nil
}

// Compile-time interface satisfaction check
var _ DatabaseWriter = (*DatabaseStore)(nil)
