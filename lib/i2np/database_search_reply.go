package i2np

import (
	"fmt"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/logger"
)

// truncateHashString safely truncates a hash string to at most maxLen characters.
// This prevents panics when the hash string is shorter than expected.
func truncateHashString(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen]
	}
	return s
}

/*
I2P I2NP DatabaseSearchReply
https://geti2p.net/spec/i2np
Accurate for version 0.9.28

+----+----+----+----+----+----+----+----+
| SHA256 hash as query key              |
+                                       +
|                                       |
+                                       +
|                                       |
+                                       +
|                                       |
+----+----+----+----+----+----+----+----+
| num| peer_hashes                      |
+----+                                  +
|                                       |
+                                       +
|                                       |
+                                       +
|                                       |
+    +----+----+----+----+----+----+----+
|    | from                             |
+----+                                  +
|                                       |
+                                       +
|                                       |
+                                       +
|                                       |
+    +----+----+----+----+----+----+----+
|    |
+----+

key ::
    32 bytes
    SHA256 of the object being searched

num ::
    1 byte Integer
    number of peer hashes that follow, 0-255

peer_hashes ::
          $num SHA256 hashes of 32 bytes each (total $num*32 bytes)
          SHA256 of the RouterIdentity that the other router thinks is close
          to the key

from ::
     32 bytes
     SHA256 of the RouterInfo of the router this reply was sent from
*/

type DatabaseSearchReply struct {
	*BaseI2NPMessage
	Key        common.Hash
	Count      int
	PeerHashes []common.Hash
	From       common.Hash
}

// NewDatabaseSearchReply creates a new DatabaseSearchReply message
func NewDatabaseSearchReply(key, from common.Hash, peerHashes []common.Hash) *DatabaseSearchReply {
	log.WithFields(logger.Fields{
		"at":         "NewDatabaseSearchReply",
		"key":        truncateHashString(key.String(), 8),
		"from":       truncateHashString(from.String(), 8),
		"peer_count": len(peerHashes),
	}).Debug("Creating DatabaseSearchReply")

	return &DatabaseSearchReply{
		BaseI2NPMessage: NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_DATABASE_SEARCH_REPLY),
		Key:             key,
		Count:           len(peerHashes),
		PeerHashes:      peerHashes,
		From:            from,
	}
}

// MarshalPayload serializes only the DatabaseSearchReply-specific payload fields
// (without the I2NP header). Use MarshalBinary() for a complete I2NP message.
func (d *DatabaseSearchReply) MarshalPayload() ([]byte, error) {
	// Calculate size: key(32) + count(1) + peerHashes(count*32) + from(32)
	size := 32 + 1 + (d.Count * 32) + 32
	result := make([]byte, size)
	offset := 0

	// Key (32 bytes)
	copy(result[offset:offset+32], d.Key[:])
	offset += 32

	// Count (1 byte)
	result[offset] = byte(d.Count)
	offset++

	// Peer hashes (count * 32 bytes)
	for i := 0; i < d.Count && i < len(d.PeerHashes); i++ {
		copy(result[offset:offset+32], d.PeerHashes[i][:])
		offset += 32
	}

	// From (32 bytes)
	copy(result[offset:offset+32], d.From[:])

	return result, nil
}

// MarshalBinary serializes the DatabaseSearchReply as a complete I2NP message
// including the 16-byte I2NP header (type, messageID, expiration, size, checksum).
func (d *DatabaseSearchReply) MarshalBinary() ([]byte, error) {
	log.WithFields(logger.Fields{
		"at":         "DatabaseSearchReply.MarshalBinary",
		"peer_count": d.Count,
	}).Debug("Serializing DatabaseSearchReply")

	// Serialize the type-specific payload
	payload, err := d.MarshalPayload()
	if err != nil {
		return nil, err
	}

	// Set the payload on the base message and delegate to produce the
	// complete I2NP message with header
	d.SetData(payload)

	return d.BaseI2NPMessage.MarshalBinary()
}

// UnmarshalBinary deserializes the DatabaseSearchReply message from binary data.
func (d *DatabaseSearchReply) UnmarshalBinary(data []byte) error {
	// Minimum size: key(32) + count(1) + from(32) = 65 bytes
	if len(data) < 65 {
		return ERR_DATABASE_SEARCH_REPLY_NOT_ENOUGH_DATA
	}

	offset := 0

	// Key (32 bytes)
	copy(d.Key[:], data[offset:offset+32])
	offset += 32

	// Count (1 byte)
	d.Count = int(data[offset])
	offset++

	// Validate total length
	expectedLen := 32 + 1 + (d.Count * 32) + 32
	if len(data) < expectedLen {
		return ERR_DATABASE_SEARCH_REPLY_NOT_ENOUGH_DATA
	}

	// Peer hashes (count * 32 bytes)
	d.PeerHashes = make([]common.Hash, d.Count)
	for i := 0; i < d.Count; i++ {
		copy(d.PeerHashes[i][:], data[offset:offset+32])
		offset += 32
	}

	// From (32 bytes)
	copy(d.From[:], data[offset:offset+32])

	log.WithFields(logger.Fields{
		"at":         "DatabaseSearchReply.UnmarshalBinary",
		"key":        truncateHashString(d.Key.String(), 8),
		"from":       truncateHashString(d.From.String(), 8),
		"peer_count": d.Count,
	}).Debug("DatabaseSearchReply unmarshaled successfully")

	return nil
}

// ReadDatabaseSearchReply reads a DatabaseSearchReply from binary data.
// This is a convenience function that creates a new DatabaseSearchReply and unmarshals into it.
func ReadDatabaseSearchReply(data []byte) (*DatabaseSearchReply, error) {
	reply := &DatabaseSearchReply{}
	if err := reply.UnmarshalBinary(data); err != nil {
		return nil, err
	}
	return reply, nil
}

// String returns a human-readable representation of the DatabaseSearchReply
func (d *DatabaseSearchReply) String() string {
	keyStr := d.Key.String()
	fromStr := d.From.String()

	// Safe string truncation
	if len(keyStr) > 8 {
		keyStr = keyStr[:8]
	}
	if len(fromStr) > 8 {
		fromStr = fromStr[:8]
	}

	return fmt.Sprintf("DatabaseSearchReply{key=%s..., from=%s..., peers=%d}", keyStr, fromStr, d.Count)
}
