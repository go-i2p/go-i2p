package i2np

import (
	common "github.com/go-i2p/common/data"
)

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
	Key        common.Hash
	Count      int
	PeerHashes []common.Hash
	From       common.Hash
}

// NewDatabaseSearchReply creates a new DatabaseSearchReply message
func NewDatabaseSearchReply(key, from common.Hash, peerHashes []common.Hash) *DatabaseSearchReply {
	return &DatabaseSearchReply{
		Key:        key,
		Count:      len(peerHashes),
		PeerHashes: peerHashes,
		From:       from,
	}
}

// MarshalBinary serializes the DatabaseSearchReply message
func (d *DatabaseSearchReply) MarshalBinary() ([]byte, error) {
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
