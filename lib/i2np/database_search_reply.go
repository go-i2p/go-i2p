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
DatabaseSearchReply is part of the I2P database subsystem. It is the reply a
floodfill router sends when a DatabaseLookup fails: instead of the requested
object, it returns the SHA-256 hashes of the routers it believes are closest
to the lookup key, so the requester can continue the iterative (Kademlia-style)
search toward the target.

The reply is unauthenticated: the "from" hash and the peer hashes are not
signed, so a router must treat them as untrusted suggestions, not as verified
identities. The peer hashes are "real" hashes (RouterIdentity), not routing
keys.

Wire format:

  +--------------------------------------------------+
  | key (32 bytes)                                   |
  +--------------------------------------------------+
  | num (1 byte)                                     |
  +--------------------------------------------------+
  | peer_hashes (num x 32 bytes)                     |
  +--------------------------------------------------+
  | from (32 bytes)                                  |
  +--------------------------------------------------+

Fields:

  key:
    SHA-256 hash of the object being searched (echoed from the lookup).

  num:
    Number of peer hashes that follow (0-255 on the wire; the spec
    recommends at most 16).

  peer_hashes:
    SHA-256 hashes of the RouterIdentity of routers the responder thinks
    are close to the key.

  from:
    SHA-256 hash of the RouterInfo of the router this reply was sent from.
    Unauthenticated and cannot be trusted.

Spec: https://geti2p.net/spec/i2np#databasesearchreply
Accurate for version 0.9.66
*/

// DatabaseSearchReply is an I2NP message returned in response to a failed
// DatabaseLookup, containing the hashes of alternative peers to query.
//
// It is the reply half of the database subsystem: when a floodfill router
// cannot satisfy a DatabaseLookup, it answers with this message so the
// requester can keep iterating toward the target key.
//
// See the package-level wire format diagram above for the on-wire layout.
type DatabaseSearchReply struct {
	*BaseI2NPMessage
	Key        common.Hash
	Count      int
	PeerHashes []common.Hash
	From       common.Hash
}

// NewDatabaseSearchReply creates a new DatabaseSearchReply message.
//
// It is used by a floodfill router to answer a DatabaseLookup it cannot
// satisfy: key is the lookup key being echoed back, from is the responder's
// RouterInfo hash, and peerHashes are the RouterIdentity hashes of routers
// the responder believes are close to the key.
func NewDatabaseSearchReply(key, from common.Hash, peerHashes []common.Hash) *DatabaseSearchReply {
	log.WithFields(logger.Fields{
		"at":         "NewDatabaseSearchReply",
		"key":        truncateHashString(key.String(), 8),
		"from":       truncateHashString(from.String(), 8),
		"peer_count": len(peerHashes),
	}).Debug("Creating DatabaseSearchReply")

	return &DatabaseSearchReply{
		BaseI2NPMessage: NewBaseI2NPMessage(I2NPMessageTypeDatabaseSearchReply),
		Key:             key,
		Count:           len(peerHashes),
		PeerHashes:      peerHashes,
		From:            from,
	}
}

// MarshalPayload serializes only the DatabaseSearchReply-specific payload
// fields (without the I2NP header), in the spec wire order:
// key(32) + num(1) + peer_hashes(num*32) + from(32).
// Use MarshalBinary() for a complete I2NP message including the header.
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

// MarshalBinary serializes the DatabaseSearchReply as a complete I2NP message,
// including the 16-byte I2NP header (type, messageID, expiration, size,
// checksum) followed by the payload produced by MarshalPayload.
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

// readPeerHashes reads count peer hashes from remainder, returning the hashes
// and the bytes that follow.
func readPeerHashes(remainder []byte, count int) ([]common.Hash, []byte, error) {
	hashes := make([]common.Hash, count)
	for i := 0; i < count; i++ {
		h, rem, err := common.ReadHash(remainder)
		if err != nil {
			return nil, nil, ErrDatabaseSearchReplyNotEnoughData
		}
		hashes[i] = h
		remainder = rem
	}
	return hashes, remainder, nil
}

// maxDatabaseSearchReplySuggestions bounds the number of peer hashes accepted
// from a DatabaseSearchReply. The wire format allows num in 0–255, and the
// spec recommends at most 16 ("Recommended maximum number of hashes to return:
// 16"). This implementation rejects replies with more than 16 suggestions:
// beyond the recommended maximum, a peer could inject an oversized suggestion
// set and skew the local router's iterative (Kademlia-style) lookup fan-out.
// See AUDIT.md for the deviation from the wire format's 0–255 range.
const maxDatabaseSearchReplySuggestions = 16

// UnmarshalBinary deserializes the DatabaseSearchReply message from binary
// data, parsing the spec wire order: key(32) + num(1) + peer_hashes(num*32) +
// from(32). It rejects messages shorter than the 65-byte minimum and replies
// whose num exceeds maxDatabaseSearchReplySuggestions.
func (d *DatabaseSearchReply) UnmarshalBinary(data []byte) error {
	// Minimum size: key(32) + count(1) + from(32) = 65 bytes
	if len(data) < 65 {
		return ErrDatabaseSearchReplyNotEnoughData
	}

	remainder := data

	// Key (32 bytes)
	key, remainder, err := common.ReadHash(remainder)
	if err != nil {
		return ErrDatabaseSearchReplyNotEnoughData
	}
	d.Key = key

	// Count (1 byte)
	d.Count = int(remainder[0])
	remainder = remainder[1:]

	// Spec guard: reject replies with more suggestions than the I2P spec allows.
	// The wire format allows 0–255 but spec-compliant routers send at most 16.
	// Accepting larger counts gives a malicious peer undue influence over the
	// local router's iterative lookup fan-out.
	if d.Count > maxDatabaseSearchReplySuggestions {
		log.WithFields(logger.Fields{
			"at":          "DatabaseSearchReply.UnmarshalBinary",
			"count":       d.Count,
			"max_allowed": maxDatabaseSearchReplySuggestions,
		}).Warn("DatabaseSearchReply count exceeds spec maximum; rejecting message")
		return ErrDatabaseSearchReplyNotEnoughData
	}

	// Validate total length
	if len(data) < 32+1+(d.Count*32)+32 {
		return ErrDatabaseSearchReplyNotEnoughData
	}

	// Peer hashes (count * 32 bytes)
	d.PeerHashes, remainder, err = readPeerHashes(remainder, d.Count)
	if err != nil {
		return err
	}

	// From (32 bytes)
	from, _, err := common.ReadHash(remainder)
	if err != nil {
		return ErrDatabaseSearchReplyNotEnoughData
	}
	d.From = from

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
