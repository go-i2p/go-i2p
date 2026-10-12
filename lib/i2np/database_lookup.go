package i2np

import (
	"github.com/go-i2p/logger"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/session_key"
	"github.com/go-i2p/common/session_tag"
)

/*
DatabaseLookup is part of the I2P database subsystem. It queries the
distributed database for a RouterInfo or LeaseSet by SHA-256 key.

In the protocol, a router that needs a peer's identity (RouterInfo) or
lease set sends a DatabaseLookup to its floodfill peers. The peers
search their local database and reply with a DatabaseSearchReplyMessage.
The reply can be delivered directly to the requesting router or routed
through a reply tunnel for additional anonymity.

When the ECIES flag is set, the reply is encrypted with
ECIES-X25519-AEAD-Ratchet (ChaCha20-Poly1305). The sender includes a
32-byte SessionKey and one or more 8-byte ECIES SessionTags so the
receiving router can decrypt the reply.

Wire format:

  +--------------------------------------------------+
  | key (32 bytes)                                   |
  +--------------------------------------------------+
  | from (32 bytes)                                  |
  +--------------------------------------------------+
  | flags (1 byte)                                   |
  +--------------------------------------------------+
  | reply_tunnelId (4 bytes)  [if deliveryFlag == 1] |
  +--------------------------------------------------+
  | size (2 bytes)                                   |
  +--------------------------------------------------+
  | excludedPeers (size x 32 bytes)                  |
  +--------------------------------------------------+
  | reply_key (32 bytes)    [if ECIES flag set]      |
  +--------------------------------------------------+
  | tags (1 byte)           [if ECIES flag set]      |
  +--------------------------------------------------+
  | reply_tags (tags x 8 bytes) [if ECIES flag set]  |
  +--------------------------------------------------+

Fields:

  key:
    SHA-256 hash of the object to look up (RouterInfo or LeaseSet).

  from:
    If deliveryFlag == 0: SHA-256 hash of the requesting router's
    RouterInfo. If deliveryFlag == 1: SHA-256 hash of the reply tunnel
    gateway.

  flags (bit order 76543210):
    bit 0  deliveryFlag: 0 = direct reply, 1 = reply via tunnel.
    bit 1  encryptionFlag: ignored as of 0.9.6 (set to 0).
    bits 3-2 lookup type:
             00 = ANY (RouterInfo or LeaseSet) — DEPRECATED as of 0.9.16
             01 = LeaseSet only
             10 = RouterInfo only
             11 = exploration (non-floodfill routers only)
    bit 4  ECIES flag: 0 = unencrypted reply, 1 = ECIES-encrypted reply.
    bits 7-5 reserved (must be 0).

  reply_tunnelId:
    4-byte tunnel ID of the reply tunnel. Present only when
    deliveryFlag == 1.

  size:
    Number of excluded peers (0-512).

  excludedPeers:
    SHA-256 hashes of routers to exclude from the reply. If the list
    contains an all-zero hash, the lookup is exploratory.

  reply_key:
    32-byte ECIES SessionKey. Present only when the ECIES flag is set.

  tags:
    Number of ECIES reply tags that follow (typically 1). Present only
    when the ECIES flag is set.

  reply_tags:
    One or more 8-byte ECIES SessionTags. Present only when the ECIES
    flag is set.

Spec: https://geti2p.net/spec/i2np#databaselookup
ECIES: https://geti2p.net/spec/ecies
*/

// DatabaseLookup is an I2NP message that queries the distributed database
// for a RouterInfo or LeaseSet by SHA-256 key.
//
// It is part of the database subsystem: the Router sends it to floodfill
// peers, which search their local database and reply with a
// DatabaseSearchReplyMessage. The reply is delivered directly or through a
// reply tunnel, and can be ECIES-encrypted.
//
// Data flow:
//
//	Requester                Floodfill peer(s)
//	     │                            │
//	     │  DatabaseLookup (key)      │
//	     ├───────────────────────────>│  search local database
//	     │                            │
//	     │  DatabaseSearchReply       │
//	     │  (peer hashes, ECIES-enc)  │
//	     │<───────────────────────────┤  direct or via reply tunnel
//	     │                            │
//
// The requester then issues follow-up lookups for each suggested peer hash.
//
// See the package-level wire format diagram above for the on-wire layout.
type DatabaseLookup struct {
	Key            common.Hash             // SHA-256 hash of the object to look up
	From           common.Hash             // RouterInfo hash (direct) or reply tunnel gateway hash (tunnel)
	Flags          byte                    // delivery, lookup type, and ECIES flags
	ReplyTunnelID  [4]byte                 // reply tunnel ID (present only when deliveryFlag == 1)
	Size           int                     // number of excluded peers (0-512)
	ExcludedPeers  []common.Hash           // routers to exclude from the reply
	ReplyKey       session_key.SessionKey  // ECIES SessionKey (present only when ECIES flag set)
	Tags           int                     // number of ECIES reply tags (present only when ECIES flag set)
	ECIESReplyTags []session_tag.ECIESSessionTag // 8-byte ECIES SessionTags (present only when ECIES flag set)
}

// ReadDatabaseLookup parses a DatabaseLookup message from the wire.
//
// It reads the fixed fields (key, from, flags), the conditional
// reply_tunnelId, the excluded peers, and — when the ECIES flag (bit 4) is
// set — the reply encryption fields (reply_key, tags, reply_tags).
func ReadDatabaseLookup(data []byte) (DatabaseLookup, error) {
	log.WithFields(logger.Fields{"at": "ReadDatabaseLookup"}).Debug("Reading DatabaseLookup")
	databaseLookup := DatabaseLookup{}

	endOffset, err := parseLookupCoreFields(&databaseLookup, data)
	if err != nil {
		return databaseLookup, err
	}

	// Per I2P spec, encryption fields (reply_key, tags, reply_tags) are only
	// present when the ECIESFlag (bit 4) is set. Parsing them unconditionally
	// on unencrypted lookups would read past the excluded peers into garbage
	// data.
	if (databaseLookup.Flags & DatabaseLookupFlagECIES) != 0 {
		if err := parseEncryptionFields(&databaseLookup, data, endOffset); err != nil {
			return databaseLookup, err
		}
	}

	log.WithFields(logger.Fields{"at": "ReadDatabaseLookup"}).Debug("DatabaseLookup read successfully")
	return databaseLookup, nil
}

// parseLookupCoreFields extracts the fixed-size and variable-size fields from the database lookup data.
func parseLookupCoreFields(databaseLookup *DatabaseLookup, data []byte) (int, error) {
	offset := 0

	var err error
	offset, databaseLookup.Key, err = readDatabaseLookupKey(data)
	if err != nil {
		log.WithError(err).WithField("field", "Key").Error("failed to read field")
		return offset, err
	}

	offset, databaseLookup.From, err = readDatabaseLookupFrom(offset, data)
	if err != nil {
		log.WithError(err).WithField("field", "From").Error("failed to read field")
		return offset, err
	}

	offset, databaseLookup.Flags, err = readDatabaseLookupFlags(offset, data)
	if err != nil {
		log.WithError(err).WithField("field", "Flags").Error("failed to read field")
		return offset, err
	}

	offset, databaseLookup.ReplyTunnelID, err = readDatabaseLookupReplyTunnelID(databaseLookup.Flags, offset, data)
	if err != nil {
		log.WithError(err).WithField("field", "ReplyTunnelID").Error("failed to read field")
		return offset, err
	}

	offset, databaseLookup.Size, err = readDatabaseLookupSize(offset, data)
	if err != nil {
		log.WithError(err).WithField("field", "Size").Error("failed to read field")
		return offset, err
	}

	offset, databaseLookup.ExcludedPeers, err = readDatabaseLookupExcludedPeers(offset, data, databaseLookup.Size)
	if err != nil {
		log.WithError(err).WithField("field", "ExcludedPeers").Error("failed to read field")
		return offset, err
	}

	return offset, nil
}

// parseEncryptionFields extracts the encryption-related fields from the database lookup data.
func parseEncryptionFields(databaseLookup *DatabaseLookup, data []byte, offset int) error {
	var err error
	offset, databaseLookup.ReplyKey, err = readDatabaseLookupReplyKey(offset, data)
	if err != nil {
		log.WithError(err).WithField("field", "ReplyKey").Error("failed to read field")
		return err
	}

	offset, databaseLookup.Tags, err = readDatabaseLookupTags(offset, data)
	if err != nil {
		log.WithError(err).WithField("field", "Tags").Error("failed to read field")
		return err
	}

	_, eciesTags, err := readDatabaseLookupECIESReplyTags(offset, data, databaseLookup.Tags)
	if err != nil {
		log.WithError(err).Error("Failed to read ECIESReplyTags")
		return err
	}
	databaseLookup.ECIESReplyTags = eciesTags
	return nil
}

func readDatabaseLookupKey(data []byte) (int, common.Hash, error) {
	key, _, err := common.ReadHash(data)
	if err != nil {
		return 0, common.Hash{}, ErrDatabaseLookupNotEnoughData
	}

	log.WithFields(logger.Fields{
		"at":  "i2np.readDatabaseLookupKey",
		"key": key,
	}).Debug("parsed_database_lookup_key")
	return 32, key, nil
}

func readDatabaseLookupFrom(length int, data []byte) (int, common.Hash, error) {
	if len(data) < length+32 {
		return length, common.Hash{}, ErrDatabaseLookupNotEnoughData
	}

	from, _, err := common.ReadHash(data[length:])
	if err != nil {
		return length, common.Hash{}, ErrDatabaseLookupNotEnoughData
	}
	log.WithFields(logger.Fields{
		"at":   "i2np.database_lookup.readDatabaseLookupFrom",
		"from": from,
	}).Debug("parsed_database_lookup_from")
	return length + 32, from, nil
}

func readDatabaseLookupFlags(length int, data []byte) (int, byte, error) {
	if len(data) < length+1 {
		return length, byte(0), ErrDatabaseLookupNotEnoughData
	}
	flags := data[length]

	log.WithFields(logger.Fields{
		"at":    "i2np.database_lookup.readDatabaseLookupFlags",
		"flags": flags,
	}).Debug("parsed_database_lookup_flags")
	return length + 1, flags, nil
}

func readDatabaseLookupReplyTunnelID(flags byte, length int, data []byte) (int, [4]byte, error) {
	if flags&1 != 1 {
		return length, [4]byte{}, nil
	}
	if len(data) < length+4 {
		return length, [4]byte{}, ErrDatabaseLookupNotEnoughData
	}

	replyTunnelID := [4]byte(data[length : length+4])
	log.WithFields(logger.Fields{
		"at":              "i2np.database_lookup.readDatabaseLookupReplyTunnelID",
		"reply_tunnel_id": replyTunnelID,
	}).Debug("parsed_database_lookup_reply_tunnel_id")
	return length + 4, replyTunnelID, nil
}

func readDatabaseLookupSize(length int, data []byte) (int, int, error) {
	if len(data) < length+2 {
		return length, 0, ErrDatabaseLookupNotEnoughData
	}

	size := common.Integer(data[length : length+2]).Int()

	// I2P spec: valid range is 0-512 peers
	// Validate to prevent resource exhaustion attacks
	// Rate limiting is enforced at the processor level
	const MaxExcludedPeers = 512
	if size < 0 || size > MaxExcludedPeers {
		log.WithFields(logger.Fields{
			"at":   "i2np.database_lookup.readDatabaseLookupSize",
			"size": size,
		}).Error("invalid_excluded_peers_size")
		return length, 0, ErrDatabaseLookupInvalidSize
	}

	log.WithFields(logger.Fields{
		"at":   "i2np.database_lookup.readDatabaseLookupSize",
		"size": size,
	}).Debug("parsed_database_lookup_size")
	return length + 2, size, nil
}

func readDatabaseLookupExcludedPeers(length int, data []byte, size int) (int, []common.Hash, error) {
	if len(data) < length+size*32 {
		return length, []common.Hash{}, ErrDatabaseLookupNotEnoughData
	}
	var excludedPeers []common.Hash
	for i := 0; i < size; i++ {
		offset := length + i*32
		peer, _, err := common.ReadHash(data[offset:])
		if err != nil {
			return length, []common.Hash{}, ErrDatabaseLookupNotEnoughData
		}
		excludedPeers = append(excludedPeers, peer)
	}

	log.WithFields(logger.Fields{
		"at":             "i2np.database_lookup.readDatabaseLookupExcludedPeers",
		"excluded_peers": excludedPeers,
	}).Debug("parsed_database_lookup_excluded_peers")
	return length + size*32, excludedPeers, nil
}

func readDatabaseLookupReplyKey(length int, data []byte) (int, session_key.SessionKey, error) {
	if len(data) < length+32 {
		return length, session_key.SessionKey{}, ErrDatabaseLookupNotEnoughData
	}
	replyKey, _, err := session_key.ReadSessionKey(data[length:])
	if err != nil {
		return length, session_key.SessionKey{}, ErrDatabaseLookupNotEnoughData
	}

	log.WithFields(logger.Fields{
		"at":        "i2np.database_lookup.readDatabaseLookupReplyKey",
		"reply_key": replyKey,
	}).Debug("parsed_database_lookup_reply_key")
	return length + 32, replyKey, nil
}

func readDatabaseLookupTags(length int, data []byte) (int, int, error) {
	if len(data) < length+1 {
		return length, 0, ErrDatabaseLookupNotEnoughData
	}
	tags := int(data[length])

	log.WithFields(logger.Fields{
		"at":   "i2np.database_lookup.readDatabaseLookupTags",
		"tags": tags,
	}).Debug("parsed_database_lookup_tags")
	return length + 1, tags, nil
}

func readDatabaseLookupECIESReplyTags(length int, data []byte, tags int) (int, []session_tag.ECIESSessionTag, error) {
	tagSize := session_tag.ECIESSessionTagSize
	if len(data) < length+tags*tagSize {
		return length, []session_tag.ECIESSessionTag{}, ErrDatabaseLookupNotEnoughData
	}
	var replyTags []session_tag.ECIESSessionTag
	for i := 0; i < tags; i++ {
		offset := length + i*tagSize
		tag, err := session_tag.NewECIESSessionTagFromBytes(data[offset : offset+tagSize])
		if err != nil {
			return length, []session_tag.ECIESSessionTag{}, err
		}
		replyTags = append(replyTags, tag)
	}

	log.WithFields(logger.Fields{
		"at":         "i2np.database_lookup.readDatabaseLookupECIESReplyTags",
		"reply_tags": replyTags,
	}).Debug("parsed_database_lookup_ecies_reply_tags")
	return length + tags*tagSize, replyTags, nil
}

// GetKey returns the SHA-256 hash of the object being looked up.
func (d *DatabaseLookup) GetKey() common.Hash {
	return d.Key
}

// GetFrom returns the reply destination: the requesting router's RouterInfo
// hash for a direct reply, or the reply tunnel gateway hash for a tunnel reply.
func (d *DatabaseLookup) GetFrom() common.Hash {
	return d.From
}

// GetFlags returns the raw flags byte (delivery, lookup type, and ECIES bits).
func (d *DatabaseLookup) GetFlags() byte {
	return d.Flags
}

// GetECIESReplyTags returns the 8-byte ECIES SessionTags used to decrypt the
// encrypted reply. Present only when the ECIES flag is set.
func (d *DatabaseLookup) GetECIESReplyTags() []session_tag.ECIESSessionTag {
	return d.ECIESReplyTags
}

// GetTagCount returns the number of ECIES reply tags.
func (d *DatabaseLookup) GetTagCount() int {
	return d.Tags
}

// IsECIES reports whether the reply is ECIES-encrypted (bit 4 set).
func (d *DatabaseLookup) IsECIES() bool {
	return (d.Flags & 0x10) != 0
}

// Flag constants for the DatabaseLookup flags byte.
//
// The flags byte is split into three fields:
//
//	bit 0    delivery: direct reply (0) or tunnel reply (1)
//	bits 3-2 lookup type: normal, LeaseSet, RouterInfo, or exploration
//	bit 4    ECIES: reply is ECIES-encrypted
//
// Combine one delivery flag, one lookup type, and optionally the ECIES flag.
const (
	// DatabaseLookupFlagDirect requests a direct reply (bit 0 = 0).
	DatabaseLookupFlagDirect byte = 0x00
	// DatabaseLookupFlagTunnel requests a reply routed through a tunnel (bit 0 = 1).
	DatabaseLookupFlagTunnel byte = 0x01
	// DatabaseLookupFlagTypeNormal requests an ANY lookup returning a
	// RouterInfo or LeaseSet (bits 3-2 = 00). DEPRECATED as of 0.9.16;
	// prefer DatabaseLookupFlagTypeLS or DatabaseLookupFlagTypeRI.
	DatabaseLookupFlagTypeNormal byte = 0x00
	// DatabaseLookupFlagTypeLS requests a LeaseSet lookup (bits 3-2 = 01).
	DatabaseLookupFlagTypeLS byte = 0x04
	// DatabaseLookupFlagTypeRI requests a RouterInfo lookup (bits 3-2 = 10).
	DatabaseLookupFlagTypeRI byte = 0x08
	// DatabaseLookupFlagTypeExploration requests an exploration lookup that
	// returns non-floodfill routers only (bits 3-2 = 11).
	DatabaseLookupFlagTypeExploration byte = 0x0C
	// DatabaseLookupFlagECIES requests an ECIES-encrypted reply (bit 4 = 1).
	DatabaseLookupFlagECIES byte = 0x10
)

// NewDatabaseLookup creates a DatabaseLookup that requests a direct,
// unencrypted reply. The reply is sent straight to the router identified by
// from.
//
// Parameters:
//   - key: SHA-256 hash of the RouterInfo or LeaseSet to look up
//   - from: SHA-256 hash of the requesting router's RouterInfo
//   - lookupType: one of DatabaseLookupFlagTypeRI, DatabaseLookupFlagTypeLS,
//     DatabaseLookupFlagTypeNormal, or DatabaseLookupFlagTypeExploration
//   - excludedPeers: routers to exclude from the reply (may be nil)
func NewDatabaseLookup(key, from common.Hash, lookupType byte, excludedPeers []common.Hash) *DatabaseLookup {
	log.WithFields(logger.Fields{
		"at":            "NewDatabaseLookup",
		"key":           key.String()[:8],
		"from":          from.String()[:8],
		"lookup_type":   lookupType,
		"excluded_size": len(excludedPeers),
	}).Debug("Creating DatabaseLookup message")

	flags := DatabaseLookupFlagDirect | lookupType // Direct reply, specified lookup type

	return &DatabaseLookup{
		Key:            key,
		From:           from,
		Flags:          flags,
		ReplyTunnelID:  [4]byte{}, // Not used for direct reply
		Size:           len(excludedPeers),
		ExcludedPeers:  excludedPeers,
		ReplyKey:       session_key.SessionKey{}, // No encryption
		Tags:           0,
		ECIESReplyTags: nil,
	}
}

// NewDatabaseLookupWithTunnel creates a DatabaseLookup that requests a reply
// routed through a reply tunnel, adding a layer of anonymity between the
// responder and the requester.
//
// Parameters:
//   - key: SHA-256 hash of the RouterInfo or LeaseSet to look up
//   - replyGateway: SHA-256 hash of the reply tunnel's gateway router
//   - replyTunnelID: the tunnel ID to route the reply through
//   - lookupType: one of DatabaseLookupFlagTypeRI, DatabaseLookupFlagTypeLS,
//     DatabaseLookupFlagTypeNormal, or DatabaseLookupFlagTypeExploration
//   - excludedPeers: routers to exclude from the reply (may be nil)
func NewDatabaseLookupWithTunnel(key, replyGateway common.Hash, replyTunnelID [4]byte, lookupType byte, excludedPeers []common.Hash) *DatabaseLookup {
	log.WithFields(logger.Fields{
		"at":              "NewDatabaseLookupWithTunnel",
		"key":             key.String()[:8],
		"reply_gateway":   replyGateway.String()[:8],
		"reply_tunnel_id": replyTunnelID,
		"lookup_type":     lookupType,
		"excluded_size":   len(excludedPeers),
	}).Debug("Creating DatabaseLookup message with tunnel reply")

	flags := DatabaseLookupFlagTunnel | lookupType // Tunnel reply, specified lookup type

	return &DatabaseLookup{
		Key:            key,
		From:           replyGateway,
		Flags:          flags,
		ReplyTunnelID:  replyTunnelID,
		Size:           len(excludedPeers),
		ExcludedPeers:  excludedPeers,
		ReplyKey:       session_key.SessionKey{},
		Tags:           0,
		ECIESReplyTags: nil,
	}
}

// MarshalBinary serializes the DatabaseLookup to its I2NP wire format.
//
// It writes the fixed fields, the conditional reply_tunnelId, the excluded
// peers, and — when the ECIES flag is set — the reply encryption fields.
// Size is recomputed from ExcludedPeers so the wire field always matches the
// slice, regardless of how the struct was constructed.
func (d *DatabaseLookup) MarshalBinary() ([]byte, error) {
	// Always recompute Size from the actual slice length so that the wire field
	// and the in-memory slice are consistent, regardless of how the struct was
	// constructed or mutated after NewDatabaseLookup.
	d.Size = len(d.ExcludedPeers)

	log.WithFields(logger.Fields{
		"at":            "DatabaseLookup.MarshalBinary",
		"key":           d.Key.String()[:8],
		"flags":         d.Flags,
		"excluded_size": d.Size,
	}).Debug("Marshaling DatabaseLookup message")

	totalSize := d.calculateMarshalSize()
	result := make([]byte, totalSize)
	offset := d.marshalFixedFields(result)
	offset = d.marshalExcludedPeers(result, offset)
	d.marshalEncryptionFields(result, offset)

	log.WithFields(logger.Fields{
		"at":          "DatabaseLookup.MarshalBinary",
		"result_size": len(result),
	}).Debug("DatabaseLookup marshaled successfully")

	return result, nil
}

// calculateMarshalSize computes the total byte length needed for the serialized message.
func (d *DatabaseLookup) calculateMarshalSize() int {
	// Base: key(32) + from(32) + flags(1) + size(2) = 67 bytes
	totalSize := 32 + 32 + 1 + 2

	if d.hasTunnelReply() {
		totalSize += 4
	}

	totalSize += d.Size * 32

	if d.IsECIES() {
		totalSize += 32 + 1 // reply_key + tags count
		totalSize += d.Tags * 8
	}

	return totalSize
}

// hasTunnelReply returns true if the tunnel reply flag is set.
func (d *DatabaseLookup) hasTunnelReply() bool {
	return (d.Flags & DatabaseLookupFlagTunnel) != 0
}

// marshalFixedFields writes the key, from, flags, and reply tunnel ID into the buffer.
// Returns the new offset after writing.
func (d *DatabaseLookup) marshalFixedFields(result []byte) int {
	offset := 0

	copy(result[offset:offset+32], d.Key[:])
	offset += 32

	copy(result[offset:offset+32], d.From[:])
	offset += 32

	result[offset] = d.Flags
	offset++

	if d.hasTunnelReply() {
		copy(result[offset:offset+4], d.ReplyTunnelID[:])
		offset += 4
	}

	// Size (2 bytes, big endian)
	result[offset] = byte(d.Size >> 8)
	result[offset+1] = byte(d.Size)
	offset += 2

	return offset
}

// marshalExcludedPeers writes the excluded peer hashes into the buffer.
// Returns the new offset after writing.
func (d *DatabaseLookup) marshalExcludedPeers(result []byte, offset int) int {
	for i := 0; i < d.Size && i < len(d.ExcludedPeers); i++ {
		copy(result[offset:offset+32], d.ExcludedPeers[i][:])
		offset += 32
	}
	return offset
}

// marshalEncryptionFields writes the reply key and ECIES session tags into
// the buffer when ECIES reply encryption is requested.
func (d *DatabaseLookup) marshalEncryptionFields(result []byte, offset int) {
	if !d.IsECIES() {
		return
	}

	copy(result[offset:offset+32], d.ReplyKey[:])
	offset += 32

	result[offset] = byte(d.Tags)
	offset++

	for i := 0; i < d.Tags && i < len(d.ECIESReplyTags); i++ {
		copy(result[offset:offset+8], d.ECIESReplyTags[i].Bytes())
		offset += 8
	}
}

// Compile-time interface satisfaction checks
var (
	_ DatabaseReader = (*DatabaseLookup)(nil)
)
