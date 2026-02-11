package i2np

import (
	"github.com/go-i2p/logger"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/session_key"
	"github.com/go-i2p/common/session_tag"
)

/*
I2P I2NP DatabaseLookup
https://geti2p.net/spec/i2np#databaselookup
Accurate for version 0.9.65

+----+----+----+----+----+----+----+----+
| SHA256 hash as the key to look up     |
+                                       +
|                                       |
+                                       +
|                                       |
+                                       +
|                                       |
+----+----+----+----+----+----+----+----+
| SHA256 hash of the routerInfo         |
+ who is asking or the gateway to       +
| send the reply to                     |
+                                       +
|                                       |
+                                       +
|                                       |
+----+----+----+----+----+----+----+----+
|flag| reply_tunnelId    | size    |    |
+----+----+----+----+----+----+----+    +
| SHA256 of key1 to exclude             |
+                                       +
|                                       |
+                                       +
|                                       |
+                                  +----+
|                                  |    |
+----+----+----+----+----+----+----+    +
| SHA256 of key2 to exclude             |
+                                       +
~                                       ~
+                                  +----+
|                                  |    |
+----+----+----+----+----+----+----+    +
|                                       |
+                                       +
|   Session key if reply encryption     |
+   was requested                       +
|                                       |
+                                  +----+
|                                  |tags|
+----+----+----+----+----+----+----+----+
|                                       |
+                                       +
|   Session tags if reply encryption    |
+   was requested                       +
|                                       |
+                                       +
|                                       |
+----+----+----+----+----+----+----+----+

key ::
    32 bytes
    SHA256 hash of the object to lookup

from ::
     32 bytes
     if deliveryFlag == 0, the SHA256 hash of the routerInfo entry this
                           request came from (to which the reply should be
                           sent)
     if deliveryFlag == 1, the SHA256 hash of the reply tunnel gateway (to
                           which the reply should be sent)

flags ::
     1 byte
     bit order: 76543210
     bit 0: deliveryFlag
             0  => send reply directly
             1  => send reply to some tunnel
     bit 1: encryptionFlag
             through release 0.9.5, must be set to 0
             as of release 0.9.6, ignored
             as of release 0.9.7:
             0  => send unencrypted reply
             1  => send AES encrypted reply using enclosed key and tag
     bits 3-2: lookup type flags
             through release 0.9.5, must be set to 00
             as of release 0.9.6, ignored
             as of release 0.9.16:
             00  => normal lookup, return RouterInfo or LeaseSet or
                    DatabaseSearchReplyMessage
                    Not recommended when sending to routers
                    with version 0.9.16 or higher.
             01  => LS lookup, return LeaseSet or
                    DatabaseSearchReplyMessage
                    As of release 0.9.38, may also return a
                    LeaseSet2, MetaLeaseSet, or EncryptedLeaseSet.
             10  => RI lookup, return RouterInfo or
                    DatabaseSearchReplyMessage
             11  => exploration lookup, return DatabaseSearchReplyMessage
                    containing non-floodfill routers only (replaces an
                    excludedPeer of all zeroes)
     bit 4: ECIESFlag
             before release 0.9.46 ignored
             as of release 0.9.46:
             0  => send unencrypted or ElGamal reply
             1  => send ChaCha/Poly encrypted reply using enclosed key
                   (whether tag is enclosed depends on bit 1)
     bits 7-5:
             through release 0.9.5, must be set to 0
             as of release 0.9.6, ignored, set to 0 for compatibility with
             future uses and with older routers

reply_tunnelId ::
               4 byte TunnelID
               only included if deliveryFlag == 1
               tunnelId of the tunnel to send the reply to, nonzero

size ::
     2 byte Integer
     valid range: 0-512
     number of peers to exclude from the DatabaseSearchReplyMessage

excludedPeers ::
              $size SHA256 hashes of 32 bytes each (total $size*32 bytes)
              if the lookup fails, these peers are requested to be excluded
              from the list in the DatabaseSearchReplyMessage.
              if excludedPeers includes a hash of all zeroes, the request is
              exploratory, and the DatabaseSearchReplyMessage is requested
              to list non-floodfill routers only.

reply_key ::
     32 byte key
     see below

tags ::
     1 byte Integer
     valid range: 1-32 (typically 1)
     the number of reply tags that follow
     see below

reply_tags ::
     one or more 8 or 32 byte session tags (typically one)
     see below


ElG to ElG

reply_key ::
     32 byte SessionKey big-endian
     only included if encryptionFlag == 1 AND ECIESFlag == 0, only as of release 0.9.7

tags ::
     1 byte Integer
     valid range: 1-32 (typically 1)
     the number of reply tags that follow
     only included if encryptionFlag == 1 AND ECIESFlag == 0, only as of release 0.9.7

reply_tags ::
     one or more 32 byte SessionTags (typically one)
     only included if encryptionFlag == 1 AND ECIESFlag == 0, only as of release 0.9.7


ECIES to ElG

reply_key ::
     32 byte ECIES SessionKey big-endian
     only included if encryptionFlag == 0 AND ECIESFlag == 1, only as of release 0.9.46

tags ::
     1 byte Integer
     required value: 1
     the number of reply tags that follow
     only included if encryptionFlag == 0 AND ECIESFlag == 1, only as of release 0.9.46

reply_tags ::
     an 8 byte ECIES SessionTag
     only included if encryptionFlag == 0 AND ECIESFlag == 1, only as of release 0.9.46

*/

type DatabaseLookup struct {
	Key            common.Hash
	From           common.Hash
	Flags          byte
	ReplyTunnelID  [4]byte
	Size           int
	ExcludedPeers  []common.Hash
	ReplyKey       session_key.SessionKey
	Tags           int
	ReplyTags      []session_tag.SessionTag
	ECIESReplyTags []session_tag.ECIESSessionTag
}

func ReadDatabaseLookup(data []byte) (DatabaseLookup, error) {
	log.Debug("Reading DatabaseLookup")
	databaseLookup := DatabaseLookup{}

	if err := parseBasicFields(&databaseLookup, data); err != nil {
		return databaseLookup, err
	}

	if err := parseVariableFields(&databaseLookup, data); err != nil {
		return databaseLookup, err
	}

	// Per I2P spec, encryption fields (reply_key, tags, reply_tags) are only
	// present when encryptionFlag (bit 1) or ECIESFlag (bit 4) is set.
	// Parsing them unconditionally on unencrypted lookups would read past
	// the excluded peers into garbage data.
	if databaseLookup.hasEncryption() || (databaseLookup.Flags&DatabaseLookupFlagECIES) != 0 {
		if err := parseEncryptionFields(&databaseLookup, data); err != nil {
			return databaseLookup, err
		}
	}

	log.Debug("DatabaseLookup read successfully")
	return databaseLookup, nil
}

// parseBasicFields extracts the fixed-size basic fields from the database lookup data.
func parseBasicFields(databaseLookup *DatabaseLookup, data []byte) error {
	length, key, err := readDatabaseLookupKey(data)
	if err != nil {
		log.WithError(err).Error("Failed to read Key")
		return err
	}
	databaseLookup.Key = key

	length, from, err := readDatabaseLookupFrom(length, data)
	if err != nil {
		log.WithError(err).Error("Failed to read From")
		return err
	}
	databaseLookup.From = from

	length, flags, err := readDatabaseLookupFlags(length, data)
	if err != nil {
		log.WithError(err).Error("Failed to read Flags")
		return err
	}
	databaseLookup.Flags = flags

	_, replyTunnelID, err := readDatabaseLookupReplyTunnelID(flags, length, data)
	if err != nil {
		log.WithError(err).Error("Failed to read ReplyTunnelID")
		return err
	}
	databaseLookup.ReplyTunnelID = replyTunnelID

	return nil
}

// parseVariableFields extracts the variable-size fields including excluded peers.
func parseVariableFields(databaseLookup *DatabaseLookup, data []byte) error {
	// Calculate length offset after basic fields
	length := 32 + 32 + 1 // Key + From + Flags
	if databaseLookup.Flags&1 == 1 {
		length += 4 // ReplyTunnelID
	}

	lengthAfter, size, err := readDatabaseLookupSize(length, data)
	if err != nil {
		log.WithError(err).Error("Failed to read Size")
		return err
	}
	databaseLookup.Size = size

	_, excludedPeers, err := readDatabaseLookupExcludedPeers(lengthAfter, data, size)
	if err != nil {
		log.WithError(err).Error("Failed to read ExcludedPeers")
		return err
	}
	databaseLookup.ExcludedPeers = excludedPeers

	return nil
}

// parseEncryptionFields extracts the encryption-related fields from the database lookup data.
func parseEncryptionFields(databaseLookup *DatabaseLookup, data []byte) error {
	// Calculate length offset after basic and variable fields
	length := 32 + 32 + 1 + 2 + (databaseLookup.Size * 32) // Key + From + Flags + Size + ExcludedPeers
	if databaseLookup.Flags&1 == 1 {
		length += 4 // ReplyTunnelID
	}

	lengthAfter, replyKey, err := readDatabaseLookupReplyKey(length, data)
	if err != nil {
		log.WithError(err).Error("Failed to read ReplyKey")
		return err
	}
	databaseLookup.ReplyKey = replyKey

	lengthAfter, tags, err := readDatabaseLookupTags(lengthAfter, data)
	if err != nil {
		log.WithError(err).Error("Failed to read Tags")
		return err
	}
	databaseLookup.Tags = tags

	ecies := (databaseLookup.Flags & 0x10) != 0
	if ecies {
		_, eciesTags, err := readDatabaseLookupECIESReplyTags(lengthAfter, data, tags)
		if err != nil {
			log.WithError(err).Error("Failed to read ECIESReplyTags")
			return err
		}
		databaseLookup.ECIESReplyTags = eciesTags
	} else {
		_, replyTags, err := readDatabaseLookupReplyTags(lengthAfter, data, tags)
		if err != nil {
			log.WithError(err).Error("Failed to read ReplyTags")
			return err
		}
		databaseLookup.ReplyTags = replyTags
	}

	return nil
}

func readDatabaseLookupKey(data []byte) (int, common.Hash, error) {
	if len(data) < 32 {
		return 0, common.Hash{}, ERR_DATABASE_LOOKUP_NOT_ENOUGH_DATA
	}

	key := common.Hash(data[:32])
	log.WithFields(logger.Fields{
		"at":  "i2np.readDatabaseLookupKey",
		"key": key,
	}).Debug("parsed_database_lookup_key")
	return 32, key, nil
}

func readDatabaseLookupFrom(length int, data []byte) (int, common.Hash, error) {
	if len(data) < length+32 {
		return length, common.Hash{}, ERR_DATABASE_LOOKUP_NOT_ENOUGH_DATA
	}

	from := common.Hash(data[length : length+32])
	log.WithFields(logger.Fields{
		"at":   "i2np.database_lookup.readDatabaseLookupFrom",
		"from": from,
	}).Debug("parsed_database_lookup_from")
	return length + 32, from, nil
}

func readDatabaseLookupFlags(length int, data []byte) (int, byte, error) {
	if len(data) < length+1 {
		return length, byte(0), ERR_DATABASE_LOOKUP_NOT_ENOUGH_DATA
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
		return length, [4]byte{}, ERR_DATABASE_LOOKUP_NOT_ENOUGH_DATA
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
		return length, 0, ERR_DATABASE_LOOKUP_NOT_ENOUGH_DATA
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
		return length, 0, ERR_DATABASE_LOOKUP_INVALID_SIZE
	}

	log.WithFields(logger.Fields{
		"at":   "i2np.database_lookup.readDatabaseLookupSize",
		"size": size,
	}).Debug("parsed_database_lookup_size")
	return length + 2, size, nil
}

func readDatabaseLookupExcludedPeers(length int, data []byte, size int) (int, []common.Hash, error) {
	if len(data) < length+size*32 {
		return length, []common.Hash{}, ERR_DATABASE_LOOKUP_NOT_ENOUGH_DATA
	}
	var excludedPeers []common.Hash
	for i := 0; i < size; i++ {
		offset := length + i*32
		peer := common.Hash(data[offset : offset+32])
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
		return length, session_key.SessionKey{}, ERR_DATABASE_LOOKUP_NOT_ENOUGH_DATA
	}
	replyKey := session_key.SessionKey(data[length : length+32])

	log.WithFields(logger.Fields{
		"at":        "i2np.database_lookup.readDatabaseLookupReplyKey",
		"reply_key": replyKey,
	}).Debug("parsed_database_lookup_reply_key")
	return length + 32, replyKey, nil
}

func readDatabaseLookupTags(length int, data []byte) (int, int, error) {
	if len(data) < length+1 {
		return length, 0, ERR_DATABASE_LOOKUP_NOT_ENOUGH_DATA
	}
	tags := int(data[length])

	log.WithFields(logger.Fields{
		"at":   "i2np.database_lookup.readDatabaseLookupTags",
		"tags": tags,
	}).Debug("parsed_database_lookup_tags")
	return length + 1, tags, nil
}

func readDatabaseLookupReplyTags(length int, data []byte, tags int) (int, []session_tag.SessionTag, error) {
	if len(data) < length+tags*32 {
		return length, []session_tag.SessionTag{}, ERR_DATABASE_LOOKUP_NOT_ENOUGH_DATA
	}
	var reply_tags []session_tag.SessionTag
	for i := 0; i < tags; i++ {
		offset := length + i*32
		tag, err := session_tag.NewSessionTagFromBytes(data[offset : offset+32])
		if err != nil {
			return length, []session_tag.SessionTag{}, err
		}
		reply_tags = append(reply_tags, tag)
	}

	log.WithFields(logger.Fields{
		"at":         "i2np.database_lookup.readDatabaseLookupReplyTags",
		"reply_tags": reply_tags,
	}).Debug("parsed_database_lookup_reply_tags")
	return length + tags*32, reply_tags, nil
}

func readDatabaseLookupECIESReplyTags(length int, data []byte, tags int) (int, []session_tag.ECIESSessionTag, error) {
	tagSize := session_tag.ECIESSessionTagSize
	if len(data) < length+tags*tagSize {
		return length, []session_tag.ECIESSessionTag{}, ERR_DATABASE_LOOKUP_NOT_ENOUGH_DATA
	}
	var reply_tags []session_tag.ECIESSessionTag
	for i := 0; i < tags; i++ {
		offset := length + i*tagSize
		tag, err := session_tag.NewECIESSessionTagFromBytes(data[offset : offset+tagSize])
		if err != nil {
			return length, []session_tag.ECIESSessionTag{}, err
		}
		reply_tags = append(reply_tags, tag)
	}

	log.WithFields(logger.Fields{
		"at":         "i2np.database_lookup.readDatabaseLookupECIESReplyTags",
		"reply_tags": reply_tags,
	}).Debug("parsed_database_lookup_ecies_reply_tags")
	return length + tags*tagSize, reply_tags, nil
}

// GetKey returns the lookup key
func (d *DatabaseLookup) GetKey() common.Hash {
	return d.Key
}

// GetFrom returns the from hash
func (d *DatabaseLookup) GetFrom() common.Hash {
	return d.From
}

// GetFlags returns the lookup flags
func (d *DatabaseLookup) GetFlags() byte {
	return d.Flags
}

// GetReplyTags returns the reply tags
func (d *DatabaseLookup) GetReplyTags() []session_tag.SessionTag {
	return d.ReplyTags
}

// GetECIESReplyTags returns the ECIES reply tags (8-byte)
func (d *DatabaseLookup) GetECIESReplyTags() []session_tag.ECIESSessionTag {
	return d.ECIESReplyTags
}

// GetTagCount returns the number of tags
func (d *DatabaseLookup) GetTagCount() int {
	return d.Tags
}

// IsECIES returns true if the ECIESFlag (bit 4) is set in the flags byte
func (d *DatabaseLookup) IsECIES() bool {
	return (d.Flags & 0x10) != 0
}

// DatabaseLookup flag constants for constructing lookup messages
const (
	// DatabaseLookupFlagDirect means send reply directly (bit 0 = 0)
	DatabaseLookupFlagDirect byte = 0x00
	// DatabaseLookupFlagTunnel means send reply to a tunnel (bit 0 = 1)
	DatabaseLookupFlagTunnel byte = 0x01
	// DatabaseLookupFlagEncryption means encrypt reply (bit 1 = 1)
	DatabaseLookupFlagEncryption byte = 0x02
	// DatabaseLookupFlagTypeNormal is a normal lookup (bits 3-2 = 00)
	DatabaseLookupFlagTypeNormal byte = 0x00
	// DatabaseLookupFlagTypeLS is a LeaseSet lookup (bits 3-2 = 01)
	DatabaseLookupFlagTypeLS byte = 0x04
	// DatabaseLookupFlagTypeRI is a RouterInfo lookup (bits 3-2 = 10)
	DatabaseLookupFlagTypeRI byte = 0x08
	// DatabaseLookupFlagTypeExploration is an exploration lookup (bits 3-2 = 11)
	DatabaseLookupFlagTypeExploration byte = 0x0C
	// DatabaseLookupFlagECIES means use ECIES encryption for reply (bit 4 = 1)
	DatabaseLookupFlagECIES byte = 0x10
)

// NewDatabaseLookup creates a new DatabaseLookup message for RouterInfo lookups.
// This creates a simple direct-reply lookup without encryption.
//
// Parameters:
//   - key: The hash of the RouterInfo/LeaseSet to look up
//   - from: The hash of our router (where to send the reply)
//   - lookupType: The type of lookup (DatabaseLookupFlagTypeRI, DatabaseLookupFlagTypeLS, etc.)
//   - excludedPeers: Peers to exclude from DatabaseSearchReply (can be nil)
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
		ReplyTags:      nil,
		ECIESReplyTags: nil,
	}
}

// NewDatabaseLookupWithTunnel creates a DatabaseLookup that sends replies through a tunnel.
//
// Parameters:
//   - key: The hash of the RouterInfo/LeaseSet to look up
//   - replyGateway: The hash of the tunnel gateway router
//   - replyTunnelID: The tunnel ID to send the reply through
//   - lookupType: The type of lookup (DatabaseLookupFlagTypeRI, DatabaseLookupFlagTypeLS, etc.)
//   - excludedPeers: Peers to exclude from DatabaseSearchReply (can be nil)
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
		ReplyTags:      nil,
		ECIESReplyTags: nil,
	}
}

// MarshalBinary serializes the DatabaseLookup message to binary format.
// The format follows the I2NP specification for DatabaseLookup messages.
func (d *DatabaseLookup) MarshalBinary() ([]byte, error) {
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

	if d.hasAnyEncryption() {
		totalSize += 32 + 1 // reply_key + tags count
		if d.IsECIES() {
			totalSize += d.Tags * 8
		} else {
			totalSize += d.Tags * 32
		}
	}

	return totalSize
}

// hasTunnelReply returns true if the tunnel reply flag is set.
func (d *DatabaseLookup) hasTunnelReply() bool {
	return (d.Flags & DatabaseLookupFlagTunnel) != 0
}

// hasEncryption returns true if the encryption flag is set.
func (d *DatabaseLookup) hasEncryption() bool {
	return (d.Flags & DatabaseLookupFlagEncryption) != 0
}

// hasAnyEncryption returns true if either the ElGamal encryption flag (bit 1)
// or the ECIES flag (bit 4) is set. Both indicate that reply_key, tags, and
// reply_tags fields are present in the wire format.
func (d *DatabaseLookup) hasAnyEncryption() bool {
	return d.hasEncryption() || d.IsECIES()
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

// marshalEncryptionFields writes the reply key and session tags into the buffer
// when encryption is requested.
func (d *DatabaseLookup) marshalEncryptionFields(result []byte, offset int) {
	if !d.hasAnyEncryption() {
		return
	}

	copy(result[offset:offset+32], d.ReplyKey[:])
	offset += 32

	result[offset] = byte(d.Tags)
	offset++

	if d.IsECIES() {
		for i := 0; i < d.Tags && i < len(d.ECIESReplyTags); i++ {
			copy(result[offset:offset+8], d.ECIESReplyTags[i].Bytes())
			offset += 8
		}
	} else {
		for i := 0; i < d.Tags && i < len(d.ReplyTags); i++ {
			copy(result[offset:offset+32], d.ReplyTags[i].Bytes())
			offset += 32
		}
	}
}

// Compile-time interface satisfaction checks
var (
	_ DatabaseReader     = (*DatabaseLookup)(nil)
	_ SessionTagProvider = (*DatabaseLookup)(nil)
)
