package i2np

import (
	"errors"

	"github.com/sirupsen/logrus"

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
	Key           common.Hash
	From          common.Hash
	Flags         byte
	ReplyTunnelID [4]byte
	Size          int
	ExcludedPeers []common.Hash
	ReplyKey      session_key.SessionKey
	Tags          int
	ReplyTags     []session_tag.SessionTag
}

var ERR_DATABASE_LOOKUP_NOT_ENOUGH_DATA = errors.New("not enough i2np database lookup data")

func ReadDatabaseLookup(data []byte) (DatabaseLookup, error) {
	log.Debug("Reading DatabaseLookup")
	databaseLookup := DatabaseLookup{}

	length, key, err := readDatabaseLookupKey(data)
	if err != nil {
		log.WithError(err).Error("Failed to read Key")
		return databaseLookup, err
	}
	databaseLookup.Key = key

	length, from, err := readDatabaseLookupFrom(length, data)
	if err != nil {
		log.WithError(err).Error("Failed to read From")
		return databaseLookup, err
	}
	databaseLookup.From = from

	length, flags, err := readDatabaseLookupFlags(length, data)
	if err != nil {
		log.WithError(err).Error("Failed to read Flags")
		return databaseLookup, err
	}
	databaseLookup.Flags = flags

	length, replyTunnelID, err := readDatabaseLookupReplyTunnelID(flags, length, data)
	if err != nil {
		log.WithError(err).Error("Failed to read ReplyTunnelID")
		return databaseLookup, err
	}
	databaseLookup.ReplyTunnelID = replyTunnelID

	length, size, err := readDatabaseLookupSize(length, data)
	if err != nil {
		log.WithError(err).Error("Failed to read Size")
		return databaseLookup, err
	}
	databaseLookup.Size = size

	length, excludedPeers, err := readDatabaseLookupExcludedPeers(length, data, size)
	if err != nil {
		log.WithError(err).Error("Failed to read ExcludedPeers")
		return databaseLookup, err
	}
	databaseLookup.ExcludedPeers = excludedPeers

	length, reply_key, err := readDatabaseLookupReplyKey(length, data)
	if err != nil {
		log.WithError(err).Error("Failed to read ReplyKey")
		return databaseLookup, err
	}
	databaseLookup.ReplyKey = reply_key

	length, tags, err := readDatabaseLookupTags(length, data)
	if err != nil {
		log.WithError(err).Error("Failed to read Tags")
		return databaseLookup, err
	}
	databaseLookup.Tags = tags

	length, reply_tags, err := readDatabaseLookupReplyTags(length, data, tags)
	if err != nil {
		log.WithError(err).Error("Failed to read ReplyTags")
		return databaseLookup, err
	}
	databaseLookup.ReplyTags = reply_tags

	log.Debug("DatabaseLookup read successfully")
	return databaseLookup, nil
}

func readDatabaseLookupKey(data []byte) (int, common.Hash, error) {
	if len(data) < 32 {
		return 0, common.Hash{}, ERR_DATABASE_LOOKUP_NOT_ENOUGH_DATA
	}

	key := common.Hash(data[:32])
	log.WithFields(logrus.Fields{
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
	log.WithFields(logrus.Fields{
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

	log.WithFields(logrus.Fields{
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
	log.WithFields(logrus.Fields{
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
	log.WithFields(logrus.Fields{
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

	log.WithFields(logrus.Fields{
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

	log.WithFields(logrus.Fields{
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

	log.WithFields(logrus.Fields{
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

	log.WithFields(logrus.Fields{
		"at":         "i2np.database_lookup.readDatabaseLookupReplyTags",
		"reply_tags": reply_tags,
	}).Debug("parsed_database_lookup_reply_tags")
	return length + tags*32, reply_tags, nil
}
