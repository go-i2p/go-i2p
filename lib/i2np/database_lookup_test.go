package i2np

import (
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/session_key"
	"github.com/go-i2p/common/session_tag"
	"github.com/stretchr/testify/assert"
)

func TestReadDatabaseLookupKeyTooLittleData(t *testing.T) {
	assert := assert.New(t)

	length, key, err := readDatabaseLookupKey([]byte{0x01})
	assert.Equal(0, length)
	assert.Equal(common.Hash{}, key)
	assert.Equal(ERR_DATABASE_LOOKUP_NOT_ENOUGH_DATA, err)
}

func TestReadDatabaseLookupKeyValidData(t *testing.T) {
	assert := assert.New(t)

	data := make([]byte, 32)
	for i := range 31 {
		data[i] = 0x31
	}
	length, key, err := readDatabaseLookupKey(data)
	expected := common.Hash(data)

	assert.Equal(32, length)
	assert.Equal(expected, key)
	assert.Equal(nil, err)
}

func TestReadDatabaseLookupFromTooLittleData(t *testing.T) {
	assert := assert.New(t)

	length := 32
	prev := make([]byte, length)
	data := append(prev, 0x01)

	length, key, err := readDatabaseLookupFrom(length, data)
	assert.Equal(32, length)
	assert.Equal(common.Hash{}, key)
	assert.Equal(ERR_DATABASE_LOOKUP_NOT_ENOUGH_DATA, err)
}

func TestReadDatabaseLookupFromValidData(t *testing.T) {
	assert := assert.New(t)

	length := 32
	prev := make([]byte, length)
	expectedFrom := make([]byte, 32)
	expectedFrom[23] = 0x21
	expectedFrom[29] = 0x37
	data := append(prev, expectedFrom...)
	length, from, err := readDatabaseLookupFrom(length, data)
	expected := common.Hash(expectedFrom)

	assert.Equal(64, length)
	assert.Equal(from, expected)
	assert.Equal(nil, err)
}

func TestReadDatabaseLookupFlagsTooLittleData(t *testing.T) {
	assert := assert.New(t)

	length := 64
	prev := make([]byte, length)
	data := prev

	length, flags, err := readDatabaseLookupFlags(length, data)
	assert.Equal(64, length)
	assert.Equal(byte(0), flags)
	assert.Equal(ERR_DATABASE_LOOKUP_NOT_ENOUGH_DATA, err)
}

func TestReadDatabaseLookupFlagsValidData(t *testing.T) {
	assert := assert.New(t)

	length := 64
	prev := make([]byte, length)
	expected := byte(0x1)
	data := append(prev, expected)
	length, flags, err := readDatabaseLookupFlags(length, data)

	assert.Equal(65, length)
	assert.Equal(flags, expected)
	assert.Equal(nil, err)
}

func TestReadDatabaseLookupReplyTunnelIDTooLittleData(t *testing.T) {
	assert := assert.New(t)

	length := 64
	prev := make([]byte, length)
	flag := byte(0x1)
	data := append(prev, flag)

	excessData := make([]byte, 2)
	excessData[1] = 0x32
	data = append(data, excessData...)
	length, flags, flagsErr := readDatabaseLookupFlags(length, data)
	if flagsErr != nil {
		t.Fatalf("readDatabaseLookupFlags failed: %v", flagsErr)
	}

	length, replyTunnelID, err := readDatabaseLookupReplyTunnelID(flags, length, data)
	assert.Equal(65, length)
	assert.Equal([4]byte{}, replyTunnelID)
	assert.Equal(ERR_DATABASE_LOOKUP_NOT_ENOUGH_DATA, err)
}

func TestReadDatabaseLookupReplyTunnelIDNotIncluded(t *testing.T) {
	assert := assert.New(t)

	length := 64
	data := make([]byte, length+1)
	length, flags, flagsErr := readDatabaseLookupFlags(length, data)
	if flagsErr != nil {
		t.Fatalf("readDatabaseLookupFlags failed: %v", flagsErr)
	}

	length, replyTunnelID, err := readDatabaseLookupReplyTunnelID(flags, length, data)
	assert.Equal(65, length)
	assert.Equal([4]byte{}, replyTunnelID)
	assert.Equal(nil, err)
}

func TestReadDatabaseLookupReplyTunnelIDValidData(t *testing.T) {
	assert := assert.New(t)

	length := 64
	prev := make([]byte, length)
	flag := byte(0x1)
	data := append(prev, flag)

	expected := make([]byte, 4)
	expected[1] = 0x32
	expected[3] = 0x34
	data = append(data, expected...)
	length, flags, flagsErr := readDatabaseLookupFlags(length, data)
	if flagsErr != nil {
		t.Fatalf("readDatabaseLookupFlags failed: %v", flagsErr)
	}

	length, replyTunnelID, err := readDatabaseLookupReplyTunnelID(flags, length, data)
	assert.Equal(69, length)
	assert.Equal([4]byte(expected), replyTunnelID)
	assert.Equal(nil, err)
}

func TestReadDatabaseLookupSizeTooLittleData(t *testing.T) {
	assert := assert.New(t)

	length := 65
	data := make([]byte, length)
	data = append(data, 0x2)

	length, size, err := readDatabaseLookupSize(length, data)
	assert.Equal(65, length)
	assert.Equal(0, size)
	assert.Equal(ERR_DATABASE_LOOKUP_NOT_ENOUGH_DATA, err)
}

func TestReadDatabaseLookupSizeValidData(t *testing.T) {
	assert := assert.New(t)

	length := 65
	data := make([]byte, length)
	// Use valid size within I2P protocol limit (0-512 peers)
	// 0x01, 0xFF = 511 (just under the 512 limit)
	expectedSizeData := []byte{0x01, 0xFF}
	data = append(data, expectedSizeData...)

	length, size, err := readDatabaseLookupSize(length, data)
	assert.Equal(67, length)
	assert.Equal(common.Integer(expectedSizeData).Int(), size)
	assert.Equal(nil, err)
}

func TestReadDatabaseLookupExcludedPeersTooLittleData(t *testing.T) {
	assert := assert.New(t)

	length := 65
	data := make([]byte, length)
	sizeData := []byte{0x0, 0x3}
	data = append(data, sizeData...)
	data = append(data, 0x23)

	length, size, sizeErr := readDatabaseLookupSize(length, data)
	if sizeErr != nil {
		t.Fatalf("readDatabaseLookupSize failed: %v", sizeErr)
	}
	length, excludedPeers, err := readDatabaseLookupExcludedPeers(length, data, size)
	assert.Equal([]common.Hash{}, excludedPeers)
	assert.Equal(67, length)
	assert.Equal(ERR_DATABASE_LOOKUP_NOT_ENOUGH_DATA, err)
}

func TestReadDatabaseLookupExcludedPeersZeroSize(t *testing.T) {
	assert := assert.New(t)

	length := 65
	data := make([]byte, length)
	sizeData := []byte{0x0, 0x0}
	data = append(data, sizeData...)
	data = append(data, 0x23)

	length, size, err := readDatabaseLookupSize(length, data)

	var expectedExcludedPeers []common.Hash

	length, excludedPeers, err := readDatabaseLookupExcludedPeers(length, data, size)
	assert.Equal(expectedExcludedPeers, excludedPeers)
	assert.Equal(67, length)
	assert.Equal(nil, err)
}

func TestReadDatabaseLookupExcludedPeersValidData(t *testing.T) {
	assert := assert.New(t)

	length := 65
	data := make([]byte, length)
	sizeData := []byte{0x0, 0x3}
	data = append(data, sizeData...)

	length, size, err := readDatabaseLookupSize(length, data)

	var expectedExcludedPeers []common.Hash
	for i := range size {
		peer := make([]byte, 32)
		// random data:
		peer[i+1] = 0x43
		peer[i+23] = 0x89
		expectedExcludedPeers = append(expectedExcludedPeers, common.Hash(peer))
		data = append(data, peer...)
	}

	length, excludedPeers, err := readDatabaseLookupExcludedPeers(length, data, size)
	assert.Equal(expectedExcludedPeers, excludedPeers)
	assert.Equal(67+32*size, length)
	assert.Equal(nil, err)
}

func TestReadDatabaseLookupReplyKeyTooLittleData(t *testing.T) {
	assert := assert.New(t)

	length := 67
	data := make([]byte, length)
	data = append(data, 0x2)

	length, replyKey, err := readDatabaseLookupReplyKey(length, data)
	assert.Equal(67, length)
	assert.Equal(session_key.SessionKey{}, replyKey)
	assert.Equal(ERR_DATABASE_LOOKUP_NOT_ENOUGH_DATA, err)
}

func TestReadDatabaseLookupReplyKeyValidData(t *testing.T) {
	assert := assert.New(t)

	length := 67
	data := make([]byte, length)
	expectedReplyKeyData := make([]byte, 32)
	expectedReplyKeyData[3] = 0x31
	expectedReplyKey := session_key.SessionKey(expectedReplyKeyData)
	data = append(data, expectedReplyKeyData...)

	length, replyKey, err := readDatabaseLookupReplyKey(length, data)
	assert.Equal(67+32, length)
	assert.Equal(expectedReplyKey, replyKey)
	assert.Equal(nil, err)
}

func TestReadDatabaseLookupTagsTooLittleData(t *testing.T) {
	assert := assert.New(t)

	length := 99
	data := make([]byte, length)

	length, tags, err := readDatabaseLookupTags(length, data)
	assert.Equal(99, length)
	assert.Equal(0, tags)
	assert.Equal(ERR_DATABASE_LOOKUP_NOT_ENOUGH_DATA, err)
}

func TestReadDatabaseLookupTagsValidData(t *testing.T) {
	assert := assert.New(t)

	length := 99
	data := make([]byte, length)
	expected := 121
	data = append(data, byte(expected))

	length, tags, err := readDatabaseLookupTags(length, data)
	assert.Equal(100, length)
	assert.Equal(expected, tags)
	assert.Equal(nil, err)
}

func TestReadDatabaseLookupReplyTagsTooLittleData(t *testing.T) {
	assert := assert.New(t)

	length := 99
	data := make([]byte, length)
	tags := 10
	data = append(data, byte(tags))
	data = append(data, 0x34)

	length, tags, err := readDatabaseLookupTags(length, data)
	length, replyTags, err := readDatabaseLookupReplyTags(length, data, tags)
	assert.Equal(100, length)
	assert.Equal([]session_tag.SessionTag{}, replyTags)
	assert.Equal(ERR_DATABASE_LOOKUP_NOT_ENOUGH_DATA, err)
}

func TestReadDatabaseLookupReplyTagsZeroTags(t *testing.T) {
	assert := assert.New(t)

	length := 99
	data := make([]byte, length)
	tags := 0
	data = append(data, byte(tags))
	data = append(data, 0x23)

	length, tags, err := readDatabaseLookupTags(length, data)

	var expectedReplyTags []session_tag.SessionTag

	length, replyTags, err := readDatabaseLookupReplyTags(length, data, tags)
	assert.Equal(expectedReplyTags, replyTags)
	assert.Equal(100, length)
	assert.Equal(nil, err)
}

func TestReadDatabaseLookupReplyTagsValidData(t *testing.T) {
	assert := assert.New(t)

	length := 99
	data := make([]byte, length)
	tags := 10
	data = append(data, byte(tags))

	length, tags, err := readDatabaseLookupTags(length, data)

	var expectedReplyTags []session_tag.SessionTag
	for i := range tags {
		tag := make([]byte, 32)
		// random data:
		tag[i+1] = 0x43
		tag[i+5] = 0x89
		sessionTag, err := session_tag.NewSessionTagFromBytes(tag)
		if err != nil {
			assert.Fail("Failed to create session tag from bytes: %v", err)
			return
		}
		expectedReplyTags = append(expectedReplyTags, sessionTag)
		// expectedReplyTags = append(expectedReplyTags, session_tag.SessionTag(tag))
		data = append(data, tag...)
	}

	length, replyTags, err := readDatabaseLookupReplyTags(length, data, tags)
	assert.Equal(expectedReplyTags, replyTags)
	assert.Equal(100+32*tags, length)
	assert.Equal(nil, err)
}

func TestReadDatabaseLookupTooLittleData(t *testing.T) {
	assert := assert.New(t)

	// Build a message with encryption flag set but not enough data for
	// the encryption fields (reply key, tags, reply tags).
	// Key (32) + From (32) + Flags (1) + Size (2) = 67 bytes total,
	// plus some extra bytes that are NOT enough for a full reply key.
	var data []byte

	// Key (32 bytes)
	data = append(data, make([]byte, 32)...)

	// From (32 bytes)
	data = append(data, make([]byte, 32)...)

	// Flags: encryption flag set (bit 1 = 0x02)
	data = append(data, DatabaseLookupFlagEncryption)

	// Size: 0 excluded peers
	data = append(data, 0x00, 0x00)

	// Only 10 bytes of reply key data — not enough for a 32-byte key
	data = append(data, make([]byte, 10)...)

	_, err := ReadDatabaseLookup(data)
	assert.Equal(ERR_DATABASE_LOOKUP_NOT_ENOUGH_DATA, err)
}

func TestReadDatabaseLookupValidData(t *testing.T) {
	assert := assert.New(t)

	data := make([]byte, 32)
	for i := range 31 {
		data[i] = 0x31
	}
	expectedKey := common.Hash(data)

	from := make([]byte, 32)
	from[14] = 0x69
	from[27] = 0x15
	data = append(data, from...)
	expectedFrom := common.Hash(from)

	// Flags: tunnel reply (bit 0) AND encryption (bit 1) = 0x03
	// Encryption flag must be set for encryption fields to be parsed.
	expectedFlags := byte(0x03)
	data = append(data, expectedFlags)

	tunnelIDData := make([]byte, 4)
	tunnelIDData[0] = 0xff
	tunnelIDData[2] = 0xf2
	data = append(data, tunnelIDData...)
	expectedTunnelID := [4]byte(tunnelIDData)

	sizeData := []byte{0x0, 0xf}
	data = append(data, sizeData...)
	expectedSize := common.Integer(sizeData).Int()

	var expectedExcludedPeers []common.Hash
	for i := range expectedSize {
		peer := make([]byte, 32)
		// random data:
		peer[i+5] = 0xdd
		peer[i+13] = 0x35
		expectedExcludedPeers = append(expectedExcludedPeers, common.Hash(peer))
		data = append(data, peer...)
	}

	replyKeyData := make([]byte, 32)
	replyKeyData[6] = 0x11
	replyKeyData[14] = 0x13
	data = append(data, replyKeyData...)
	expectedReplyKey := session_key.SessionKey(replyKeyData)

	expectedTags := 15
	data = append(data, byte(expectedTags))

	var expectedReplyTags []session_tag.SessionTag
	for i := range expectedTags {
		tag := make([]byte, 32)
		// random data:
		tag[i+3] = 0x22
		tag[i+13] = 0x11
		sessionTag, err := session_tag.NewSessionTagFromBytes(tag)
		if err != nil {
			assert.Fail("Failed to create session tag from bytes: %v", err)
			return
		}
		expectedReplyTags = append(expectedReplyTags, sessionTag)
		data = append(data, tag...)
	}
	databaseLookup, err := ReadDatabaseLookup(data)
	assert.Equal(expectedKey, databaseLookup.Key)
	assert.Equal(expectedFrom, databaseLookup.From)
	assert.Equal(expectedFlags, databaseLookup.Flags)
	assert.Equal(expectedTunnelID, databaseLookup.ReplyTunnelID)
	assert.Equal(expectedSize, databaseLookup.Size)
	assert.Equal(expectedExcludedPeers, databaseLookup.ExcludedPeers)
	assert.Equal(expectedReplyKey, databaseLookup.ReplyKey)
	assert.Equal(expectedTags, databaseLookup.Tags)
	assert.Equal(expectedReplyTags, databaseLookup.ReplyTags)
	assert.Equal(err, nil)
}

func TestReadDatabaseLookupECIESReplyTagsTooLittleData(t *testing.T) {
	assert := assert.New(t)

	length := 99
	data := make([]byte, length)
	tags := 3
	// Only add 2 bytes of tag data, but we need 3*8=24
	data = append(data, make([]byte, 2)...)

	length, replyTags, err := readDatabaseLookupECIESReplyTags(length, data, tags)
	assert.Equal(99, length)
	assert.Equal([]session_tag.ECIESSessionTag{}, replyTags)
	assert.Equal(ERR_DATABASE_LOOKUP_NOT_ENOUGH_DATA, err)
}

func TestReadDatabaseLookupECIESReplyTagsZeroTags(t *testing.T) {
	assert := assert.New(t)

	length := 99
	data := make([]byte, length)
	tags := 0

	var expectedReplyTags []session_tag.ECIESSessionTag

	length, replyTags, err := readDatabaseLookupECIESReplyTags(length, data, tags)
	assert.Equal(expectedReplyTags, replyTags)
	assert.Equal(99, length)
	assert.Nil(err)
}

func TestReadDatabaseLookupECIESReplyTagsValidData(t *testing.T) {
	assert := assert.New(t)

	length := 50
	data := make([]byte, length)
	tags := 3

	var expectedReplyTags []session_tag.ECIESSessionTag
	for i := 0; i < tags; i++ {
		tag := make([]byte, 8)
		tag[0] = byte(i + 1)
		tag[3] = 0xAB
		eciesTag, err := session_tag.NewECIESSessionTagFromBytes(tag)
		if err != nil {
			assert.Fail("Failed to create ECIES session tag: %v", err)
			return
		}
		expectedReplyTags = append(expectedReplyTags, eciesTag)
		data = append(data, tag...)
	}

	length, replyTags, err := readDatabaseLookupECIESReplyTags(length, data, tags)
	assert.Equal(expectedReplyTags, replyTags)
	assert.Equal(50+8*tags, length)
	assert.Nil(err)
}

func TestReadDatabaseLookupWithECIESFlag(t *testing.T) {
	assert := assert.New(t)

	// Build a complete DatabaseLookup message with ECIESFlag set
	// Key (32 bytes)
	data := make([]byte, 32)
	for i := range 31 {
		data[i] = 0x31
	}
	expectedKey := common.Hash(data)

	// From (32 bytes)
	from := make([]byte, 32)
	from[14] = 0x69
	from[27] = 0x15
	data = append(data, from...)
	expectedFrom := common.Hash(from)

	// Flags: deliveryFlag=1 (bit 0) + ECIESFlag=1 (bit 4) = 0x11
	expectedFlags := byte(0x11)
	data = append(data, expectedFlags)

	// ReplyTunnelID (4 bytes, because deliveryFlag=1)
	tunnelIDData := make([]byte, 4)
	tunnelIDData[0] = 0xff
	tunnelIDData[2] = 0xf2
	data = append(data, tunnelIDData...)
	expectedTunnelID := [4]byte(tunnelIDData)

	// Size (2 bytes) = 2 excluded peers
	sizeData := []byte{0x0, 0x02}
	data = append(data, sizeData...)
	expectedSize := common.Integer(sizeData).Int()

	// ExcludedPeers (2 * 32 bytes)
	var expectedExcludedPeers []common.Hash
	for i := 0; i < expectedSize; i++ {
		peer := make([]byte, 32)
		peer[5] = byte(0xDD + i)
		peer[13] = 0x35
		expectedExcludedPeers = append(expectedExcludedPeers, common.Hash(peer))
		data = append(data, peer...)
	}

	// ReplyKey (32 bytes)
	replyKeyData := make([]byte, 32)
	replyKeyData[6] = 0x11
	replyKeyData[14] = 0x13
	data = append(data, replyKeyData...)
	expectedReplyKey := session_key.SessionKey(replyKeyData)

	// Tags count = 2
	expectedTags := 2
	data = append(data, byte(expectedTags))

	// ECIES reply tags (2 * 8 bytes, not 32!)
	var expectedECIESTags []session_tag.ECIESSessionTag
	for i := 0; i < expectedTags; i++ {
		tag := make([]byte, 8)
		tag[0] = byte(i + 1)
		tag[3] = 0xCC
		tag[7] = byte(0xA0 + i)
		eciesTag, err := session_tag.NewECIESSessionTagFromBytes(tag)
		if err != nil {
			assert.Fail("Failed to create ECIES session tag: %v", err)
			return
		}
		expectedECIESTags = append(expectedECIESTags, eciesTag)
		data = append(data, tag...)
	}

	databaseLookup, err := ReadDatabaseLookup(data)
	assert.Nil(err)
	assert.Equal(expectedKey, databaseLookup.Key)
	assert.Equal(expectedFrom, databaseLookup.From)
	assert.Equal(expectedFlags, databaseLookup.Flags)
	assert.Equal(expectedTunnelID, databaseLookup.ReplyTunnelID)
	assert.Equal(expectedSize, databaseLookup.Size)
	assert.Equal(expectedExcludedPeers, databaseLookup.ExcludedPeers)
	assert.Equal(expectedReplyKey, databaseLookup.ReplyKey)
	assert.Equal(expectedTags, databaseLookup.Tags)
	assert.True(databaseLookup.IsECIES())
	// ElGamal tags should be nil/empty since ECIESFlag is set
	assert.Nil(databaseLookup.ReplyTags)
	// ECIES tags should be populated
	assert.Equal(expectedECIESTags, databaseLookup.ECIESReplyTags)
	assert.Equal(2, len(databaseLookup.ECIESReplyTags))
	// Verify each tag is 8 bytes
	for _, tag := range databaseLookup.ECIESReplyTags {
		assert.Equal(8, len(tag.Bytes()))
	}
}

// TestReadDatabaseLookupNoEncryptionFlags verifies that a DatabaseLookup message
// without encryption flags (bit 1 and bit 4 both unset) parses correctly and does
// NOT attempt to read encryption fields past the excluded peers.
// This is the most common case on the I2P network.
func TestReadDatabaseLookupNoEncryptionFlags(t *testing.T) {
	assert := assert.New(t)

	// Build a minimal unencrypted DatabaseLookup:
	// Key (32) + From (32) + Flags (1) + Size (2) = 67 bytes
	// Flags = 0x00: direct reply, no encryption, normal lookup
	var data []byte

	// Key
	key := make([]byte, 32)
	key[0] = 0xAA
	expectedKey := common.Hash(key)
	data = append(data, key...)

	// From
	from := make([]byte, 32)
	from[0] = 0xBB
	expectedFrom := common.Hash(from)
	data = append(data, from...)

	// Flags: no encryption, no tunnel, normal lookup
	expectedFlags := byte(0x00)
	data = append(data, expectedFlags)

	// Size: 0 excluded peers
	data = append(data, 0x00, 0x00)

	databaseLookup, err := ReadDatabaseLookup(data)
	assert.Nil(err, "Unencrypted DatabaseLookup should parse without error")
	assert.Equal(expectedKey, databaseLookup.Key)
	assert.Equal(expectedFrom, databaseLookup.From)
	assert.Equal(expectedFlags, databaseLookup.Flags)
	assert.Equal(0, databaseLookup.Size)
	// Encryption fields should be zero-valued since no encryption flag was set
	assert.Equal(session_key.SessionKey{}, databaseLookup.ReplyKey)
	assert.Equal(0, databaseLookup.Tags)
	assert.Nil(databaseLookup.ReplyTags)
	assert.Nil(databaseLookup.ECIESReplyTags)
}

// TestReadDatabaseLookupNoEncryptionWithExcludedPeers verifies parsing of
// an unencrypted lookup with excluded peers — data ends right after the peers
// and no garbage is read as encryption fields.
func TestReadDatabaseLookupNoEncryptionWithExcludedPeers(t *testing.T) {
	assert := assert.New(t)

	var data []byte

	// Key (32 bytes)
	key := make([]byte, 32)
	key[0] = 0x01
	data = append(data, key...)

	// From (32 bytes)
	from := make([]byte, 32)
	from[0] = 0x02
	data = append(data, from...)

	// Flags: tunnel reply, NO encryption, RI lookup (bits: 0b00001001 = 0x09)
	flags := byte(DatabaseLookupFlagTunnel | DatabaseLookupFlagTypeRI)
	data = append(data, flags)

	// ReplyTunnelID (4 bytes, since tunnel flag is set)
	data = append(data, 0x00, 0x00, 0x01, 0x00)

	// Size: 2 excluded peers
	data = append(data, 0x00, 0x02)

	// 2 excluded peers (2 * 32 bytes)
	peer1 := make([]byte, 32)
	peer1[0] = 0xCC
	data = append(data, peer1...)

	peer2 := make([]byte, 32)
	peer2[0] = 0xDD
	data = append(data, peer2...)

	// No encryption data follows — this is the end of the message.
	// Previously the parser would try to read past here and fail.

	databaseLookup, err := ReadDatabaseLookup(data)
	assert.Nil(err, "Unencrypted DatabaseLookup with excluded peers should parse without error")
	assert.Equal(flags, databaseLookup.Flags)
	assert.Equal(2, databaseLookup.Size)
	assert.Equal(2, len(databaseLookup.ExcludedPeers))
	// Encryption fields must remain zero/nil
	assert.Equal(session_key.SessionKey{}, databaseLookup.ReplyKey)
	assert.Equal(0, databaseLookup.Tags)
	assert.Nil(databaseLookup.ReplyTags)
	assert.Nil(databaseLookup.ECIESReplyTags)
}

// TestReadDatabaseLookupWithEncryptionFlagStillWorks verifies that lookups
// WITH the encryption flag set still parse encryption fields correctly.
func TestReadDatabaseLookupWithEncryptionFlagStillWorks(t *testing.T) {
	assert := assert.New(t)

	var data []byte

	// Key (32 bytes)
	key := make([]byte, 32)
	key[0] = 0x11
	data = append(data, key...)

	// From (32 bytes)
	from := make([]byte, 32)
	from[0] = 0x22
	data = append(data, from...)

	// Flags: encryption flag set (bit 1), direct reply
	flags := byte(DatabaseLookupFlagEncryption)
	data = append(data, flags)

	// Size: 0 excluded peers
	data = append(data, 0x00, 0x00)

	// ReplyKey (32 bytes)
	replyKey := make([]byte, 32)
	replyKey[0] = 0xFF
	expectedReplyKey := session_key.SessionKey(replyKey)
	data = append(data, replyKey...)

	// Tags: 1
	data = append(data, 0x01)

	// 1 ElGamal reply tag (32 bytes)
	tagData := make([]byte, 32)
	tagData[0] = 0xEE
	data = append(data, tagData...)

	databaseLookup, err := ReadDatabaseLookup(data)
	assert.Nil(err, "Encrypted DatabaseLookup should parse without error")
	assert.Equal(flags, databaseLookup.Flags)
	assert.True(databaseLookup.hasEncryption())
	assert.Equal(expectedReplyKey, databaseLookup.ReplyKey)
	assert.Equal(1, databaseLookup.Tags)
	assert.Equal(1, len(databaseLookup.ReplyTags))
}

// TestReadDatabaseLookupExplorationNoEncryption verifies an exploration lookup
// (bits 3-2 = 11) without encryption parses correctly.
func TestReadDatabaseLookupExplorationNoEncryption(t *testing.T) {
	assert := assert.New(t)

	var data []byte

	// Key (32 bytes)
	data = append(data, make([]byte, 32)...)

	// From (32 bytes)
	data = append(data, make([]byte, 32)...)

	// Flags: exploration, no encryption
	flags := byte(DatabaseLookupFlagTypeExploration)
	data = append(data, flags)

	// Size: 1 excluded peer (all zeros = exploration marker)
	data = append(data, 0x00, 0x01)
	data = append(data, make([]byte, 32)...) // all-zero hash

	databaseLookup, err := ReadDatabaseLookup(data)
	assert.Nil(err, "Exploration lookup without encryption should parse without error")
	assert.Equal(flags, databaseLookup.Flags)
	assert.Equal(1, databaseLookup.Size)
	// No encryption fields should be populated
	assert.Equal(session_key.SessionKey{}, databaseLookup.ReplyKey)
	assert.Equal(0, databaseLookup.Tags)
}
