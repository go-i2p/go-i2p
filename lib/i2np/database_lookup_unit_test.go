package i2np

import (
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/session_key"
	"github.com/go-i2p/common/session_tag"
	"github.com/stretchr/testify/assert"
)

// assertNoEncryptionFields verifies encryption-related fields are zero/nil.
func assertNoEncryptionFields(t *testing.T, dl DatabaseLookup) {
	t.Helper()
	assert := assert.New(t)
	assert.Equal(session_key.SessionKey{}, dl.ReplyKey)
	assert.Equal(0, dl.Tags)
	assert.Nil(dl.ReplyTags)
	assert.Nil(dl.ECIESReplyTags)
}

// buildLookupHeader builds a DatabaseLookup message prefix: Key(32)+From(32)+Flags(1)
// plus optional TunnelID(4)+Size(2). keyByte/fromByte seed position 0 of Key/From.
func buildLookupHeader(keyByte, fromByte, flags byte, tunnelID []byte, sizeBytes [2]byte) []byte {
	key := make([]byte, 32)
	key[0] = keyByte
	from := make([]byte, 32)
	from[0] = fromByte
	data := append(key, from...)
	data = append(data, flags)
	if tunnelID != nil {
		data = append(data, tunnelID...)
	}
	data = append(data, sizeBytes[0], sizeBytes[1])
	return data
}

// appendExcludedPeers appends count 32-byte peers with peer[0] seeded.
func appendExcludedPeers(data []byte, count int, seeds ...byte) ([]byte, []common.Hash) {
	var peers []common.Hash
	for i := 0; i < count; i++ {
		peer := make([]byte, 32)
		if i < len(seeds) {
			peer[0] = seeds[i]
		}
		peers = append(peers, common.Hash(peer))
		data = append(data, peer...)
	}
	return data, peers
}

// lookupExpected holds expected values from a full DatabaseLookup message build.
type lookupExpected struct {
	Key      common.Hash
	From     common.Hash
	Flags    byte
	TunnelID [4]byte
	Size     int
	Peers    []common.Hash
	ReplyKey session_key.SessionKey
	Tags     int
}

// buildFullLookupMessage builds a DatabaseLookup wire message with key, from, flags,
// tunnel ID, excluded peers, and reply key. Returns data and expected values.
func buildFullLookupMessage(flags byte, peerCount int) ([]byte, lookupExpected) {
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

	data = append(data, flags)

	tunnelIDData := make([]byte, 4)
	tunnelIDData[0] = 0xff
	tunnelIDData[2] = 0xf2
	data = append(data, tunnelIDData...)
	expectedTunnelID := [4]byte(tunnelIDData)

	sizeData := []byte{0x0, byte(peerCount)}
	data = append(data, sizeData...)
	expectedSize := common.Integer(sizeData).Int()

	var expectedExcludedPeers []common.Hash
	for i := 0; i < expectedSize; i++ {
		peer := make([]byte, 32)
		peer[5] = byte(0xDD + i)
		peer[13] = 0x35
		expectedExcludedPeers = append(expectedExcludedPeers, common.Hash(peer))
		data = append(data, peer...)
	}

	replyKeyData := make([]byte, 32)
	replyKeyData[6] = 0x11
	replyKeyData[14] = 0x13
	data = append(data, replyKeyData...)
	expectedReplyKey := session_key.SessionKey(replyKeyData)

	return data, lookupExpected{
		Key:      expectedKey,
		From:     expectedFrom,
		Flags:    flags,
		TunnelID: expectedTunnelID,
		Size:     expectedSize,
		Peers:    expectedExcludedPeers,
		ReplyKey: expectedReplyKey,
	}
}

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

	// Build message with encryption flag set but not enough data for encryption fields
	data := buildLookupHeader(0x00, 0x00, DatabaseLookupFlagEncryption, nil, [2]byte{0x00, 0x00})
	// Only 10 bytes of reply key data — not enough for a 32-byte key
	data = append(data, make([]byte, 10)...)

	_, err := ReadDatabaseLookup(data)
	assert.Equal(ERR_DATABASE_LOOKUP_NOT_ENOUGH_DATA, err)
}

func TestReadDatabaseLookupValidData(t *testing.T) {
	assert := assert.New(t)

	data, exp := buildFullLookupMessage(0x03, 15)

	expectedTags := 15
	data = append(data, byte(expectedTags))

	var expectedReplyTags []session_tag.SessionTag
	for i := range expectedTags {
		tag := make([]byte, 32)
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
	assert.Equal(exp.Key, databaseLookup.Key)
	assert.Equal(exp.From, databaseLookup.From)
	assert.Equal(exp.Flags, databaseLookup.Flags)
	assert.Equal(exp.TunnelID, databaseLookup.ReplyTunnelID)
	assert.Equal(exp.Size, databaseLookup.Size)
	assert.Equal(exp.Peers, databaseLookup.ExcludedPeers)
	assert.Equal(exp.ReplyKey, databaseLookup.ReplyKey)
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

	// Flags: deliveryFlag=1 (bit 0) + ECIESFlag=1 (bit 4) = 0x11
	data, exp := buildFullLookupMessage(0x11, 2)

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
	assert.Equal(exp.Key, databaseLookup.Key)
	assert.Equal(exp.From, databaseLookup.From)
	assert.Equal(exp.Flags, databaseLookup.Flags)
	assert.Equal(exp.TunnelID, databaseLookup.ReplyTunnelID)
	assert.Equal(exp.Size, databaseLookup.Size)
	assert.Equal(exp.Peers, databaseLookup.ExcludedPeers)
	assert.Equal(exp.ReplyKey, databaseLookup.ReplyKey)
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

	data := buildLookupHeader(0xAA, 0xBB, 0x00, nil, [2]byte{0x00, 0x00})
	expectedKey := common.Hash(data[:32])
	expectedFrom := common.Hash(data[32:64])

	databaseLookup, err := ReadDatabaseLookup(data)
	assert.Nil(err, "Unencrypted DatabaseLookup should parse without error")
	assert.Equal(expectedKey, databaseLookup.Key)
	assert.Equal(expectedFrom, databaseLookup.From)
	assert.Equal(byte(0x00), databaseLookup.Flags)
	assert.Equal(0, databaseLookup.Size)
	assertNoEncryptionFields(t, databaseLookup)
}

// TestReadDatabaseLookupNoEncryptionWithExcludedPeers verifies parsing of
// an unencrypted lookup with excluded peers — data ends right after the peers
// and no garbage is read as encryption fields.
func TestReadDatabaseLookupNoEncryptionWithExcludedPeers(t *testing.T) {
	assert := assert.New(t)

	flags := byte(DatabaseLookupFlagTunnel | DatabaseLookupFlagTypeRI)
	data := buildLookupHeader(0x01, 0x02, flags, []byte{0x00, 0x00, 0x01, 0x00}, [2]byte{0x00, 0x02})
	data, _ = appendExcludedPeers(data, 2, 0xCC, 0xDD)

	databaseLookup, err := ReadDatabaseLookup(data)
	assert.Nil(err, "Unencrypted DatabaseLookup with excluded peers should parse without error")
	assert.Equal(flags, databaseLookup.Flags)
	assert.Equal(2, databaseLookup.Size)
	assert.Equal(2, len(databaseLookup.ExcludedPeers))
	assertNoEncryptionFields(t, databaseLookup)
}

// TestReadDatabaseLookupWithEncryptionFlagStillWorks verifies that lookups
// WITH the encryption flag set still parse encryption fields correctly.
func TestReadDatabaseLookupWithEncryptionFlagStillWorks(t *testing.T) {
	assert := assert.New(t)

	flags := byte(DatabaseLookupFlagEncryption)
	data := buildLookupHeader(0x11, 0x22, flags, nil, [2]byte{0x00, 0x00})

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

	flags := byte(DatabaseLookupFlagTypeExploration)
	data := buildLookupHeader(0x00, 0x00, flags, nil, [2]byte{0x00, 0x01})
	data = append(data, make([]byte, 32)...) // all-zero hash exploration marker

	databaseLookup, err := ReadDatabaseLookup(data)
	assert.Nil(err, "Exploration lookup without encryption should parse without error")
	assert.Equal(flags, databaseLookup.Flags)
	assert.Equal(1, databaseLookup.Size)
	assertNoEncryptionFields(t, databaseLookup)
}
