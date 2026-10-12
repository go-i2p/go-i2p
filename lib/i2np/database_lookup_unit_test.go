// Tests for I2NP DatabaseLookup message wire-format parsing.
package i2np

// These tests validate the DatabaseLookup wire-format parsing required by the
// I2NP specification (https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/i2np.rst): each field
// is read at the correct offset, conditional fields (reply_tunnelId, ECIES
// reply fields) appear only when their flag is set, and malformed or
// truncated input is rejected.

import (
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/session_key"
	"github.com/go-i2p/common/session_tag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// assertNoEncryptionFields verifies encryption-related fields are zero/nil.
func assertNoEncryptionFields(t *testing.T, dl DatabaseLookup) {
	t.Helper()
	assert := assert.New(t)
	assert.Equal(session_key.SessionKey{}, dl.ReplyKey)
	assert.Equal(0, dl.Tags)
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

// TestReadDatabaseLookupKeyTooLittleData validates that reading the 32-byte
// key rejects input shorter than 32 bytes.
func TestReadDatabaseLookupKeyTooLittleData(t *testing.T) {
	assert := assert.New(t)

	length, key, err := readDatabaseLookupKey([]byte{0x01})
	assert.Equal(0, length)
	assert.Equal(common.Hash{}, key)
	assert.Equal(ErrDatabaseLookupNotEnoughData, err)
}

// TestReadDatabaseLookupKeyValidData validates that a 32-byte key is read
// verbatim and advances the offset by 32.
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

// TestReadDatabaseLookupFromTooLittleData validates that reading the 32-byte
// "from" router hash rejects input shorter than 32 bytes.
func TestReadDatabaseLookupFromTooLittleData(t *testing.T) {
	assert := assert.New(t)

	length := 32
	prev := make([]byte, length)
	data := append(prev, 0x01)

	length, key, err := readDatabaseLookupFrom(length, data)
	assert.Equal(32, length)
	assert.Equal(common.Hash{}, key)
	assert.Equal(ErrDatabaseLookupNotEnoughData, err)
}

// TestReadDatabaseLookupFromValidData validates that the 32-byte From field
// (the identity hash of the requesting router) is parsed as a common.Hash.
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

// TestReadDatabaseLookupFlagsTooLittleData validates that the 1-byte Flags
// field is rejected with ErrDatabaseLookupNotEnoughData when the buffer is
// exhausted.
func TestReadDatabaseLookupFlagsTooLittleData(t *testing.T) {
	assert := assert.New(t)

	length := 64
	prev := make([]byte, length)
	data := prev

	length, flags, err := readDatabaseLookupFlags(length, data)
	assert.Equal(64, length)
	assert.Equal(byte(0), flags)
	assert.Equal(ErrDatabaseLookupNotEnoughData, err)
}

// TestReadDatabaseLookupFlagsValidData validates that the 1-byte Flags field
// is parsed verbatim (here 0x01 = tunnel delivery, normal lookup type).
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

// TestReadDatabaseLookupReplyTunnelIDTooLittleData validates that reading the
// 4-byte reply tunnel ID rejects input shorter than 4 bytes when the tunnel
// delivery flag is set.
func TestReadDatabaseLookupReplyTunnelIDTooLittleData(t *testing.T) {
	assert := assert.New(t)

	length := 64
	prev := make([]byte, length)
	flag := byte(0x1)
	data := append(prev, flag)

	excessData := make([]byte, 2)
	excessData[1] = 0x32
	data = append(data, excessData...)
	length, flags := mustParseDatabaseLookupFlags(t, length, data)

	length, replyTunnelID, err := readDatabaseLookupReplyTunnelID(flags, length, data)
	assert.Equal(65, length)
	assert.Equal([4]byte{}, replyTunnelID)
	assert.Equal(ErrDatabaseLookupNotEnoughData, err)
}

// TestReadDatabaseLookupReplyTunnelIDNotIncluded validates that when the
// tunnel delivery flag is unset, no reply tunnel ID is read and the offset is
// unchanged.
func TestReadDatabaseLookupReplyTunnelIDNotIncluded(t *testing.T) {
	assert := assert.New(t)

	length := 64
	data := make([]byte, length+1)
	length, flags := mustParseDatabaseLookupFlags(t, length, data)

	length, replyTunnelID, err := readDatabaseLookupReplyTunnelID(flags, length, data)
	assert.Equal(65, length)
	assert.Equal([4]byte{}, replyTunnelID)
	assert.Equal(nil, err)
}

// TestReadDatabaseLookupReplyTunnelIDValidData validates that a 4-byte reply
// tunnel ID is read verbatim when the tunnel delivery flag is set.
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
	length, flags := mustParseDatabaseLookupFlags(t, length, data)

	length, replyTunnelID, err := readDatabaseLookupReplyTunnelID(flags, length, data)
	assert.Equal(69, length)
	assert.Equal([4]byte(expected), replyTunnelID)
	assert.Equal(nil, err)
}

// TestReadDatabaseLookupSizeTooLittleData validates that reading the 2-byte
// excluded-peer count rejects input shorter than 2 bytes.
func TestReadDatabaseLookupSizeTooLittleData(t *testing.T) {
	assert := assert.New(t)

	length := 65
	data := make([]byte, length)
	data = append(data, 0x2)

	length, size, err := readDatabaseLookupSize(length, data)
	assert.Equal(65, length)
	assert.Equal(0, size)
	assert.Equal(ErrDatabaseLookupNotEnoughData, err)
}

// TestReadDatabaseLookupSizeValidData validates that the 2-byte big-endian
// Size field (number of excluded peers, 0-512) is parsed as an integer.
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

// TestReadDatabaseLookupExcludedPeersTooLittleData validates that reading
// excluded peers rejects input shorter than the declared peer count.
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
	assert.Equal(ErrDatabaseLookupNotEnoughData, err)
}

// TestReadDatabaseLookupExcludedPeersZeroSize validates that a zero peer count
// yields no excluded peers and advances the offset by only the 2-byte size.
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

// TestReadDatabaseLookupExcludedPeersValidData validates that N excluded
// peers are read as N consecutive 32-byte router hashes.
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

// TestReadDatabaseLookupReplyKeyTooLittleData validates that reading the
// 32-byte ECIES reply key rejects input shorter than 32 bytes.
func TestReadDatabaseLookupReplyKeyTooLittleData(t *testing.T) {
	assert := assert.New(t)

	length := 67
	data := make([]byte, length)
	data = append(data, 0x2)

	length, replyKey, err := readDatabaseLookupReplyKey(length, data)
	assert.Equal(67, length)
	assert.Equal(session_key.SessionKey{}, replyKey)
	assert.Equal(ErrDatabaseLookupNotEnoughData, err)
}

// TestReadDatabaseLookupReplyKeyValidData validates that a 32-byte ECIES
// reply key is read verbatim and advances the offset by 32.
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

// TestReadDatabaseLookupTagsTooLittleData validates that reading the 1-byte
// ECIES tag count rejects empty input.
func TestReadDatabaseLookupTagsTooLittleData(t *testing.T) {
	assert := assert.New(t)

	length := 99
	data := make([]byte, length)

	length, tags, err := readDatabaseLookupTags(length, data)
	assert.Equal(99, length)
	assert.Equal(0, tags)
	assert.Equal(ErrDatabaseLookupNotEnoughData, err)
}

// TestReadDatabaseLookupTagsValidData validates that the 1-byte ECIES tag
// count is read verbatim and advances the offset by 1.
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

// TestReadDatabaseLookupTooLittleData validates that a DatabaseLookup with the
// ECIES flag set but truncated encryption fields is rejected.
func TestReadDatabaseLookupTooLittleData(t *testing.T) {
	assert := assert.New(t)

	// Build message with ECIES flag set but not enough data for encryption fields
	data := buildLookupHeader(0x00, 0x00, DatabaseLookupFlagECIES, nil, [2]byte{0x00, 0x00})
	// Only 10 bytes of reply key data — not enough for a 32-byte key
	data = append(data, make([]byte, 10)...)

	_, err := ReadDatabaseLookup(data)
	assert.Equal(ErrDatabaseLookupNotEnoughData, err)
}

// TestReadDatabaseLookupValidData validates that a complete DatabaseLookup
// message — including ECIES reply fields — is parsed with every field at the
// correct wire offset.
func TestReadDatabaseLookupValidData(t *testing.T) {
	assert := assert.New(t)

	data, exp := buildFullLookupMessage(0x13, 15)

	expectedTags := 15
	data = append(data, byte(expectedTags))

	var expectedReplyTags []session_tag.ECIESSessionTag
	for i := 0; i < expectedTags; i++ {
		tag := make([]byte, 8)
		tag[3] = 0x22
		tag[7] = 0x11
		eciesTag, err := session_tag.NewECIESSessionTagFromBytes(tag)
		require.NoError(t, err, "Failed to create ECIES session tag %d", i)
		expectedReplyTags = append(expectedReplyTags, eciesTag)
		data = append(data, tag...)
	}

	databaseLookup, err := ReadDatabaseLookup(data)
	assertLookupFieldsMatch(t, databaseLookup, exp)
	assert.Equal(expectedTags, databaseLookup.Tags)
	assert.Equal(expectedReplyTags, databaseLookup.ECIESReplyTags)
	assert.Equal(err, nil)
}

// TestReadDatabaseLookupECIESReplyTagsTooLittleData validates that reading ECIES
// reply tags rejects input shorter than tags×8 bytes.
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
	assert.Equal(ErrDatabaseLookupNotEnoughData, err)
}

// TestReadDatabaseLookupECIESReplyTagsZeroTags validates that a zero tag count
// yields no reply tags and leaves the offset unchanged.
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

// TestReadDatabaseLookupECIESReplyTagsValidData validates that N ECIES reply
// tags are read as N consecutive 8-byte tags.
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

// TestReadDatabaseLookupWithECIESFlag validates that when the ECIES flag
// (bit 4) is set, the parser reads the 32-byte reply_key, the tag count, and
// the 8-byte ECIES reply tags — not the legacy 32-byte ElGamal tags.
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
	assertLookupFieldsMatch(t, databaseLookup, exp)
	assert.Equal(expectedTags, databaseLookup.Tags)
	assert.True(databaseLookup.IsECIES())
	// ECIES tags should be populated
	assert.Equal(expectedECIESTags, databaseLookup.ECIESReplyTags)
	assert.Equal(2, len(databaseLookup.ECIESReplyTags))
	// Verify each tag is 8 bytes
	for _, tag := range databaseLookup.ECIESReplyTags {
		assert.Equal(8, len(tag.Bytes()))
	}
}

// TestReadDatabaseLookupNoEncryptionFlags validates that an unencrypted
// DatabaseLookup (ECIES flag unset) parses without reading encryption fields
// past the excluded peers — the most common case on the I2P network.
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

// TestReadDatabaseLookupNoEncryptionWithExcludedPeers validates that an
// unencrypted lookup with excluded peers parses correctly, with the message
// ending right after the peers and no trailing bytes misread as encryption
// fields.
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

// TestReadDatabaseLookupWithECIESFlagStillWorks validates that a direct-reply
// ECIES lookup (ECIES flag set, no tunnel) parses the 32-byte reply_key, a
// single tag count, and one 8-byte ECIES reply tag.
func TestReadDatabaseLookupWithECIESFlagStillWorks(t *testing.T) {
	assert := assert.New(t)

	flags := byte(DatabaseLookupFlagECIES)
	data := buildLookupHeader(0x11, 0x22, flags, nil, [2]byte{0x00, 0x00})

	// ReplyKey (32 bytes)
	replyKey := make([]byte, 32)
	replyKey[0] = 0xFF
	expectedReplyKey := session_key.SessionKey(replyKey)
	data = append(data, replyKey...)

	// Tags: 1
	data = append(data, 0x01)

	// 1 ECIES reply tag (8 bytes)
	tagData := make([]byte, 8)
	tagData[0] = 0xEE
	data = append(data, tagData...)

	databaseLookup, err := ReadDatabaseLookup(data)
	assert.Nil(err, "ECIES DatabaseLookup should parse without error")
	assert.Equal(flags, databaseLookup.Flags)
	assert.True(databaseLookup.IsECIES())
	assert.Equal(expectedReplyKey, databaseLookup.ReplyKey)
	assert.Equal(1, databaseLookup.Tags)
	assert.Equal(1, len(databaseLookup.ECIESReplyTags))
}

// TestReadDatabaseLookupExplorationNoEncryption validates that an exploration
// lookup (bits 3-2 = 11) with an all-zero excluded-peer marker parses
// correctly without encryption fields.
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
