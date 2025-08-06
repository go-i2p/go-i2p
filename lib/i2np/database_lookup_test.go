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
	length, flags, err := readDatabaseLookupFlags(length, data)

	length, replyTunnelID, err := readDatabaseLookupReplyTunnelID(flags, length, data)
	assert.Equal(65, length)
	assert.Equal([4]byte{}, replyTunnelID)
	assert.Equal(ERR_DATABASE_LOOKUP_NOT_ENOUGH_DATA, err)
}

func TestReadDatabaseLookupReplyTunnelIDNotIncluded(t *testing.T) {
	assert := assert.New(t)

	length := 65
	data := make([]byte, length)
	length, flags, err := readDatabaseLookupFlags(length, data)

	length, tunnelID, err := readDatabaseLookupReplyTunnelID(flags, length, data)
	assert.Equal(65, length)
	assert.Equal([4]byte{}, tunnelID)
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
	length, flags, err := readDatabaseLookupFlags(length, data)

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
	expectedSizeData := []byte{0x16, 0x9}
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

	length, size, err := readDatabaseLookupSize(length, data)
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

	length := 67
	data := make([]byte, length)
	expectedReplyKeyData := make([]byte, 32)
	expectedReplyKeyData[3] = 0x31
	expectedReplyKey := session_key.SessionKey(expectedReplyKeyData)
	data = append(data, expectedReplyKeyData...)

	databaseLookup, err := ReadDatabaseLookup(data)
	assert.Equal(expectedReplyKey, databaseLookup.ReplyKey)
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

	expectedFlags := byte(0x1)
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
