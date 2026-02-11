package i2np

import (
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/session_key"
	"github.com/go-i2p/common/session_tag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDatabaseLookup_ECIESOnlyMarshalRoundTrip verifies that a DatabaseLookup
// with only the ECIES flag set (bit 4, without bit 1) correctly marshals and
// unmarshals the encryption fields. This was previously broken because
// calculateMarshalSize and marshalEncryptionFields only checked bit 1.
func TestDatabaseLookup_ECIESOnlyMarshalRoundTrip(t *testing.T) {
	require := require.New(t)

	key := common.Hash{}
	key[0] = 0xAA
	key[31] = 0xBB

	from := common.Hash{}
	from[0] = 0xCC
	from[31] = 0xDD

	replyKeyData := make([]byte, 32)
	replyKeyData[0] = 0x11
	replyKeyData[15] = 0x22
	replyKey := session_key.SessionKey(replyKeyData)

	tagData := make([]byte, 8)
	tagData[0] = 0x01
	tagData[7] = 0xFF
	eciesTag, err := session_tag.NewECIESSessionTagFromBytes(tagData)
	require.Nil(err)

	// Create a lookup with ECIES flag only (bit 4 = 0x10), no ElGamal encryption (bit 1 = 0)
	lookup := &DatabaseLookup{
		Key:            key,
		From:           from,
		Flags:          DatabaseLookupFlagECIES, // 0x10 — only ECIES, not ElGamal
		ReplyTunnelID:  [4]byte{},
		Size:           0,
		ExcludedPeers:  nil,
		ReplyKey:       replyKey,
		Tags:           1,
		ECIESReplyTags: []session_tag.ECIESSessionTag{eciesTag},
	}

	// Verify the flags are set correctly
	require.True(lookup.IsECIES(), "ECIES flag should be set")
	require.False(lookup.hasEncryption(), "ElGamal encryption flag should NOT be set")
	require.True(lookup.hasAnyEncryption(), "hasAnyEncryption should return true for ECIES-only")

	// Marshal
	data, err := lookup.MarshalBinary()
	require.Nil(err)

	// The size should include encryption fields:
	// key(32) + from(32) + flags(1) + size(2) + replyKey(32) + tagsCount(1) + eciesTag(8) = 108
	expectedSize := 32 + 32 + 1 + 2 + 32 + 1 + 8
	require.Equal(expectedSize, len(data),
		"Marshal size should include ECIES encryption fields")

	// Unmarshal and verify round-trip
	parsed, err := ReadDatabaseLookup(data)
	require.Nil(err)

	assert := assert.New(t)
	assert.Equal(key, parsed.Key)
	assert.Equal(from, parsed.From)
	assert.Equal(DatabaseLookupFlagECIES, parsed.Flags)
	assert.True(parsed.IsECIES())
	assert.Equal(replyKey, parsed.ReplyKey)
	assert.Equal(1, parsed.Tags)
	assert.Equal(1, len(parsed.ECIESReplyTags))
	assert.Equal(eciesTag, parsed.ECIESReplyTags[0])
	assert.Nil(parsed.ReplyTags, "ElGamal tags should be nil for ECIES-only lookup")
}

// TestDatabaseLookup_ECIESWithTunnelMarshalRoundTrip verifies ECIES + tunnel flag.
func TestDatabaseLookup_ECIESWithTunnelMarshalRoundTrip(t *testing.T) {
	require := require.New(t)

	key := common.Hash{}
	key[0] = 0x01

	from := common.Hash{}
	from[0] = 0x02

	tunnelID := [4]byte{0x00, 0x00, 0x01, 0x00}

	replyKeyData := make([]byte, 32)
	replyKeyData[0] = 0x33
	replyKey := session_key.SessionKey(replyKeyData)

	tag1Data := make([]byte, 8)
	tag1Data[0] = 0xA1
	tag1, err := session_tag.NewECIESSessionTagFromBytes(tag1Data)
	require.Nil(err)

	tag2Data := make([]byte, 8)
	tag2Data[0] = 0xA2
	tag2, err := session_tag.NewECIESSessionTagFromBytes(tag2Data)
	require.Nil(err)

	// Flags: tunnel(0x01) + ECIES(0x10) = 0x11
	lookup := &DatabaseLookup{
		Key:            key,
		From:           from,
		Flags:          DatabaseLookupFlagTunnel | DatabaseLookupFlagECIES,
		ReplyTunnelID:  tunnelID,
		Size:           0,
		ExcludedPeers:  nil,
		ReplyKey:       replyKey,
		Tags:           2,
		ECIESReplyTags: []session_tag.ECIESSessionTag{tag1, tag2},
	}

	data, err := lookup.MarshalBinary()
	require.Nil(err)

	// key(32) + from(32) + flags(1) + tunnelID(4) + size(2) + replyKey(32) + tags(1) + 2*eciesTags(16) = 120
	expectedSize := 32 + 32 + 1 + 4 + 2 + 32 + 1 + 2*8
	require.Equal(expectedSize, len(data))

	parsed, err := ReadDatabaseLookup(data)
	require.Nil(err)

	assert := assert.New(t)
	assert.Equal(key, parsed.Key)
	assert.Equal(from, parsed.From)
	assert.Equal(byte(0x11), parsed.Flags)
	assert.Equal(tunnelID, parsed.ReplyTunnelID)
	assert.True(parsed.IsECIES())
	assert.Equal(replyKey, parsed.ReplyKey)
	assert.Equal(2, parsed.Tags)
	assert.Equal(2, len(parsed.ECIESReplyTags))
	assert.Equal(tag1, parsed.ECIESReplyTags[0])
	assert.Equal(tag2, parsed.ECIESReplyTags[1])
}

// TestDatabaseLookup_ElGamalEncryptionStillWorks verifies that the fix
// for ECIES doesn't break the existing ElGamal encryption path (bit 1).
func TestDatabaseLookup_ElGamalEncryptionStillWorks(t *testing.T) {
	require := require.New(t)

	key := common.Hash{}
	key[0] = 0x10

	from := common.Hash{}
	from[0] = 0x20

	replyKeyData := make([]byte, 32)
	replyKeyData[0] = 0x44
	replyKey := session_key.SessionKey(replyKeyData)

	tagData := make([]byte, 32)
	tagData[0] = 0xBB
	tagData[31] = 0xCC
	tag, err := session_tag.NewSessionTagFromBytes(tagData)
	require.Nil(err)

	// Flags: encryption(0x02) only, no ECIES
	lookup := &DatabaseLookup{
		Key:           key,
		From:          from,
		Flags:         DatabaseLookupFlagEncryption,
		ReplyTunnelID: [4]byte{},
		Size:          0,
		ExcludedPeers: nil,
		ReplyKey:      replyKey,
		Tags:          1,
		ReplyTags:     []session_tag.SessionTag{tag},
	}

	require.True(lookup.hasEncryption())
	require.False(lookup.IsECIES())
	require.True(lookup.hasAnyEncryption())

	data, err := lookup.MarshalBinary()
	require.Nil(err)

	// key(32) + from(32) + flags(1) + size(2) + replyKey(32) + tags(1) + tag(32) = 132
	expectedSize := 32 + 32 + 1 + 2 + 32 + 1 + 32
	require.Equal(expectedSize, len(data))

	parsed, err := ReadDatabaseLookup(data)
	require.Nil(err)

	assert := assert.New(t)
	assert.Equal(key, parsed.Key)
	assert.Equal(from, parsed.From)
	assert.Equal(DatabaseLookupFlagEncryption, parsed.Flags)
	assert.False(parsed.IsECIES())
	assert.Equal(replyKey, parsed.ReplyKey)
	assert.Equal(1, parsed.Tags)
	assert.Equal(1, len(parsed.ReplyTags))
	assert.Equal(tag, parsed.ReplyTags[0])
	assert.Nil(parsed.ECIESReplyTags)
}

// TestDatabaseLookup_NoEncryptionMarshalSize verifies that a lookup without
// any encryption flags doesn't include encryption fields.
func TestDatabaseLookup_NoEncryptionMarshalSize(t *testing.T) {
	assert := assert.New(t)

	lookup := NewDatabaseLookup(common.Hash{}, common.Hash{}, DatabaseLookupFlagTypeRI, nil)

	data, err := lookup.MarshalBinary()
	assert.Nil(err)

	// key(32) + from(32) + flags(1) + size(2) = 67
	assert.Equal(67, len(data))
	assert.False(lookup.hasAnyEncryption())
}

// TestDatabaseLookup_HasAnyEncryption verifies the hasAnyEncryption helper.
func TestDatabaseLookup_HasAnyEncryption(t *testing.T) {
	tests := []struct {
		name     string
		flags    byte
		expected bool
	}{
		{"NoFlags", 0x00, false},
		{"TunnelOnly", DatabaseLookupFlagTunnel, false},
		{"ElGamalOnly", DatabaseLookupFlagEncryption, true},
		{"ECIESOnly", DatabaseLookupFlagECIES, true},
		{"BothEncryption", DatabaseLookupFlagEncryption | DatabaseLookupFlagECIES, true},
		{"TunnelPlusECIES", DatabaseLookupFlagTunnel | DatabaseLookupFlagECIES, true},
		{"TunnelPlusElGamal", DatabaseLookupFlagTunnel | DatabaseLookupFlagEncryption, true},
		{"AllFlags", DatabaseLookupFlagTunnel | DatabaseLookupFlagEncryption | DatabaseLookupFlagECIES, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			lookup := &DatabaseLookup{Flags: tc.flags}
			assert.Equal(t, tc.expected, lookup.hasAnyEncryption(),
				"hasAnyEncryption() for flags 0x%02x", tc.flags)
		})
	}
}

// TestDatabaseLookup_ECIESCalculateMarshalSize verifies that calculateMarshalSize
// accounts for ECIES encryption fields even when only bit 4 is set.
func TestDatabaseLookup_ECIESCalculateMarshalSize(t *testing.T) {
	assert := assert.New(t)

	// ECIES-only lookup with 1 tag (8 bytes) and no tunnel
	lookup := &DatabaseLookup{
		Flags: DatabaseLookupFlagECIES,
		Size:  0,
		Tags:  1,
	}

	// Expected: base(67) + replyKey(32) + tagsCount(1) + 1*eciesTag(8) = 108
	assert.Equal(108, lookup.calculateMarshalSize())

	// ECIES-only lookup with 3 tags and 2 excluded peers
	lookup2 := &DatabaseLookup{
		Flags: DatabaseLookupFlagECIES,
		Size:  2,
		Tags:  3,
	}

	// Expected: base(67) + 2*peer(64) + replyKey(32) + tagsCount(1) + 3*eciesTag(24) = 188
	assert.Equal(188, lookup2.calculateMarshalSize())
}
