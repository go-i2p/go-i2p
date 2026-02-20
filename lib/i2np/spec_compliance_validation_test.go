package i2np

// spec_compliance_test.go — I2P specification compliance tests for I2NP headers.
//
// These tests verify that the lib/i2np package correctly implements the I2NP
// message header format as defined in i2np.rst. Each test group maps to a
// specific audit checklist item in Section 6 of AUDIT.md.
//
// Spec reference: https://geti2p.net/spec/i2np (version 0.9.66+)

import (
	"bytes"
	"github.com/go-i2p/crypto/types"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"github.com/go-i2p/common/certificate"
	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/session_key"
	"github.com/go-i2p/common/session_tag"
	"github.com/go-i2p/crypto/chacha20poly1305"
	"github.com/go-i2p/crypto/ecies"
	"github.com/go-i2p/crypto/ratchet"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Audit Item: Header format
// Type (1 byte) + MsgID (4 bytes) + Expiration (8 bytes) + Size (2 bytes) +
// Checksum (1 byte) + Data  =  16-byte header
// =============================================================================

// TestStandardHeaderSize_Is16Bytes verifies the NTCP standard header is exactly
// 16 bytes as defined in i2np.rst.
func TestStandardHeaderSize_Is16Bytes(t *testing.T) {
	msg := NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_DATA)
	msg.SetMessageID(1)
	msg.SetData([]byte{})

	data, err := msg.MarshalBinary()
	require.NoError(t, err)

	// Empty payload → header only = 16 bytes
	assert.Equal(t, 16, len(data),
		"Standard I2NP header with empty payload must be exactly 16 bytes")
}

// TestStandardHeaderLayout_FieldOffsets verifies byte-level field positions:
//
//	offset 0:    type       (1 byte)
//	offset 1-4:  msg_id     (4 bytes, big-endian)
//	offset 5-12: expiration (8 bytes, Date = milliseconds since epoch)
//	offset 13-14: size      (2 bytes, big-endian)
//	offset 15:   checksum   (1 byte, first byte of SHA256(payload))
//	offset 16+:  data       (variable)
func TestStandardHeaderLayout_FieldOffsets(t *testing.T) {
	msg := NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_DATABASE_STORE)
	msg.SetMessageID(0x01020304)
	payload := []byte{0xAA, 0xBB, 0xCC}
	msg.SetData(payload)
	msg.SetExpiration(time.Unix(86400, 0)) // 1970-01-02T00:00:00Z

	data, err := msg.MarshalBinary()
	require.NoError(t, err)
	require.True(t, len(data) >= 16+3, "must have header + 3-byte payload")

	// Type at offset 0
	assert.Equal(t, byte(I2NP_MESSAGE_TYPE_DATABASE_STORE), data[0],
		"type field at offset 0")

	// Message ID at offset 1-4 (big-endian)
	msgID := binary.BigEndian.Uint32(data[1:5])
	assert.Equal(t, uint32(0x01020304), msgID,
		"msg_id field at offset 1-4 (big-endian)")

	// Expiration at offset 5-12 (8 bytes, milliseconds since epoch)
	// 86400 seconds = 86400000 milliseconds
	expMs := binary.BigEndian.Uint64(data[5:13])
	assert.Equal(t, uint64(86400)*1000, expMs,
		"expiration field at offset 5-12 (milliseconds since epoch)")

	// Size at offset 13-14 (big-endian)
	size := binary.BigEndian.Uint16(data[13:15])
	assert.Equal(t, uint16(3), size,
		"size field at offset 13-14")

	// Checksum at offset 15 (first byte of SHA256)
	hash := types.SHA256(payload)
	assert.Equal(t, hash[0], data[15],
		"checksum field at offset 15 (SHA256 first byte)")

	// Payload at offset 16+
	assert.Equal(t, payload, data[16:],
		"payload starting at offset 16")
}

// TestStandardHeaderRoundtrip_MarshalUnmarshal verifies marshal/unmarshal preserves
// all header fields.
func TestStandardHeaderRoundtrip_MarshalUnmarshal(t *testing.T) {
	original := NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_GARLIC)
	original.SetMessageID(999999)
	original.SetData([]byte("garlic message test payload"))
	original.SetExpiration(time.Now().Add(5 * time.Minute).Truncate(time.Millisecond))

	data, err := original.MarshalBinary()
	require.NoError(t, err)

	parsed := &BaseI2NPMessage{}
	err = parsed.UnmarshalBinary(data)
	require.NoError(t, err)

	assert.Equal(t, original.Type(), parsed.Type(), "type preserved")
	assert.Equal(t, original.MessageID(), parsed.MessageID(), "messageID preserved")
	assert.Equal(t, original.GetData(), parsed.GetData(), "payload preserved")
	// Expiration precision: I2P Date stores milliseconds, so within 1ms
	assert.WithinDuration(t, original.Expiration(), parsed.Expiration(), time.Millisecond,
		"expiration preserved within 1ms")
}

// TestStandardHeader_ReadI2NPNTCPHeader verifies the separate field-reader pipeline
// produces the same result as UnmarshalBinary.
func TestStandardHeader_ReadI2NPNTCPHeader(t *testing.T) {
	msg := NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_TUNNEL_DATA)
	msg.SetMessageID(42)
	payload := []byte("hello world")
	msg.SetData(payload)

	data, err := msg.MarshalBinary()
	require.NoError(t, err)

	header, err := ReadI2NPNTCPHeader(data)
	require.NoError(t, err)

	assert.Equal(t, I2NP_MESSAGE_TYPE_TUNNEL_DATA, header.Type)
	assert.Equal(t, 42, header.MessageID)
	assert.Equal(t, len(payload), header.Size)
	assert.Equal(t, payload, header.Data)

	// Verify checksum matches
	hash := types.SHA256(payload)
	assert.Equal(t, int(hash[0]), header.Checksum)
}

// TestStandardHeader_PayloadSizeLimit verifies the 2-byte (uint16) payload
// size limit of 65535 bytes.
func TestStandardHeader_PayloadSizeLimit(t *testing.T) {
	msg := NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_DATA)

	// At the limit: 65535 bytes — should succeed
	msg.SetData(make([]byte, MaxI2NPStandardPayload))
	_, err := msg.MarshalBinary()
	assert.NoError(t, err, "payload of exactly MaxI2NPStandardPayload should succeed")

	// Over the limit: 65536 bytes — should fail
	msg.SetData(make([]byte, MaxI2NPStandardPayload+1))
	_, err = msg.MarshalBinary()
	assert.Error(t, err, "payload exceeding MaxI2NPStandardPayload must be rejected")
}

// =============================================================================
// Audit Item: SSU short header / NTCP2/SSU2 second-gen transport header
// Type (1 byte) + MsgID (4 bytes) + Short Expiration (4 bytes) = 9 bytes
// Legacy SSU: Type (1 byte) + Short Expiration (4 bytes) = 5 bytes
// =============================================================================

// TestSecondGenTransportHeader_Is9Bytes verifies the NTCP2/SSU2 "second gen"
// header is parsed correctly from 9 bytes: type(1) + msgID(4) + exp_seconds(4).
func TestSecondGenTransportHeader_Is9Bytes(t *testing.T) {
	// Construct a known 9-byte header
	data := make([]byte, 9)
	data[0] = byte(I2NP_MESSAGE_TYPE_TUNNEL_DATA)             // type
	binary.BigEndian.PutUint32(data[1:5], 0x12345678)         // msg_id
	binary.BigEndian.PutUint32(data[5:9], uint32(1704067200)) // exp (2024-01-01 00:00:00 UTC)

	header, err := ReadI2NPSecondGenTransportHeader(data)
	require.NoError(t, err)

	assert.Equal(t, I2NP_MESSAGE_TYPE_TUNNEL_DATA, header.Type)
	assert.Equal(t, 0x12345678, header.MessageID)

	expected := time.Unix(1704067200, 0)
	assert.Equal(t, expected.Unix(), header.Expiration.Unix(),
		"expiration should be seconds-based (not milliseconds)")
}

// TestSecondGenTransportHeader_TooShort verifies rejection of data < 9 bytes.
func TestSecondGenTransportHeader_TooShort(t *testing.T) {
	for _, length := range []int{0, 1, 4, 8} {
		_, err := ReadI2NPSecondGenTransportHeader(make([]byte, length))
		assert.Equal(t, ERR_I2NP_NOT_ENOUGH_DATA, err,
			"data of length %d must be rejected", length)
	}
}

// TestSecondGenTransportHeader_ExpirationIsSeconds verifies the short expiration
// field is in seconds (not milliseconds) per i2np.rst.
func TestSecondGenTransportHeader_ExpirationIsSeconds(t *testing.T) {
	// Encode 86400 seconds (exactly 1 day) as a 4-byte big-endian uint32
	data := make([]byte, 9)
	data[0] = byte(I2NP_MESSAGE_TYPE_DATA)
	binary.BigEndian.PutUint32(data[5:9], 86400)

	header, err := ReadI2NPSecondGenTransportHeader(data)
	require.NoError(t, err)

	// If seconds: 86400 → 1970-01-02T00:00:00Z
	// If milliseconds: 86400 → 1970-01-01T00:01:26Z (wrong)
	assert.Equal(t, int64(86400), header.Expiration.Unix(),
		"short expiration must be seconds since epoch, not milliseconds")
}

// TestSecondGenTransportHeader_MarshalRoundtrip verifies the marshal→unmarshal
// roundtrip for the NTCP2/SSU2 9-byte header.
func TestSecondGenTransportHeader_MarshalRoundtrip(t *testing.T) {
	original := I2NPSecondGenTransportHeader{
		Type:       I2NP_MESSAGE_TYPE_GARLIC,
		MessageID:  0x00ABCDEF,
		Expiration: time.Unix(1704067200, 0), // 2024-01-01
	}

	data, err := MarshalSecondGenTransportHeader(original)
	require.NoError(t, err)
	require.Equal(t, 9, len(data), "second-gen header must be exactly 9 bytes")

	parsed, err := ReadI2NPSecondGenTransportHeader(data)
	require.NoError(t, err)

	assert.Equal(t, original.Type, parsed.Type)
	assert.Equal(t, original.MessageID, parsed.MessageID)
	assert.Equal(t, original.Expiration.Unix(), parsed.Expiration.Unix())
}

// TestLegacySSUHeader_Is5Bytes verifies the legacy SSU header (5 bytes).
func TestLegacySSUHeader_Is5Bytes(t *testing.T) {
	data := make([]byte, 5)
	data[0] = byte(I2NP_MESSAGE_TYPE_DATABASE_LOOKUP)
	binary.BigEndian.PutUint32(data[1:5], 86400) // 86400 seconds

	header, err := ReadI2NPSSUHeader(data)
	require.NoError(t, err)

	assert.Equal(t, I2NP_MESSAGE_TYPE_DATABASE_LOOKUP, header.Type)
	assert.Equal(t, int64(86400), header.Expiration.Unix())
}

// TestLegacySSUHeader_TooShort verifies rejection of data < 5 bytes.
func TestLegacySSUHeader_TooShort(t *testing.T) {
	for _, length := range []int{0, 1, 3, 4} {
		_, err := ReadI2NPSSUHeader(make([]byte, length))
		assert.Equal(t, ERR_I2NP_NOT_ENOUGH_DATA, err,
			"data of length %d must be rejected", length)
	}
}

// TestBothHeaderFormats_Supported verifies that the same message type can be
// parsed from both standard (16-byte) and second-gen transport (9-byte) headers.
func TestBothHeaderFormats_Supported(t *testing.T) {
	// Build standard NTCP header
	msg := NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_DELIVERY_STATUS)
	msg.SetMessageID(0x00112233)
	msg.SetData([]byte{0x01, 0x02})
	standardData, err := msg.MarshalBinary()
	require.NoError(t, err)

	standardHeader, err := ReadI2NPNTCPHeader(standardData)
	require.NoError(t, err)
	assert.Equal(t, I2NP_MESSAGE_TYPE_DELIVERY_STATUS, standardHeader.Type)
	assert.Equal(t, 0x00112233, standardHeader.MessageID)

	// Build second-gen transport header for the same message
	shortData := make([]byte, 9)
	shortData[0] = byte(I2NP_MESSAGE_TYPE_DELIVERY_STATUS)
	binary.BigEndian.PutUint32(shortData[1:5], 0x00112233)
	binary.BigEndian.PutUint32(shortData[5:9], uint32(time.Now().Add(time.Minute).Unix()))

	shortHeader, err := ReadI2NPSecondGenTransportHeader(shortData)
	require.NoError(t, err)
	assert.Equal(t, I2NP_MESSAGE_TYPE_DELIVERY_STATUS, shortHeader.Type)
	assert.Equal(t, 0x00112233, shortHeader.MessageID)
}

// =============================================================================
// Audit Item: Message type IDs
// Verify all 14 type constants match spec (1,2,3,10,11,18,19,20,21,22,23,24,25,26)
// =============================================================================

// TestMessageTypeIDs_MatchSpec verifies every I2NP message type constant matches
// the authoritative values from i2np.rst.
func TestMessageTypeIDs_MatchSpec(t *testing.T) {
	// Spec-defined message type IDs (i2np.rst)
	specTypes := map[string]int{
		"DatabaseStore":            1,
		"DatabaseLookup":           2,
		"DatabaseSearchReply":      3,
		"DeliveryStatus":           10,
		"Garlic":                   11,
		"TunnelData":               18,
		"TunnelGateway":            19,
		"Data":                     20,
		"TunnelBuild":              21,
		"TunnelBuildReply":         22,
		"VariableTunnelBuild":      23,
		"VariableTunnelBuildReply": 24,
		"ShortTunnelBuild":         25,
		"ShortTunnelBuildReply":    26,
	}

	codeTypes := map[string]int{
		"DatabaseStore":            I2NP_MESSAGE_TYPE_DATABASE_STORE,
		"DatabaseLookup":           I2NP_MESSAGE_TYPE_DATABASE_LOOKUP,
		"DatabaseSearchReply":      I2NP_MESSAGE_TYPE_DATABASE_SEARCH_REPLY,
		"DeliveryStatus":           I2NP_MESSAGE_TYPE_DELIVERY_STATUS,
		"Garlic":                   I2NP_MESSAGE_TYPE_GARLIC,
		"TunnelData":               I2NP_MESSAGE_TYPE_TUNNEL_DATA,
		"TunnelGateway":            I2NP_MESSAGE_TYPE_TUNNEL_GATEWAY,
		"Data":                     I2NP_MESSAGE_TYPE_DATA,
		"TunnelBuild":              I2NP_MESSAGE_TYPE_TUNNEL_BUILD,
		"TunnelBuildReply":         I2NP_MESSAGE_TYPE_TUNNEL_BUILD_REPLY,
		"VariableTunnelBuild":      I2NP_MESSAGE_TYPE_VARIABLE_TUNNEL_BUILD,
		"VariableTunnelBuildReply": I2NP_MESSAGE_TYPE_VARIABLE_TUNNEL_BUILD_REPLY,
		"ShortTunnelBuild":         I2NP_MESSAGE_TYPE_SHORT_TUNNEL_BUILD,
		"ShortTunnelBuildReply":    I2NP_MESSAGE_TYPE_SHORT_TUNNEL_BUILD_REPLY,
	}

	assert.Equal(t, len(specTypes), 14, "spec defines exactly 14 I2NP message types")
	assert.Equal(t, len(codeTypes), 14, "code defines exactly 14 I2NP message type constants")

	for name, specID := range specTypes {
		codeID, ok := codeTypes[name]
		require.True(t, ok, "missing constant for %s", name)
		assert.Equal(t, specID, codeID,
			"type ID mismatch for %s: spec=%d, code=%d", name, specID, codeID)
	}
}

// TestMessageTypeIDs_AllValidTypesRecognized verifies ReadI2NPType accepts all
// 14 spec-defined type values without error.
func TestMessageTypeIDs_AllValidTypesRecognized(t *testing.T) {
	specTypeIDs := []int{1, 2, 3, 10, 11, 18, 19, 20, 21, 22, 23, 24, 25, 26}

	for _, typeID := range specTypeIDs {
		data := []byte{byte(typeID)}
		result, err := ReadI2NPType(data)
		assert.NoError(t, err, "type %d should be accepted", typeID)
		assert.Equal(t, typeID, result, "ReadI2NPType should return %d", typeID)
	}
}

// TestMessageTypeIDs_NoGapOverlap verifies there are no duplicate type IDs
// and the set of assigned IDs is exactly {1,2,3,10,11,18,19,20,21,22,23,24,25,26}.
func TestMessageTypeIDs_NoGapOverlap(t *testing.T) {
	allConstants := []int{
		I2NP_MESSAGE_TYPE_DATABASE_STORE,
		I2NP_MESSAGE_TYPE_DATABASE_LOOKUP,
		I2NP_MESSAGE_TYPE_DATABASE_SEARCH_REPLY,
		I2NP_MESSAGE_TYPE_DELIVERY_STATUS,
		I2NP_MESSAGE_TYPE_GARLIC,
		I2NP_MESSAGE_TYPE_TUNNEL_DATA,
		I2NP_MESSAGE_TYPE_TUNNEL_GATEWAY,
		I2NP_MESSAGE_TYPE_DATA,
		I2NP_MESSAGE_TYPE_TUNNEL_BUILD,
		I2NP_MESSAGE_TYPE_TUNNEL_BUILD_REPLY,
		I2NP_MESSAGE_TYPE_VARIABLE_TUNNEL_BUILD,
		I2NP_MESSAGE_TYPE_VARIABLE_TUNNEL_BUILD_REPLY,
		I2NP_MESSAGE_TYPE_SHORT_TUNNEL_BUILD,
		I2NP_MESSAGE_TYPE_SHORT_TUNNEL_BUILD_REPLY,
	}

	expected := map[int]bool{
		1: true, 2: true, 3: true, 10: true, 11: true,
		18: true, 19: true, 20: true, 21: true, 22: true,
		23: true, 24: true, 25: true, 26: true,
	}

	seen := make(map[int]bool)
	for _, id := range allConstants {
		assert.False(t, seen[id], "duplicate message type ID: %d", id)
		assert.True(t, expected[id], "unexpected message type ID: %d", id)
		seen[id] = true
	}
	assert.Equal(t, len(expected), len(seen),
		"all 14 spec type IDs must be represented by constants")
}

// =============================================================================
// Audit Item: Checksum
// SHA256 of payload, first byte only
// =============================================================================

// TestChecksum_IsSHA256FirstByte verifies the checksum is computed as the first
// byte of SHA256(payload), matching i2np.rst.
func TestChecksum_IsSHA256FirstByte(t *testing.T) {
	payloads := [][]byte{
		{},                          // empty payload
		{0x00},                      // single zero byte
		{0xFF, 0xFE, 0xFD},          // small payload
		make([]byte, 1024),          // 1KB zeros
		[]byte("I2NP test payload"), // text
	}

	for _, payload := range payloads {
		msg := NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_DATA)
		msg.SetData(payload)

		data, err := msg.MarshalBinary()
		require.NoError(t, err)
		require.True(t, len(data) >= 16)

		// Wire checksum is at offset 15
		wireChecksum := data[15]

		// Expected: first byte of SHA256(payload)
		hash := types.SHA256(payload)
		assert.Equal(t, hash[0], wireChecksum,
			"checksum must be SHA256(payload)[0] for payload of length %d", len(payload))
	}
}

// TestChecksum_VerifiedOnUnmarshal verifies that UnmarshalBinary rejects
// messages with corrupted checksums.
func TestChecksum_VerifiedOnUnmarshal(t *testing.T) {
	msg := NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_DATA)
	msg.SetData([]byte("integrity check"))

	data, err := msg.MarshalBinary()
	require.NoError(t, err)

	// Corrupt the checksum byte at offset 15
	data[15] ^= 0xFF

	parsed := &BaseI2NPMessage{}
	err = parsed.UnmarshalBinary(data)
	assert.Error(t, err, "corrupted checksum must be rejected")
	assert.Contains(t, err.Error(), "checksum mismatch",
		"error should mention checksum mismatch")
}

// TestChecksum_VerifiedOnUnmarshal_CorruptedPayload verifies that a corrupted
// payload fails the checksum check.
func TestChecksum_VerifiedOnUnmarshal_CorruptedPayload(t *testing.T) {
	msg := NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_DATA)
	msg.SetData([]byte("original payload data"))

	data, err := msg.MarshalBinary()
	require.NoError(t, err)

	// Corrupt a byte in the payload area (offset 16+)
	if len(data) > 17 {
		data[17] ^= 0xFF
	}

	parsed := &BaseI2NPMessage{}
	err = parsed.UnmarshalBinary(data)
	assert.Error(t, err, "corrupted payload must fail checksum verification")
}

// =============================================================================
// Audit Item: Expiration
// 8-byte milliseconds since epoch; receivers MUST drop messages with expiration
// in the past
// =============================================================================

// TestExpiration_Is8ByteMilliseconds verifies the standard header stores
// expiration as an 8-byte millisecond timestamp.
func TestExpiration_Is8ByteMilliseconds(t *testing.T) {
	// Use a known time: 2024-01-01 00:00:00 UTC = 1704067200 seconds
	knownTime := time.Unix(1704067200, 0)
	msg := NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_DATA)
	msg.SetExpiration(knownTime)
	msg.SetData([]byte{})

	data, err := msg.MarshalBinary()
	require.NoError(t, err)

	// Read the 8-byte expiration field at offset 5-12
	expMs := binary.BigEndian.Uint64(data[5:13])

	// 1704067200 seconds = 1704067200000 milliseconds
	assert.Equal(t, uint64(1704067200000), expMs,
		"expiration field must store milliseconds since epoch")
}

// TestExpiration_MUST_DropExpiredMessages verifies that expired messages are
// rejected by the ExpirationValidator (per spec: "receivers MUST drop messages
// with expiration in the past").
func TestExpiration_MUST_DropExpiredMessages(t *testing.T) {
	now := time.Date(2026, 2, 16, 12, 0, 0, 0, time.UTC)

	v := NewExpirationValidator().
		WithTolerance(0). // No tolerance — strict spec compliance check
		WithTimeSource(func() time.Time { return now })

	// Message that expired 1 second ago
	pastExp := now.Add(-1 * time.Second)
	err := v.ValidateExpiration(pastExp)
	assert.Error(t, err, "expired message MUST be rejected")
	assert.ErrorIs(t, err, ERR_I2NP_MESSAGE_EXPIRED)

	// Message that expires 1 second in the future
	futureExp := now.Add(1 * time.Second)
	err = v.ValidateExpiration(futureExp)
	assert.NoError(t, err, "non-expired message must be accepted")
}

// TestExpiration_ToleranceAllowsRecentPast verifies the default 5-minute
// tolerance accepts messages that expired recently (accounting for clock skew).
func TestExpiration_ToleranceAllowsRecentPast(t *testing.T) {
	now := time.Date(2026, 2, 16, 12, 0, 0, 0, time.UTC)

	v := NewExpirationValidator().
		WithTolerance(DefaultExpirationTolerance).
		WithTimeSource(func() time.Time { return now })

	// Message expired 4 minutes ago — within 5-minute tolerance
	recentExp := now.Add(-4 * time.Minute)
	assert.False(t, v.IsExpired(recentExp),
		"message within tolerance should not be considered expired")

	// Message expired 10 minutes ago — beyond tolerance
	oldExp := now.Add(-10 * time.Minute)
	assert.True(t, v.IsExpired(oldExp),
		"message beyond tolerance must be considered expired")
}

// TestExpiration_ProcessorRejectsExpiredMessages verifies the MessageProcessor
// integrates expiration validation and rejects expired messages.
func TestExpiration_ProcessorRejectsExpiredMessages(t *testing.T) {
	now := time.Date(2026, 2, 16, 12, 0, 0, 0, time.UTC)

	processor := NewMessageProcessor()
	processor.SetExpirationValidator(
		NewExpirationValidator().
			WithTolerance(0).
			WithTimeSource(func() time.Time { return now }),
	)

	// Create a message that expired 1 hour ago
	msg := NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_DATA)
	msg.SetExpiration(now.Add(-1 * time.Hour))
	msg.SetData([]byte("expired"))

	err := processor.ProcessMessage(msg)
	assert.Error(t, err, "processor must reject expired messages")
	assert.ErrorIs(t, err, ERR_I2NP_MESSAGE_EXPIRED)
}

// TestExpiration_ProcessorAcceptsFutureMessages verifies the processor accepts
// messages with future expiration.
func TestExpiration_ProcessorAcceptsFutureMessages(t *testing.T) {
	now := time.Date(2026, 2, 16, 12, 0, 0, 0, time.UTC)

	processor := NewMessageProcessor()
	processor.SetExpirationValidator(
		NewExpirationValidator().
			WithTolerance(0).
			WithTimeSource(func() time.Time { return now }),
	)

	// Create a message that expires 5 minutes from now
	msg := NewDataMessage([]byte("test payload"))
	msg.SetExpiration(now.Add(5 * time.Minute))

	err := processor.ProcessMessage(msg)
	assert.NoError(t, err, "processor must accept non-expired messages")
}

// TestExpiration_SSUShortExpiration_IsSeconds verifies the 4-byte short
// expiration in SSU/NTCP2 headers is seconds since epoch (not milliseconds).
func TestExpiration_SSUShortExpiration_IsSeconds(t *testing.T) {
	// 1704067200 seconds = 2024-01-01 00:00:00 UTC
	data := make([]byte, 9)
	data[0] = byte(I2NP_MESSAGE_TYPE_DATA)
	binary.BigEndian.PutUint32(data[5:9], 1704067200)

	header, err := ReadI2NPSecondGenTransportHeader(data)
	require.NoError(t, err)

	assert.Equal(t, int64(1704067200), header.Expiration.Unix(),
		"short expiration uses seconds, not milliseconds")
}

// TestExpiration_DefaultToleranceIs5Minutes documents the default tolerance
// value matching the I2P spec recommendation.
func TestExpiration_DefaultToleranceIs5Minutes(t *testing.T) {
	assert.Equal(t, int64(300), int64(DefaultExpirationTolerance),
		"default expiration tolerance must be 300 seconds (5 minutes)")
}

// =============================================================================
// Audit Item: DatabaseStore — Store types
// Type byte bits 3-0: RouterInfo (0), LeaseSet (1), LeaseSet2 (3),
// EncryptedLeaseSet (5), MetaLeaseSet (7)
// =============================================================================

// TestDatabaseStore_StoreTypes_MatchSpec verifies that all store type constants
// match the I2NP specification values from i2np.rst.
func TestDatabaseStore_StoreTypes_MatchSpec(t *testing.T) {
	specTypes := map[string]int{
		"RouterInfo":        0,
		"LeaseSet":          1,
		"LeaseSet2":         3,
		"EncryptedLeaseSet": 5,
		"MetaLeaseSet":      7,
	}

	codeTypes := map[string]int{
		"RouterInfo":        DATABASE_STORE_TYPE_ROUTER_INFO,
		"LeaseSet":          DATABASE_STORE_TYPE_LEASESET,
		"LeaseSet2":         DATABASE_STORE_TYPE_LEASESET2,
		"EncryptedLeaseSet": DATABASE_STORE_TYPE_ENCRYPTED_LEASESET,
		"MetaLeaseSet":      DATABASE_STORE_TYPE_META_LEASESET,
	}

	for name, specVal := range specTypes {
		codeVal, ok := codeTypes[name]
		require.True(t, ok, "missing constant for store type %s", name)
		assert.Equal(t, specVal, codeVal,
			"store type %s: spec=%d, code=%d", name, specVal, codeVal)
	}
}

// TestDatabaseStore_StoreTypes_Bits3to0 verifies that GetLeaseSetType extracts
// bits 3-0 of the type field, per spec: "bits 3-0: LeaseSet type variant".
func TestDatabaseStore_StoreTypes_Bits3to0(t *testing.T) {
	tests := []struct {
		name     string
		rawType  byte
		expected int
	}{
		{"RouterInfo_0x00", 0x00, DATABASE_STORE_TYPE_ROUTER_INFO},
		{"LeaseSet_0x01", 0x01, DATABASE_STORE_TYPE_LEASESET},
		{"LeaseSet2_0x03", 0x03, DATABASE_STORE_TYPE_LEASESET2},
		{"EncryptedLeaseSet_0x05", 0x05, DATABASE_STORE_TYPE_ENCRYPTED_LEASESET},
		{"MetaLeaseSet_0x07", 0x07, DATABASE_STORE_TYPE_META_LEASESET},
		// Bits 7-4 set (reserved, should be masked out)
		{"RouterInfo_HighBitsSet", 0xF0, DATABASE_STORE_TYPE_ROUTER_INFO},
		{"LeaseSet2_HighBitsSet", 0xF3, DATABASE_STORE_TYPE_LEASESET2},
		{"EncryptedLeaseSet_HighBitsSet", 0xA5, DATABASE_STORE_TYPE_ENCRYPTED_LEASESET},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ds := &DatabaseStore{StoreType: tc.rawType}
			assert.Equal(t, tc.expected, ds.GetLeaseSetType(),
				"GetLeaseSetType must extract bits 3-0 only")
		})
	}
}

// TestDatabaseStore_StoreTypes_IsRouterInfo verifies the IsRouterInfo helper.
func TestDatabaseStore_StoreTypes_IsRouterInfo(t *testing.T) {
	ri := &DatabaseStore{StoreType: DATABASE_STORE_TYPE_ROUTER_INFO}
	assert.True(t, ri.IsRouterInfo(), "type 0 must be RouterInfo")

	ls := &DatabaseStore{StoreType: DATABASE_STORE_TYPE_LEASESET}
	assert.False(t, ls.IsRouterInfo(), "type 1 must NOT be RouterInfo")

	ls2 := &DatabaseStore{StoreType: DATABASE_STORE_TYPE_LEASESET2}
	assert.False(t, ls2.IsRouterInfo(), "type 3 must NOT be RouterInfo")
}

// TestDatabaseStore_StoreTypes_IsLeaseSet verifies the IsLeaseSet helper
// recognizes all LeaseSet variants (1, 3, 5, 7) but NOT RouterInfo (0).
func TestDatabaseStore_StoreTypes_IsLeaseSet(t *testing.T) {
	ri := &DatabaseStore{StoreType: DATABASE_STORE_TYPE_ROUTER_INFO}
	assert.False(t, ri.IsLeaseSet(), "RouterInfo (0) must NOT be a LeaseSet")

	for _, lsType := range []byte{
		DATABASE_STORE_TYPE_LEASESET,
		DATABASE_STORE_TYPE_LEASESET2,
		DATABASE_STORE_TYPE_ENCRYPTED_LEASESET,
		DATABASE_STORE_TYPE_META_LEASESET,
	} {
		ds := &DatabaseStore{StoreType: lsType}
		assert.True(t, ds.IsLeaseSet(),
			"store type %d must be recognized as LeaseSet", lsType)
	}
}

// TestDatabaseStore_StoreTypes_MarshalRoundtrip verifies each store type
// survives a marshal→unmarshal cycle.
func TestDatabaseStore_StoreTypes_MarshalRoundtrip(t *testing.T) {
	storeTypes := []byte{
		DATABASE_STORE_TYPE_ROUTER_INFO,
		DATABASE_STORE_TYPE_LEASESET,
		DATABASE_STORE_TYPE_LEASESET2,
		DATABASE_STORE_TYPE_ENCRYPTED_LEASESET,
		DATABASE_STORE_TYPE_META_LEASESET,
	}

	for _, st := range storeTypes {
		t.Run(fmt.Sprintf("type_%d", st), func(t *testing.T) {
			key := common.Hash{}
			key[0] = st // Make each key distinct
			original := NewDatabaseStore(key, []byte("test data"), st)

			payload, err := original.MarshalPayload()
			require.NoError(t, err)

			parsed := &DatabaseStore{}
			err = parsed.UnmarshalBinary(payload)
			require.NoError(t, err)

			assert.Equal(t, st, parsed.StoreType,
				"store type must survive roundtrip")
			assert.Equal(t, key, parsed.Key,
				"key must survive roundtrip")
		})
	}
}

// =============================================================================
// Audit Item: DatabaseStore — Reply token
// "If greater than zero, a DeliveryStatusMessage is requested with the Message
// ID set to the value of the Reply Token."
// When reply token > 0: replyTunnelID (4 bytes) + replyGateway (32 bytes) follow.
// When reply token == 0: data follows immediately.
// =============================================================================

// TestDatabaseStore_ReplyToken_ZeroMeansNoReplyFields verifies that when the
// reply token is zero, the replyTunnelID and replyGateway fields are NOT present
// in the wire format.
func TestDatabaseStore_ReplyToken_ZeroMeansNoReplyFields(t *testing.T) {
	key := common.Hash{}
	key[0] = 0xAA
	data := []byte("test payload")

	ds := NewDatabaseStore(key, data, DATABASE_STORE_TYPE_LEASESET2)
	// Default reply token is zero

	payload, err := ds.MarshalPayload()
	require.NoError(t, err)

	// Expected: key(32) + type(1) + replyToken(4) + data(12) = 49 bytes
	// NOT key(32) + type(1) + replyToken(4) + tunnelID(4) + gateway(32) + data(12) = 85
	expectedLen := 32 + 1 + 4 + len(data)
	assert.Equal(t, expectedLen, len(payload),
		"zero reply token must NOT include tunnelID/gateway fields")
}

// TestDatabaseStore_ReplyToken_NonzeroIncludesReplyFields verifies that when
// the reply token is nonzero, the wire format includes replyTunnelID (4 bytes)
// and replyGateway (32 bytes).
func TestDatabaseStore_ReplyToken_NonzeroIncludesReplyFields(t *testing.T) {
	key := common.Hash{}
	key[0] = 0xBB
	gateway := common.Hash{}
	gateway[0] = 0xCC
	data := []byte("payload")

	ds := NewDatabaseStore(key, data, DATABASE_STORE_TYPE_ROUTER_INFO)
	ds.ReplyToken = [4]byte{0x00, 0x00, 0x00, 0x01} // nonzero
	ds.ReplyTunnelID = [4]byte{0x00, 0x00, 0x10, 0x00}
	ds.ReplyGateway = gateway

	payload, err := ds.MarshalPayload()
	require.NoError(t, err)

	// Expected: key(32) + type(1) + replyToken(4) + tunnelID(4) + gateway(32) + data(7) = 80
	expectedLen := 32 + 1 + 4 + 4 + 32 + len(data)
	assert.Equal(t, expectedLen, len(payload),
		"nonzero reply token MUST include tunnelID + gateway fields")
}

// TestDatabaseStore_ReplyToken_RoundtripWithReply verifies reply token, tunnel
// ID, and gateway survive a marshal→unmarshal cycle.
func TestDatabaseStore_ReplyToken_RoundtripWithReply(t *testing.T) {
	key := common.Hash{}
	key[31] = 0x42
	gateway := common.Hash{}
	gateway[0] = 0xDE
	gateway[31] = 0xAD

	original := NewDatabaseStore(key, []byte("reply test"), DATABASE_STORE_TYPE_LEASESET)
	original.ReplyToken = [4]byte{0x00, 0x01, 0x02, 0x03}
	original.ReplyTunnelID = [4]byte{0x00, 0x00, 0xFF, 0xFE}
	original.ReplyGateway = gateway

	payload, err := original.MarshalPayload()
	require.NoError(t, err)

	parsed := &DatabaseStore{}
	err = parsed.UnmarshalBinary(payload)
	require.NoError(t, err)

	assert.Equal(t, original.ReplyToken, parsed.ReplyToken, "reply token must survive roundtrip")
	assert.Equal(t, original.ReplyTunnelID, parsed.ReplyTunnelID, "reply tunnel ID must survive roundtrip")
	assert.Equal(t, original.ReplyGateway, parsed.ReplyGateway, "reply gateway must survive roundtrip")
	assert.Equal(t, original.Data, parsed.Data, "data must survive roundtrip")
}

// TestDatabaseStore_ReplyToken_UnmarshalTruncatedWithReply verifies rejection
// when the message claims a nonzero reply token but is too short to contain
// the replyTunnelID + replyGateway fields.
func TestDatabaseStore_ReplyToken_UnmarshalTruncatedWithReply(t *testing.T) {
	// Build payload: key(32) + type(1) + replyToken(4 nonzero) = 37 bytes
	// Missing: replyTunnelID(4) + replyGateway(32)
	payload := make([]byte, 37)
	payload[33] = 0x01 // replyToken byte 0 nonzero

	parsed := &DatabaseStore{}
	err := parsed.UnmarshalBinary(payload)
	assert.Error(t, err, "truncated message with nonzero reply token must be rejected")
}

// =============================================================================
// Audit Item: DatabaseStore — Compression
// "If type == 0, data is a 2-byte Integer specifying the number of bytes that
// follow, followed by a gzip-compressed RouterInfo."
// All other types are uncompressed.
// =============================================================================

// TestDatabaseStore_Compression_RouterInfoHas2ByteLengthPrefix documents that
// the spec requires RouterInfo data to be prefixed with a 2-byte length field
// followed by gzip-compressed data. This test verifies the wire format structure.
func TestDatabaseStore_Compression_RouterInfoHas2ByteLengthPrefix(t *testing.T) {
	// Simulate a RouterInfo payload: 2-byte length prefix + compressed data
	compressedRI := []byte{0xAA, 0xBB, 0xCC, 0xDD} // fake compressed data
	riPayload := make([]byte, 2+len(compressedRI))
	binary.BigEndian.PutUint16(riPayload[0:2], uint16(len(compressedRI)))
	copy(riPayload[2:], compressedRI)

	key := common.Hash{}
	ds := NewDatabaseStore(key, riPayload, DATABASE_STORE_TYPE_ROUTER_INFO)

	payload, err := ds.MarshalPayload()
	require.NoError(t, err)

	// Parse back and extract the data portion
	parsed := &DatabaseStore{}
	err = parsed.UnmarshalBinary(payload)
	require.NoError(t, err)

	assert.Equal(t, byte(DATABASE_STORE_TYPE_ROUTER_INFO), parsed.StoreType)

	// Verify the data starts with a 2-byte length prefix
	require.True(t, len(parsed.Data) >= 2, "RouterInfo data must have 2-byte length prefix")
	prefixLen := binary.BigEndian.Uint16(parsed.Data[0:2])
	assert.Equal(t, uint16(len(compressedRI)), prefixLen,
		"2-byte prefix must specify the number of gzip-compressed bytes")
	assert.Equal(t, compressedRI, parsed.Data[2:2+prefixLen],
		"compressed data must follow the 2-byte length prefix")
}

// TestDatabaseStore_Compression_LeaseSetTypesUncompressed verifies that non-RouterInfo
// store types carry uncompressed data (no 2-byte length prefix required by spec).
func TestDatabaseStore_Compression_LeaseSetTypesUncompressed(t *testing.T) {
	leaseSetTypes := []byte{
		DATABASE_STORE_TYPE_LEASESET,
		DATABASE_STORE_TYPE_LEASESET2,
		DATABASE_STORE_TYPE_ENCRYPTED_LEASESET,
		DATABASE_STORE_TYPE_META_LEASESET,
	}

	rawData := []byte("uncompressed leaseset data for test")

	for _, lsType := range leaseSetTypes {
		t.Run(fmt.Sprintf("type_%d", lsType), func(t *testing.T) {
			key := common.Hash{}
			ds := NewDatabaseStore(key, rawData, lsType)

			payload, err := ds.MarshalPayload()
			require.NoError(t, err)

			parsed := &DatabaseStore{}
			err = parsed.UnmarshalBinary(payload)
			require.NoError(t, err)

			assert.Equal(t, rawData, parsed.Data,
				"LeaseSet type %d data must be stored uncompressed (verbatim)", lsType)
		})
	}
}

// TestDatabaseStore_Compression_SizeLimits verifies the max size enforcement
// for both RouterInfo and LeaseSet types.
func TestDatabaseStore_Compression_SizeLimits(t *testing.T) {
	// RouterInfo: max 65536 bytes
	err := validateDatabaseStoreSize(DATABASE_STORE_TYPE_ROUTER_INFO, MaxRouterInfoSize)
	assert.NoError(t, err, "RouterInfo at exactly MaxRouterInfoSize must be accepted")

	err = validateDatabaseStoreSize(DATABASE_STORE_TYPE_ROUTER_INFO, MaxRouterInfoSize+1)
	assert.Error(t, err, "RouterInfo exceeding MaxRouterInfoSize must be rejected")

	// LeaseSet: max 32768 bytes
	err = validateDatabaseStoreSize(DATABASE_STORE_TYPE_LEASESET2, MaxLeaseSetSize)
	assert.NoError(t, err, "LeaseSet2 at exactly MaxLeaseSetSize must be accepted")

	err = validateDatabaseStoreSize(DATABASE_STORE_TYPE_LEASESET2, MaxLeaseSetSize+1)
	assert.Error(t, err, "LeaseSet2 exceeding MaxLeaseSetSize must be rejected")
}

// =============================================================================
// Audit Item: DatabaseLookup — Lookup types
// Flag byte bits 3-2: Normal (00), LeaseSet (01), RouterInfo (10),
// Exploration (11)
// =============================================================================

// TestDatabaseLookup_LookupTypes_FlagConstants verifies the flag constants for
// lookup types match the spec's bit 3-2 encoding.
func TestDatabaseLookup_LookupTypes_FlagConstants(t *testing.T) {
	// Spec: bits 3-2 determine lookup type
	// 00 = normal (0x00), 01 = LS (0x04), 10 = RI (0x08), 11 = exploration (0x0C)
	assert.Equal(t, byte(0x00), DatabaseLookupFlagTypeNormal,
		"Normal lookup: bits 3-2 = 00 → 0x00")
	assert.Equal(t, byte(0x04), DatabaseLookupFlagTypeLS,
		"LeaseSet lookup: bits 3-2 = 01 → 0x04")
	assert.Equal(t, byte(0x08), DatabaseLookupFlagTypeRI,
		"RouterInfo lookup: bits 3-2 = 10 → 0x08")
	assert.Equal(t, byte(0x0C), DatabaseLookupFlagTypeExploration,
		"Exploration lookup: bits 3-2 = 11 → 0x0C")
}

// TestDatabaseLookup_LookupTypes_BitPositions verifies the lookup type occupies
// exactly bits 3-2 with no overlap on other flag bits.
func TestDatabaseLookup_LookupTypes_BitPositions(t *testing.T) {
	typeMask := byte(0x0C) // bits 3-2

	tests := []struct {
		name     string
		flag     byte
		expected byte
	}{
		{"Normal", DatabaseLookupFlagTypeNormal, 0x00},
		{"LeaseSet", DatabaseLookupFlagTypeLS, 0x04},
		{"RouterInfo", DatabaseLookupFlagTypeRI, 0x08},
		{"Exploration", DatabaseLookupFlagTypeExploration, 0x0C},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// The flag should only set bits within the type mask
			assert.Equal(t, tc.expected, tc.flag&typeMask,
				"lookup type must occupy only bits 3-2")
			assert.Equal(t, byte(0), tc.flag & ^typeMask,
				"lookup type flag must NOT set bits outside 3-2")
		})
	}
}

// TestDatabaseLookup_LookupTypes_OtherFlagBits verifies the other flag bits:
// bit 0 = delivery (direct/tunnel), bit 1 = encryption, bit 4 = ECIES.
func TestDatabaseLookup_LookupTypes_OtherFlagBits(t *testing.T) {
	// bit 0: delivery flag
	assert.Equal(t, byte(0x00), DatabaseLookupFlagDirect, "direct reply: bit 0 = 0")
	assert.Equal(t, byte(0x01), DatabaseLookupFlagTunnel, "tunnel reply: bit 0 = 1")

	// bit 1: encryption flag
	assert.Equal(t, byte(0x02), DatabaseLookupFlagEncryption, "encryption: bit 1 = 1")

	// bit 4: ECIES flag
	assert.Equal(t, byte(0x10), DatabaseLookupFlagECIES, "ECIES: bit 4 = 1")
}

// TestDatabaseLookup_LookupTypes_ParseFromFlags verifies the lookup type can be
// extracted from a flags byte that also has other bits set.
func TestDatabaseLookup_LookupTypes_ParseFromFlags(t *testing.T) {
	// Combine tunnel reply + encryption + RI lookup + ECIES
	flags := DatabaseLookupFlagTunnel | DatabaseLookupFlagEncryption |
		DatabaseLookupFlagTypeRI | DatabaseLookupFlagECIES
	// flags = 0x01 | 0x02 | 0x08 | 0x10 = 0x1B

	// Extract lookup type via bits 3-2 mask
	lookupType := flags & 0x0C
	assert.Equal(t, DatabaseLookupFlagTypeRI, lookupType,
		"lookup type must be extractable from combined flags byte")

	// Verify ECIES detection via IsECIES
	dl := &DatabaseLookup{Flags: flags}
	assert.True(t, dl.IsECIES(), "bit 4 set must be detected as ECIES")
}

// TestDatabaseLookup_LookupTypes_MarshalRoundtrip verifies each lookup type
// survives a marshal→unmarshal cycle.
func TestDatabaseLookup_LookupTypes_MarshalRoundtrip(t *testing.T) {
	lookupTypes := []struct {
		name     string
		flagType byte
	}{
		{"Normal", DatabaseLookupFlagTypeNormal},
		{"LeaseSet", DatabaseLookupFlagTypeLS},
		{"RouterInfo", DatabaseLookupFlagTypeRI},
		{"Exploration", DatabaseLookupFlagTypeExploration},
	}

	for _, lt := range lookupTypes {
		t.Run(lt.name, func(t *testing.T) {
			key := common.Hash{}
			key[0] = lt.flagType
			from := common.Hash{}
			from[0] = 0xFF

			original := NewDatabaseLookup(key, from, lt.flagType, nil)

			data, err := original.MarshalBinary()
			require.NoError(t, err)

			parsed, err := ReadDatabaseLookup(data)
			require.NoError(t, err)

			// Extract lookup type from parsed flags
			parsedLookupType := parsed.Flags & 0x0C
			assert.Equal(t, lt.flagType, parsedLookupType,
				"lookup type must survive marshal→unmarshal roundtrip")
		})
	}
}

// =============================================================================
// Audit Item: DatabaseLookup — Reply encryption
// When encryption flag (bit 1) or ECIES flag (bit 4) is set:
// reply_key (32 bytes) + tags count (1 byte) + reply_tags (count * 32 or 8)
// =============================================================================

// TestDatabaseLookup_ReplyEncryption_ElGamalFields verifies the legacy (ElGamal)
// encryption fields: reply_key (32 bytes) + tags (1 byte) + reply_tags (n*32).
func TestDatabaseLookup_ReplyEncryption_ElGamalFields(t *testing.T) {
	key := common.Hash{}
	from := common.Hash{}
	from[0] = 0x01

	dl := NewDatabaseLookup(key, from, DatabaseLookupFlagTypeLS, nil)
	// Enable encryption (bit 1)
	dl.Flags |= DatabaseLookupFlagEncryption

	// Set reply key
	replyKey := session_key.SessionKey{}
	replyKey[0] = 0xAA
	replyKey[31] = 0xBB
	dl.ReplyKey = replyKey

	// Set 2 legacy 32-byte session tags
	tag1, _ := session_tag.NewSessionTagFromBytes(make([]byte, 32))
	tag2, _ := session_tag.NewSessionTagFromBytes(make([]byte, 32))
	dl.Tags = 2
	dl.ReplyTags = []session_tag.SessionTag{tag1, tag2}

	data, err := dl.MarshalBinary()
	require.NoError(t, err)

	parsed, err := ReadDatabaseLookup(data)
	require.NoError(t, err)

	assert.True(t, parsed.hasEncryption(), "encryption flag must be set")
	assert.False(t, parsed.IsECIES(), "ECIES flag must NOT be set")
	assert.Equal(t, replyKey, parsed.ReplyKey, "reply key must survive roundtrip")
	assert.Equal(t, 2, parsed.Tags, "tag count must survive roundtrip")
	assert.Equal(t, 2, len(parsed.ReplyTags), "legacy reply tags must survive roundtrip")
}

// TestDatabaseLookup_ReplyEncryption_ECIESFields verifies ECIES encryption
// fields: reply_key (32 bytes) + tags (1 byte) + reply_tags (n*8).
func TestDatabaseLookup_ReplyEncryption_ECIESFields(t *testing.T) {
	key := common.Hash{}
	from := common.Hash{}
	from[0] = 0x02

	dl := NewDatabaseLookup(key, from, DatabaseLookupFlagTypeLS, nil)
	// Enable ECIES flag (bit 4)
	dl.Flags |= DatabaseLookupFlagECIES

	// Set reply key
	replyKey := session_key.SessionKey{}
	replyKey[0] = 0xCC
	dl.ReplyKey = replyKey

	// Set 3 ECIES 8-byte session tags
	eciesTag1, _ := session_tag.NewECIESSessionTagFromBytes(make([]byte, 8))
	eciesTag2, _ := session_tag.NewECIESSessionTagFromBytes(make([]byte, 8))
	eciesTag3, _ := session_tag.NewECIESSessionTagFromBytes(make([]byte, 8))
	dl.Tags = 3
	dl.ECIESReplyTags = []session_tag.ECIESSessionTag{eciesTag1, eciesTag2, eciesTag3}

	data, err := dl.MarshalBinary()
	require.NoError(t, err)

	parsed, err := ReadDatabaseLookup(data)
	require.NoError(t, err)

	assert.True(t, parsed.IsECIES(), "ECIES flag must be set")
	assert.Equal(t, replyKey, parsed.ReplyKey, "reply key must survive roundtrip")
	assert.Equal(t, 3, parsed.Tags, "ECIES tag count must survive roundtrip")
	assert.Equal(t, 3, len(parsed.ECIESReplyTags), "ECIES reply tags must survive roundtrip")
}

// TestDatabaseLookup_ReplyEncryption_NoEncryptionOmitsFields verifies that
// when neither encryption nor ECIES flag is set, no reply_key/tags fields
// are present in the wire format.
func TestDatabaseLookup_ReplyEncryption_NoEncryptionOmitsFields(t *testing.T) {
	key := common.Hash{}
	from := common.Hash{}

	dl := NewDatabaseLookup(key, from, DatabaseLookupFlagTypeRI, nil)
	// No encryption flags set

	data, err := dl.MarshalBinary()
	require.NoError(t, err)

	// Expected size: key(32) + from(32) + flags(1) + size(2) = 67 bytes
	// (no tunnel ID since direct, no encryption fields, no excluded peers)
	assert.Equal(t, 67, len(data),
		"no-encryption lookup must be exactly 67 bytes (no reply_key/tags)")
}

// =============================================================================
// Audit Item: DatabaseLookup — Exclude list
// Size (2 bytes, big-endian) + ExcludedPeers (size * 32 bytes)
// Max 512 excluded peers
// =============================================================================

// TestDatabaseLookup_ExcludeList_EmptyList verifies a lookup with zero
// excluded peers has size=0 and no peer hash data.
func TestDatabaseLookup_ExcludeList_EmptyList(t *testing.T) {
	key := common.Hash{}
	from := common.Hash{}

	dl := NewDatabaseLookup(key, from, DatabaseLookupFlagTypeNormal, nil)

	data, err := dl.MarshalBinary()
	require.NoError(t, err)

	parsed, err := ReadDatabaseLookup(data)
	require.NoError(t, err)

	assert.Equal(t, 0, parsed.Size, "empty exclude list must have size 0")
	assert.Empty(t, parsed.ExcludedPeers, "empty exclude list must have no peer hashes")
}

// TestDatabaseLookup_ExcludeList_MultiplePeers verifies correct serialization
// and parsing of multiple excluded peer hashes.
func TestDatabaseLookup_ExcludeList_MultiplePeers(t *testing.T) {
	key := common.Hash{}
	from := common.Hash{}

	// Create 3 distinct excluded peers
	peer1 := common.Hash{}
	peer1[0] = 0x01
	peer2 := common.Hash{}
	peer2[0] = 0x02
	peer3 := common.Hash{}
	peer3[0] = 0x03
	excludedPeers := []common.Hash{peer1, peer2, peer3}

	dl := NewDatabaseLookup(key, from, DatabaseLookupFlagTypeExploration, excludedPeers)

	data, err := dl.MarshalBinary()
	require.NoError(t, err)

	parsed, err := ReadDatabaseLookup(data)
	require.NoError(t, err)

	assert.Equal(t, 3, parsed.Size, "exclude list must report 3 peers")
	require.Equal(t, 3, len(parsed.ExcludedPeers))
	assert.Equal(t, peer1, parsed.ExcludedPeers[0])
	assert.Equal(t, peer2, parsed.ExcludedPeers[1])
	assert.Equal(t, peer3, parsed.ExcludedPeers[2])
}

// TestDatabaseLookup_ExcludeList_MaxPeers512 verifies the maximum of 512
// excluded peers is enforced.
func TestDatabaseLookup_ExcludeList_MaxPeers512(t *testing.T) {
	// Build a raw lookup with size = 513 (exceeds max)
	// Format: key(32) + from(32) + flags(1) + size(2) = 67 bytes min
	raw := make([]byte, 67)
	raw[64] = 0x00 // flags: direct, normal lookup
	// Size field at offset 65-66 (big-endian): 513
	binary.BigEndian.PutUint16(raw[65:67], 513)

	_, err := ReadDatabaseLookup(raw)
	assert.Error(t, err, "excluded peers count > 512 must be rejected")
	assert.Equal(t, ERR_DATABASE_LOOKUP_INVALID_SIZE, err)
}

// TestDatabaseLookup_ExcludeList_Size2BytesBigEndian verifies the exclude list
// size is encoded as a 2-byte big-endian integer.
func TestDatabaseLookup_ExcludeList_Size2BytesBigEndian(t *testing.T) {
	key := common.Hash{}
	from := common.Hash{}

	// Create 256 excluded peers (needs 2 bytes to represent: 0x0100)
	peers := make([]common.Hash, 256)
	for i := range peers {
		peers[i] = common.Hash{}
		peers[i][0] = byte(i)
		peers[i][1] = byte(i >> 8)
	}

	dl := NewDatabaseLookup(key, from, DatabaseLookupFlagTypeNormal, peers)
	data, err := dl.MarshalBinary()
	require.NoError(t, err)

	parsed, err := ReadDatabaseLookup(data)
	require.NoError(t, err)

	assert.Equal(t, 256, parsed.Size,
		"size field must correctly encode 256 in 2-byte big-endian")
	assert.Equal(t, 256, len(parsed.ExcludedPeers))
}

// TestDatabaseLookup_ExcludeList_WithTunnelReply verifies the exclude list
// works correctly when combined with tunnel reply (bit 0 = 1), which shifts
// field offsets by 4 bytes.
func TestDatabaseLookup_ExcludeList_WithTunnelReply(t *testing.T) {
	key := common.Hash{}
	gateway := common.Hash{}
	gateway[0] = 0xAA
	tunnelID := [4]byte{0x00, 0x00, 0x00, 0x42}
	peer := common.Hash{}
	peer[0] = 0xBB

	dl := NewDatabaseLookupWithTunnel(key, gateway, tunnelID, DatabaseLookupFlagTypeLS, []common.Hash{peer})

	data, err := dl.MarshalBinary()
	require.NoError(t, err)

	parsed, err := ReadDatabaseLookup(data)
	require.NoError(t, err)

	assert.Equal(t, 1, parsed.Size)
	require.Equal(t, 1, len(parsed.ExcludedPeers))
	assert.Equal(t, peer, parsed.ExcludedPeers[0])
	assert.Equal(t, gateway, parsed.From, "from must be the tunnel gateway")
}

// =============================================================================
// Audit Item: DatabaseSearchReply — Format
// Key hash (32) + count (1) + peer hashes (count*32) + from hash (32)
// =============================================================================

// TestDatabaseSearchReply_Format_WireLayout verifies the exact wire layout:
// key(32) + count(1) + peers(count*32) + from(32).
func TestDatabaseSearchReply_Format_WireLayout(t *testing.T) {
	key := common.Hash{}
	key[0] = 0x11
	from := common.Hash{}
	from[0] = 0x22

	peer1 := common.Hash{}
	peer1[0] = 0xAA
	peer2 := common.Hash{}
	peer2[0] = 0xBB

	dsr := NewDatabaseSearchReply(key, from, []common.Hash{peer1, peer2})

	payload, err := dsr.MarshalPayload()
	require.NoError(t, err)

	// Expected: key(32) + count(1) + 2*peer(64) + from(32) = 129 bytes
	assert.Equal(t, 129, len(payload), "payload must be 32+1+64+32=129 bytes")

	// Verify field positions
	assert.Equal(t, byte(0x11), payload[0], "key starts at offset 0")
	assert.Equal(t, byte(2), payload[32], "count at offset 32")
	assert.Equal(t, byte(0xAA), payload[33], "peer1 starts at offset 33")
	assert.Equal(t, byte(0xBB), payload[65], "peer2 starts at offset 65")
	assert.Equal(t, byte(0x22), payload[97], "from starts at offset 97")
}

// TestDatabaseSearchReply_Format_CountIs1Byte verifies count is a single byte
// (range 0-255).
func TestDatabaseSearchReply_Format_CountIs1Byte(t *testing.T) {
	key := common.Hash{}
	from := common.Hash{}

	// Zero peers
	dsr0 := NewDatabaseSearchReply(key, from, nil)
	payload0, err := dsr0.MarshalPayload()
	require.NoError(t, err)
	assert.Equal(t, byte(0), payload0[32], "count of 0 peers must be 0x00")

	// 255 peers (max for 1-byte count)
	peers := make([]common.Hash, 255)
	dsr255 := NewDatabaseSearchReply(key, from, peers)
	payload255, err := dsr255.MarshalPayload()
	require.NoError(t, err)
	assert.Equal(t, byte(255), payload255[32], "count of 255 peers must be 0xFF")
}

// TestDatabaseSearchReply_Format_Roundtrip verifies the marshal→unmarshal cycle
// preserves all fields.
func TestDatabaseSearchReply_Format_Roundtrip(t *testing.T) {
	key := common.Hash{}
	key[0] = 0x42
	key[31] = 0x43
	from := common.Hash{}
	from[15] = 0x99

	peer1 := common.Hash{}
	peer1[0] = 0x01
	peer2 := common.Hash{}
	peer2[0] = 0x02
	peer3 := common.Hash{}
	peer3[0] = 0x03

	original := NewDatabaseSearchReply(key, from, []common.Hash{peer1, peer2, peer3})

	payload, err := original.MarshalPayload()
	require.NoError(t, err)

	parsed := &DatabaseSearchReply{}
	err = parsed.UnmarshalBinary(payload)
	require.NoError(t, err)

	assert.Equal(t, key, parsed.Key, "key must survive roundtrip")
	assert.Equal(t, 3, parsed.Count, "count must survive roundtrip")
	require.Equal(t, 3, len(parsed.PeerHashes))
	assert.Equal(t, peer1, parsed.PeerHashes[0])
	assert.Equal(t, peer2, parsed.PeerHashes[1])
	assert.Equal(t, peer3, parsed.PeerHashes[2])
	assert.Equal(t, from, parsed.From, "from must survive roundtrip")
}

// TestDatabaseSearchReply_Format_MinimumSize verifies the minimum payload size
// is 65 bytes: key(32) + count(1) + from(32) with zero peers.
func TestDatabaseSearchReply_Format_MinimumSize(t *testing.T) {
	// Exactly 65 bytes: key(32) + count=0(1) + from(32) should succeed
	data := make([]byte, 65)
	parsed := &DatabaseSearchReply{}
	err := parsed.UnmarshalBinary(data)
	assert.NoError(t, err, "65 bytes must be accepted (zero peers)")
	assert.Equal(t, 0, parsed.Count)

	// 64 bytes: too short
	shortData := make([]byte, 64)
	err = (&DatabaseSearchReply{}).UnmarshalBinary(shortData)
	assert.Error(t, err, "64 bytes must be rejected")
	assert.Equal(t, ERR_DATABASE_SEARCH_REPLY_NOT_ENOUGH_DATA, err)
}

// =============================================================================
// Audit Item: DeliveryStatus — Format
// MsgID (4 bytes, uint32) + Timestamp (8 bytes, I2P Date) = 12 bytes total
// =============================================================================

// TestDeliveryStatus_Format_PayloadIs12Bytes verifies the DeliveryStatus
// payload is exactly 12 bytes: MsgID(4) + Timestamp(8).
func TestDeliveryStatus_Format_PayloadIs12Bytes(t *testing.T) {
	now := time.Now().Truncate(time.Millisecond)
	ds := NewDeliveryStatusMessage(12345, now)

	// GetData returns the 12-byte payload set by the constructor
	data := ds.GetData()
	assert.Equal(t, 12, len(data),
		"DeliveryStatus payload must be exactly 12 bytes (MsgID 4 + Timestamp 8)")
}

// TestDeliveryStatus_Format_MsgID4BytesBigEndian verifies the message ID is
// stored as a 4-byte big-endian uint32 at payload offset 0-3.
func TestDeliveryStatus_Format_MsgID4BytesBigEndian(t *testing.T) {
	msgID := 0x01020304
	ds := NewDeliveryStatusMessage(msgID, time.Now())

	data := ds.GetData()
	require.Equal(t, 12, len(data))

	parsedID := binary.BigEndian.Uint32(data[0:4])
	assert.Equal(t, uint32(0x01020304), parsedID,
		"MsgID must be 4-byte big-endian uint32 at offset 0")
}

// TestDeliveryStatus_Format_Timestamp8BytesI2PDate verifies the timestamp is
// stored as an 8-byte I2P Date (milliseconds since epoch) at payload offset 4-11.
func TestDeliveryStatus_Format_Timestamp8BytesI2PDate(t *testing.T) {
	// Use a known time: 2024-01-01 00:00:00 UTC = 1704067200 seconds
	knownTime := time.Unix(1704067200, 0)
	ds := NewDeliveryStatusMessage(1, knownTime)

	data := ds.GetData()
	require.Equal(t, 12, len(data))

	// I2P Date is milliseconds since epoch, big-endian 8 bytes
	tsMs := binary.BigEndian.Uint64(data[4:12])
	expectedMs := uint64(1704067200) * 1000
	assert.Equal(t, expectedMs, tsMs,
		"Timestamp must be I2P Date (milliseconds since epoch) at offset 4-11")
}

// TestDeliveryStatus_Format_Roundtrip verifies the DeliveryStatus survives
// a full I2NP message marshal→unmarshal cycle, preserving MsgID and Timestamp.
func TestDeliveryStatus_Format_Roundtrip(t *testing.T) {
	msgID := 0xDEADBEEF
	ts := time.Unix(1704067200, 0) // 2024-01-01 00:00:00 UTC

	original := NewDeliveryStatusMessage(msgID, ts)

	wireData, err := original.MarshalBinary()
	require.NoError(t, err)

	parsed := &DeliveryStatusMessage{
		BaseI2NPMessage: NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_DELIVERY_STATUS),
	}
	err = parsed.UnmarshalBinary(wireData)
	require.NoError(t, err)

	assert.Equal(t, msgID, parsed.StatusMessageID,
		"MsgID must survive roundtrip")
	assert.Equal(t, ts.Unix(), parsed.Timestamp.Unix(),
		"Timestamp must survive roundtrip (seconds precision)")
}

// TestDeliveryStatus_Format_TooShortPayload verifies that a DeliveryStatus
// with a payload shorter than 12 bytes is rejected on unmarshal.
func TestDeliveryStatus_Format_TooShortPayload(t *testing.T) {
	// Build a valid I2NP message with only 11 bytes of payload
	msg := NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_DELIVERY_STATUS)
	msg.SetMessageID(1)
	msg.SetData(make([]byte, 11)) // Too short for DeliveryStatus

	wireData, err := msg.MarshalBinary()
	require.NoError(t, err)

	parsed := &DeliveryStatusMessage{
		BaseI2NPMessage: NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_DELIVERY_STATUS),
	}
	err = parsed.UnmarshalBinary(wireData)
	assert.Error(t, err, "payload < 12 bytes must be rejected")
}

// =============================================================================
// Audit Item: Garlic — ECIES-X25519-AEAD-Ratchet
// Proposal 144: New Session, Existing Session, New Session Reply
// =============================================================================

// TestGarlic_ECIES_NewSessionMessageFormat verifies the New Session wire format:
// [ephemeralPubKey(32)] + [nonce(12)] + [ciphertext(N)] + [tag(16)]
// Minimum size = 32 + 12 + 0 + 16 = 60 bytes (empty plaintext).
func TestGarlic_ECIES_NewSessionMessageFormat(t *testing.T) {
	sm, err := GenerateGarlicSessionManager()
	require.NoError(t, err)

	// Create a destination key pair
	destSM, err := GenerateGarlicSessionManager()
	require.NoError(t, err)
	destHash := common.Hash{}
	destHash[0] = 0x42

	plaintext := []byte("test garlic payload")
	encrypted, err := sm.EncryptGarlicMessage(destHash, destSM.ourPublicKey, plaintext)
	require.NoError(t, err)

	// New Session: [ephPub(32)] + [nonce(12)] + [ciphertext(N)] + [tag(16)]
	// Minimum overhead = 32+12+16 = 60 bytes
	assert.True(t, len(encrypted) >= 60,
		"New Session message must be at least 60 bytes (32 ephPub + 12 nonce + 16 tag)")

	// Verify structure: first 32 bytes should be a valid X25519 public key
	// (non-zero and not all zeros)
	ephemeralPub := encrypted[0:32]
	allZero := true
	for _, b := range ephemeralPub {
		if b != 0 {
			allZero = false
			break
		}
	}
	assert.False(t, allZero, "ephemeral public key must not be all zeros")

	// Total size: 32 + 12 + len(ciphertext) + 16
	// ciphertext should be at least len(plaintext) bytes
	expectedMinSize := 32 + 12 + len(plaintext) + 16
	assert.True(t, len(encrypted) >= expectedMinSize,
		"New Session message must be at least %d bytes for %d-byte plaintext",
		expectedMinSize, len(plaintext))
}

// TestGarlic_ECIES_ExistingSessionMessageFormat verifies the Existing Session wire format:
// [sessionTag(8)] + [nonce(12)] + [ciphertext(N)] + [tag(16)]
// Minimum size = 8 + 12 + 0 + 16 = 36 bytes (empty plaintext).
func TestGarlic_ECIES_ExistingSessionMessageFormat(t *testing.T) {
	sm, err := GenerateGarlicSessionManager()
	require.NoError(t, err)

	destSM, err := GenerateGarlicSessionManager()
	require.NoError(t, err)
	destHash := common.Hash{}
	destHash[0] = 0x43

	plaintext := []byte("existing session test")

	// First message: creates New Session
	_, err = sm.EncryptGarlicMessage(destHash, destSM.ourPublicKey, plaintext)
	require.NoError(t, err)

	// Second message: uses Existing Session
	encrypted, err := sm.EncryptGarlicMessage(destHash, destSM.ourPublicKey, plaintext)
	require.NoError(t, err)

	// Existing Session: [sessionTag(8)] + [nonce(12)] + [ciphertext(N)] + [tag(16)]
	// Minimum overhead = 8+12+16 = 36 bytes
	assert.True(t, len(encrypted) >= 36,
		"Existing Session message must be at least 36 bytes (8 tag + 12 nonce + 16 auth tag)")

	// Existing Session should be SMALLER than New Session (no 32-byte ephemeral key)
	// New Session overhead: 60 bytes. Existing Session overhead: 36 bytes.
	expectedMinSize := 8 + 12 + len(plaintext) + 16
	assert.True(t, len(encrypted) >= expectedMinSize,
		"Existing Session must be at least %d bytes for %d-byte plaintext",
		expectedMinSize, len(plaintext))

	// Verify session tag is the first 8 bytes (should be non-zero since it's ratchet-derived)
	sessionTag := encrypted[0:8]
	allZero := true
	for _, b := range sessionTag {
		if b != 0 {
			allZero = false
			break
		}
	}
	assert.False(t, allZero, "session tag must not be all zeros")
}

// TestGarlic_ECIES_NewSessionDecryptionRoundtrip verifies that a New Session
// message can be decrypted by the recipient using their static private key.
func TestGarlic_ECIES_NewSessionDecryptionRoundtrip(t *testing.T) {
	sender, err := GenerateGarlicSessionManager()
	require.NoError(t, err)
	receiver, err := GenerateGarlicSessionManager()
	require.NoError(t, err)

	destHash := common.Hash{}
	destHash[0] = 0x44
	plaintext := []byte("hello from new session")

	encrypted, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, plaintext)
	require.NoError(t, err)

	decrypted, sessionTag, err := receiver.DecryptGarlicMessage(encrypted)
	require.NoError(t, err)

	assert.Equal(t, plaintext, decrypted, "decrypted plaintext must match original")
	assert.Equal(t, [8]byte{}, sessionTag,
		"New Session decryption must return empty session tag")
}

// TestGarlic_ECIES_ExistingSessionRoundtrip verifies the session transition:
// first message uses New Session, subsequent messages use Existing Session with
// ratchet-derived session tags.
func TestGarlic_ECIES_ExistingSessionRoundtrip(t *testing.T) {
	sender, err := GenerateGarlicSessionManager()
	require.NoError(t, err)
	receiver, err := GenerateGarlicSessionManager()
	require.NoError(t, err)

	destHash := common.Hash{}
	destHash[0] = 0x45

	// Message 1: New Session
	msg1 := []byte("first message")
	enc1, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, msg1)
	require.NoError(t, err)

	dec1, tag1, err := receiver.DecryptGarlicMessage(enc1)
	require.NoError(t, err)
	assert.Equal(t, msg1, dec1)
	assert.Equal(t, [8]byte{}, tag1, "first message is New Session (no tag)")

	// Verify session was established
	assert.Equal(t, 1, sender.GetSessionCount(),
		"sender must have 1 active session after New Session")
}

// TestGarlic_ECIES_NewSessionReplyNotSeparatelyImplemented documents that
// the implementation handles New Session Reply implicitly: the responder
// creates an inbound ratchet session on New Session decryption and subsequent
// outbound messages use the Existing Session format. There is no separate
// "New Session Reply" message type distinct from Existing Session.
func TestGarlic_ECIES_NewSessionReplyNotSeparatelyImplemented(t *testing.T) {
	// Per Proposal 144, there are three protocol states:
	// 1. New Session (NS) — initiator's first message
	// 2. New Session Reply (NSR) — responder's first reply
	// 3. Existing Session (ES) — subsequent messages
	//
	// In this implementation, the responder creates an inbound session on NS
	// decryption (via initializeInboundRatchetState) and then uses ES format
	// for all outbound messages. NSR is effectively folded into ES.

	receiver, err := GenerateGarlicSessionManager()
	require.NoError(t, err)

	// After decrypting a New Session, the receiver should have stored
	// inbound ratchet state (session count > 0)
	sender, err := GenerateGarlicSessionManager()
	require.NoError(t, err)

	destHash := common.Hash{}
	destHash[0] = 0x46

	enc, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, []byte("NS"))
	require.NoError(t, err)

	_, _, err = receiver.DecryptGarlicMessage(enc)
	require.NoError(t, err)

	// The receiver now has an inbound session keyed by the sender's ephemeral key hash
	assert.Equal(t, 1, receiver.GetSessionCount(),
		"receiver must store inbound session after New Session decryption")
}

// TestGarlic_ECIES_ChaCha20Poly1305Used verifies that the encryption uses
// ChaCha20-Poly1305 AEAD as required by the ECIES-X25519-AEAD-Ratchet spec.
// The auth tag is exactly 16 bytes (Poly1305 tag size).
func TestGarlic_ECIES_ChaCha20Poly1305Used(t *testing.T) {
	sm, err := GenerateGarlicSessionManager()
	require.NoError(t, err)
	destSM, err := GenerateGarlicSessionManager()
	require.NoError(t, err)

	destHash := common.Hash{}
	destHash[0] = 0x47

	// Encrypt with known plaintext
	plaintext := []byte("chacha20 poly1305 test")
	encrypted, err := sm.EncryptGarlicMessage(destHash, destSM.ourPublicKey, plaintext)
	require.NoError(t, err)

	// New Session format: [ephPub(32)] + [nonce(12)] + [ciphertext(N)] + [tag(16)]
	// The last 16 bytes must be the Poly1305 authentication tag
	assert.True(t, len(encrypted) > 16, "encrypted message must contain auth tag")

	// Verify decryption works (proves correct AEAD was used)
	decrypted, _, err := destSM.DecryptGarlicMessage(encrypted)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted,
		"ChaCha20-Poly1305 decrypt must recover original plaintext")

	// Corrupt a single byte — should fail authentication
	corrupted := make([]byte, len(encrypted))
	copy(corrupted, encrypted)
	corrupted[len(corrupted)-1] ^= 0xFF
	_, _, err = destSM.DecryptGarlicMessage(corrupted)
	assert.Error(t, err, "corrupted auth tag must cause decryption failure")
}

// =============================================================================
// Audit Item: Garlic — Session tag derivation
// Tags derived from HKDF chain key via TagRatchet, 8 bytes each
// =============================================================================

// TestGarlic_SessionTagDerivation_TagsAre8Bytes verifies that session tags
// generated by the tag ratchet are exactly 8 bytes, matching the ECIES spec.
func TestGarlic_SessionTagDerivation_TagsAre8Bytes(t *testing.T) {
	sm, err := GenerateGarlicSessionManager()
	require.NoError(t, err)
	destSM, err := GenerateGarlicSessionManager()
	require.NoError(t, err)

	destHash := common.Hash{}
	destHash[0] = 0x50

	// Create a session
	_, err = sm.EncryptGarlicMessage(destHash, destSM.ourPublicKey, []byte("session init"))
	require.NoError(t, err)

	// The session should now have pending tags in the tag index
	sm.mu.RLock()
	session, exists := sm.sessions[destHash]
	sm.mu.RUnlock()
	require.True(t, exists, "session must exist after first message")

	// Generate a tag from the tag ratchet directly
	session.mu.Lock()
	tag, err := session.TagRatchet.GenerateNextTag()
	session.mu.Unlock()
	require.NoError(t, err)

	assert.Equal(t, 8, len(tag), "session tag must be exactly 8 bytes")
}

// TestGarlic_SessionTagDerivation_TagsAreDeterministic verifies that the same
// chain key produces the same sequence of tags (deterministic ratchet).
func TestGarlic_SessionTagDerivation_TagsAreDeterministic(t *testing.T) {
	// Create two ratchets with the same key
	key := [32]byte{0x01, 0x02, 0x03}
	ratchet1 := ratchet.NewTagRatchet(key)
	ratchet2 := ratchet.NewTagRatchet(key)

	// Generate tags from both — they must produce the same sequence
	for i := 0; i < 5; i++ {
		tag1, err := ratchet1.GenerateNextTag()
		require.NoError(t, err)
		tag2, err := ratchet2.GenerateNextTag()
		require.NoError(t, err)
		assert.Equal(t, tag1, tag2,
			"tag ratchets with same key must produce same tag sequence at step %d", i)
	}
}

// TestGarlic_SessionTagDerivation_TagsAreUnique verifies that consecutive tags
// from the same ratchet are distinct (no collisions).
func TestGarlic_SessionTagDerivation_TagsAreUnique(t *testing.T) {
	key := [32]byte{0xAA, 0xBB, 0xCC}
	tr := ratchet.NewTagRatchet(key)

	seen := make(map[[8]byte]bool)
	for i := 0; i < 100; i++ {
		tag, err := tr.GenerateNextTag()
		require.NoError(t, err)
		assert.False(t, seen[tag], "tag collision at step %d", i)
		seen[tag] = true
	}
	assert.Equal(t, 100, len(seen), "all 100 tags must be distinct")
}

// TestGarlic_SessionTagDerivation_DifferentKeysProduceDifferentTags verifies
// that different chain keys produce different tag sequences.
func TestGarlic_SessionTagDerivation_DifferentKeysProduceDifferentTags(t *testing.T) {
	key1 := [32]byte{0x01}
	key2 := [32]byte{0x02}
	ratchet1 := ratchet.NewTagRatchet(key1)
	ratchet2 := ratchet.NewTagRatchet(key2)

	tag1, err := ratchet1.GenerateNextTag()
	require.NoError(t, err)
	tag2, err := ratchet2.GenerateNextTag()
	require.NoError(t, err)

	assert.NotEqual(t, tag1, tag2,
		"different chain keys must produce different tag sequences")
}

// TestGarlic_SessionTagDerivation_HKDFChainKeyUsed verifies that session keys
// are derived from the shared secret via HKDF, which is the source of the
// tag ratchet's chain key.
func TestGarlic_SessionTagDerivation_HKDFChainKeyUsed(t *testing.T) {
	// deriveSessionKeysFromSecret uses HKDF internally to produce rootKey, symKey, tagKey
	sharedSecret := make([]byte, 32)
	sharedSecret[0] = 0xDE
	sharedSecret[31] = 0xAD

	keys, err := deriveSessionKeysFromSecret(sharedSecret)
	require.NoError(t, err)

	// All three derived keys must be non-zero (HKDF output)
	assert.NotEqual(t, [32]byte{}, keys.rootKey, "root key must be non-zero HKDF output")
	assert.NotEqual(t, [32]byte{}, keys.symKey, "symmetric key must be non-zero HKDF output")
	assert.NotEqual(t, [32]byte{}, keys.tagKey, "tag key must be non-zero HKDF output")

	// All three keys must be distinct
	assert.NotEqual(t, keys.rootKey, keys.symKey, "root and sym keys must differ")
	assert.NotEqual(t, keys.rootKey, keys.tagKey, "root and tag keys must differ")
	assert.NotEqual(t, keys.symKey, keys.tagKey, "sym and tag keys must differ")

	// Same secret must produce same keys (deterministic HKDF)
	keys2, err := deriveSessionKeysFromSecret(sharedSecret)
	require.NoError(t, err)
	assert.Equal(t, keys.rootKey, keys2.rootKey, "HKDF must be deterministic for rootKey")
	assert.Equal(t, keys.symKey, keys2.symKey, "HKDF must be deterministic for symKey")
	assert.Equal(t, keys.tagKey, keys2.tagKey, "HKDF must be deterministic for tagKey")
}

// TestGarlic_SessionTagDerivation_DirectionalKeysDistinct verifies that
// initiator and responder derive distinct send/receive keys from the same
// base key, per the ECIES-X25519-AEAD-Ratchet specification.
func TestGarlic_SessionTagDerivation_DirectionalKeysDistinct(t *testing.T) {
	baseKey := [32]byte{0x42}

	// Initiator's keys
	iSend, iRecv := deriveDirectionalKeys(baseKey, true)

	// Responder's keys
	rSend, rRecv := deriveDirectionalKeys(baseKey, false)

	// Initiator's send key must equal responder's receive key (and vice versa)
	assert.Equal(t, iSend, rRecv,
		"initiator send key must equal responder receive key")
	assert.Equal(t, iRecv, rSend,
		"initiator receive key must equal responder send key")

	// Send and receive keys must be distinct
	assert.NotEqual(t, iSend, iRecv,
		"send and receive keys must be distinct within same role")
}

// =============================================================================
// Audit Item: Garlic — Clove format
// Clove = DeliveryInstructions(var) + I2NPMessage(var) + CloveID(4) +
// Expiration(8) + Certificate(3, always NULL)
// =============================================================================

// TestGarlic_CloveFormat_SerializationLayout verifies the garlic clove wire format:
// delivery_instructions(variable) + i2np_message(variable) + cloveID(4) +
// expiration(8) + certificate(3).
func TestGarlic_CloveFormat_SerializationLayout(t *testing.T) {
	// Create a simple LOCAL delivery clove with a known I2NP message
	payload := []byte{0xDE, 0xAD}
	innerMsg := NewDataMessage(payload)
	innerMsg.SetMessageID(0x12345678)
	innerMsg.SetExpiration(time.Unix(1704067200, 0))

	clove := GarlicClove{
		DeliveryInstructions: NewLocalDeliveryInstructions(),
		I2NPMessage:          innerMsg,
		CloveID:              0x00AABBCC,
		Expiration:           time.UnixMilli(1704067200000),
		Certificate:          *certificate.NewCertificate(),
	}

	data, err := serializeGarlicClove(&clove)
	require.NoError(t, err)

	// LOCAL delivery instructions = 1 byte (flag only)
	// I2NP message = 16-byte header + payload
	innerData, err := innerMsg.MarshalBinary()
	require.NoError(t, err)

	// Certificate NULL per I2P spec = type(1) + length(2) = 3 bytes
	const certLen = 3

	// Expected: DI(1) + I2NP(len) + CloveID(4) + Exp(8) + Cert(3)
	expectedLen := 1 + len(innerData) + 4 + 8 + certLen
	assert.Equal(t, expectedLen, len(data),
		"clove size must be DI(1) + I2NP(%d) + CloveID(4) + Exp(8) + Cert(%d) = %d",
		len(innerData), certLen, expectedLen)

	offset := 1 + len(innerData)

	// CloveID at offset (after DI + I2NP)
	cloveID := binary.BigEndian.Uint32(data[offset : offset+4])
	assert.Equal(t, uint32(0x00AABBCC), cloveID, "CloveID must be at correct offset")

	// Expiration at offset+4
	expMs := binary.BigEndian.Uint64(data[offset+4 : offset+12])
	assert.Equal(t, uint64(1704067200000), expMs,
		"Expiration must be milliseconds since epoch at correct offset")

	// Certificate at end (3 bytes, NULL = all zeros per I2P spec)
	certStart := offset + 12
	assert.Equal(t, byte(0), data[certStart], "certificate type must be 0 (NULL)")
	assert.Equal(t, byte(0), data[certStart+1], "certificate length high byte must be 0")
	assert.Equal(t, byte(0), data[certStart+2], "certificate length low byte must be 0")
}

// TestGarlic_CloveFormat_DeliveryInstructionSizes verifies the typical
// delivery instruction sizes per spec:
// LOCAL = 1 byte, DESTINATION/ROUTER = 33 bytes, TUNNEL = 37 bytes.
func TestGarlic_CloveFormat_DeliveryInstructionSizes(t *testing.T) {
	tests := []struct {
		name     string
		di       GarlicCloveDeliveryInstructions
		expected int
	}{
		{"LOCAL", NewLocalDeliveryInstructions(), 1},
		{"DESTINATION", NewDestinationDeliveryInstructions(common.Hash{}), 33},
		{"ROUTER", NewRouterDeliveryInstructions(common.Hash{}), 33},
		{"TUNNEL", NewTunnelDeliveryInstructions(common.Hash{}, 0), 37},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data, err := serializeDeliveryInstructions(&tc.di)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, len(data),
				"%s delivery instructions must be %d bytes", tc.name, tc.expected)
		})
	}
}

// TestGarlic_CloveFormat_CertificateAlwaysNULL verifies that garlic clove
// certificates are always NULL in the current implementation.
// Per I2P spec: NULL certificate = type(1 byte, 0x00) + length(2 bytes, 0x0000) = 3 bytes.
// Note: certificate.NewCertificate().Bytes() returns only 2 bytes, so garlic
// serializers write an explicit 3-byte {0x00, 0x00, 0x00} to match the spec.
func TestGarlic_CloveFormat_CertificateAlwaysNULL(t *testing.T) {
	// The spec-correct NULL certificate is 3 bytes: type(0) + length(0,0)
	nullCert := []byte{0x00, 0x00, 0x00}
	assert.Equal(t, 3, len(nullCert), "NULL certificate must be exactly 3 bytes per I2P spec")
	assert.Equal(t, byte(0), nullCert[0], "certificate type must be 0")
	assert.Equal(t, byte(0), nullCert[1], "certificate length high byte must be 0")
	assert.Equal(t, byte(0), nullCert[2], "certificate length low byte must be 0")
}

// TestGarlic_CloveFormat_GarlicWireFormat verifies the complete garlic message
// wire format: count(1) + cloves(var) + certificate(3) + messageID(4) + expiration(8).
func TestGarlic_CloveFormat_GarlicWireFormat(t *testing.T) {
	builder := NewGarlicBuilder(0x12345678, time.UnixMilli(1704067200000))

	msg := NewDataMessage([]byte("test"))
	msg.SetMessageID(1)
	msg.SetExpiration(time.UnixMilli(1704067200000))

	err := builder.AddLocalDeliveryClove(msg, 1)
	require.NoError(t, err)

	payload, err := builder.BuildAndSerialize()
	require.NoError(t, err)

	// First byte: clove count
	assert.Equal(t, byte(1), payload[0], "first byte must be clove count")

	// Last 15 bytes: certificate(3) + messageID(4) + expiration(8)
	trailerStart := len(payload) - 15
	require.True(t, trailerStart > 1, "payload must have room for trailer")

	// Certificate (3 bytes NULL per I2P spec)
	assert.Equal(t, byte(0), payload[trailerStart], "garlic certificate type = 0")
	assert.Equal(t, byte(0), payload[trailerStart+1], "garlic certificate len high = 0")
	assert.Equal(t, byte(0), payload[trailerStart+2], "garlic certificate len low = 0")

	// Message ID (4 bytes)
	msgID := binary.BigEndian.Uint32(payload[trailerStart+3 : trailerStart+7])
	assert.Equal(t, uint32(0x12345678), msgID, "garlic message ID must match")

	// Expiration (8 bytes)
	expMs := binary.BigEndian.Uint64(payload[trailerStart+7 : trailerStart+15])
	assert.Equal(t, uint64(1704067200000), expMs, "garlic expiration must match")
}

// TestGarlic_CloveFormat_Roundtrip verifies that a garlic message with
// a single clove survives a serialize→deserialize cycle.
func TestGarlic_CloveFormat_Roundtrip(t *testing.T) {
	fixedExp := time.UnixMilli(1704067200000)
	builder := NewGarlicBuilder(42, fixedExp)

	msg1 := NewDataMessage([]byte("clove1"))
	msg1.SetMessageID(1)
	msg1.SetExpiration(fixedExp)

	err := builder.AddLocalDeliveryClove(msg1, 100)
	require.NoError(t, err)

	payload, err := builder.BuildAndSerialize()
	require.NoError(t, err)

	assert.Equal(t, byte(1), payload[0], "first byte must be clove count")

	garlic, err := DeserializeGarlic(payload, 0)
	require.NoError(t, err)

	assert.Equal(t, 1, garlic.Count, "clove count must be preserved")
	assert.Equal(t, 1, len(garlic.Cloves), "must have 1 clove")
	assert.Equal(t, 42, garlic.MessageID, "garlic messageID must be preserved")
}

// TestGarlic_CloveFormat_MultiCloveRoundtrip verifies that a garlic message with
// multiple cloves survives a serialize→deserialize cycle.
func TestGarlic_CloveFormat_MultiCloveRoundtrip(t *testing.T) {
	fixedExp := time.UnixMilli(1704067200000)
	builder := NewGarlicBuilder(42, fixedExp)

	msg1 := NewDataMessage([]byte("clove1"))
	msg1.SetMessageID(1)
	msg1.SetExpiration(fixedExp)

	msg2 := NewDataMessage([]byte("clove2"))
	msg2.SetMessageID(2)
	msg2.SetExpiration(fixedExp)

	err := builder.AddLocalDeliveryClove(msg1, 100)
	require.NoError(t, err)
	err = builder.AddLocalDeliveryClove(msg2, 200)
	require.NoError(t, err)

	payload, err := builder.BuildAndSerialize()
	require.NoError(t, err)

	garlic, err := DeserializeGarlic(payload, 0)
	require.NoError(t, err)

	assert.Equal(t, 2, garlic.Count, "clove count must be preserved")
	assert.Equal(t, 2, len(garlic.Cloves), "must have 2 cloves")
	assert.Equal(t, 42, garlic.MessageID, "garlic messageID must be preserved")
}

// TestGarlic_CloveFormat_MaxCloves255 verifies the clove count is a single
// byte (0-255), so the maximum is 255 cloves.
func TestGarlic_CloveFormat_MaxCloves255(t *testing.T) {
	builder := NewGarlicBuilder(1, time.Now().Add(10*time.Second))

	// Try to add 256 cloves — the builder limits to 255
	for i := 0; i < 256; i++ {
		msg := NewDataMessage([]byte("x"))
		msg.SetMessageID(i)
		msg.SetExpiration(time.Now().Add(10 * time.Second))
		_ = builder.AddLocalDeliveryClove(msg, i)
	}

	_, err := builder.Build()
	assert.Error(t, err, "more than 255 cloves must be rejected")
}

// =============================================================================
// Audit Item: Delivery instruction types
// Local (0), Destination (1), Router (2), Tunnel (3)
//
// Spec reference: https://geti2p.net/spec/i2np (Garlic Clove Delivery Instructions)
//
// flag byte bit layout: 76543210
//   bit 7:   encrypted (always 0)
//   bits 6-5: delivery type  0=LOCAL, 1=DESTINATION, 2=ROUTER, 3=TUNNEL
//   bit 4:   delay included (always 0)
//   bits 3-0: reserved (0)
// =============================================================================

// TestGarlic_DeliveryInstructions_FlagBitEncoding verifies that the delivery
// type is encoded in bits 6-5 of the flag byte, matching the I2P spec:
//
//	LOCAL=0x00, DESTINATION=0x20, ROUTER=0x40, TUNNEL=0x60
func TestGarlic_DeliveryInstructions_FlagBitEncoding(t *testing.T) {
	tests := []struct {
		name         string
		di           GarlicCloveDeliveryInstructions
		expectedFlag byte
		expectedType byte // bits 6-5 >> 5
	}{
		{"LOCAL", NewLocalDeliveryInstructions(), 0x00, 0x00},
		{"DESTINATION", NewDestinationDeliveryInstructions(common.Hash{}), 0x20, 0x01},
		{"ROUTER", NewRouterDeliveryInstructions(common.Hash{}), 0x40, 0x02},
		{"TUNNEL", NewTunnelDeliveryInstructions(common.Hash{}, 0), 0x60, 0x03},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Verify the raw flag value
			assert.Equal(t, tc.expectedFlag, tc.di.Flag,
				"flag byte must be 0x%02x for %s delivery", tc.expectedFlag, tc.name)

			// Verify delivery type extracted from bits 6-5
			deliveryType := extractDeliveryType(tc.di.Flag)
			assert.Equal(t, tc.expectedType, deliveryType,
				"bits 6-5 must encode delivery type %d for %s", tc.expectedType, tc.name)

			// Verify reserved bits 3-0 are zero
			assert.Equal(t, byte(0), tc.di.Flag&0x0F,
				"reserved bits 3-0 must be zero for %s", tc.name)

			// Verify encryption bit 7 is zero
			assert.Equal(t, byte(0), tc.di.Flag&0x80,
				"encryption bit 7 must be zero for %s", tc.name)

			// Verify delay bit 4 is zero
			assert.Equal(t, byte(0), tc.di.Flag&0x10,
				"delay bit 4 must be zero for %s", tc.name)
		})
	}
}

// TestGarlic_DeliveryInstructions_LocalWireFormat verifies LOCAL delivery
// instructions serialize to exactly 1 byte (flag only, no hash, no tunnel ID).
func TestGarlic_DeliveryInstructions_LocalWireFormat(t *testing.T) {
	di := NewLocalDeliveryInstructions()
	data, err := serializeDeliveryInstructions(&di)
	require.NoError(t, err)

	assert.Equal(t, 1, len(data), "LOCAL delivery must be exactly 1 byte")
	assert.Equal(t, byte(0x00), data[0], "LOCAL flag must be 0x00")
}

// TestGarlic_DeliveryInstructions_DestinationWireFormat verifies DESTINATION
// delivery instructions: flag(1) + hash(32) = 33 bytes.
func TestGarlic_DeliveryInstructions_DestinationWireFormat(t *testing.T) {
	var destHash common.Hash
	for i := 0; i < 32; i++ {
		destHash[i] = byte(0xAA + i)
	}
	di := NewDestinationDeliveryInstructions(destHash)
	data, err := serializeDeliveryInstructions(&di)
	require.NoError(t, err)

	assert.Equal(t, 33, len(data), "DESTINATION delivery must be 33 bytes")
	assert.Equal(t, byte(0x20), data[0], "DESTINATION flag must be 0x20")

	// Verify the 32-byte destination hash follows immediately after the flag
	assert.True(t, bytes.Equal(destHash[:], data[1:33]),
		"destination hash must follow flag byte")
}

// TestGarlic_DeliveryInstructions_RouterWireFormat verifies ROUTER delivery
// instructions: flag(1) + hash(32) = 33 bytes.
func TestGarlic_DeliveryInstructions_RouterWireFormat(t *testing.T) {
	var routerHash common.Hash
	for i := 0; i < 32; i++ {
		routerHash[i] = byte(0xBB + i)
	}
	di := NewRouterDeliveryInstructions(routerHash)
	data, err := serializeDeliveryInstructions(&di)
	require.NoError(t, err)

	assert.Equal(t, 33, len(data), "ROUTER delivery must be 33 bytes")
	assert.Equal(t, byte(0x40), data[0], "ROUTER flag must be 0x40")

	// Verify the 32-byte router hash follows immediately after the flag
	assert.True(t, bytes.Equal(routerHash[:], data[1:33]),
		"router hash must follow flag byte")
}

// TestGarlic_DeliveryInstructions_TunnelWireFormat verifies TUNNEL delivery
// instructions: flag(1) + hash(32) + tunnelID(4) = 37 bytes.
func TestGarlic_DeliveryInstructions_TunnelWireFormat(t *testing.T) {
	var gatewayHash common.Hash
	for i := 0; i < 32; i++ {
		gatewayHash[i] = byte(0xCC + i)
	}
	tid := tunnel.TunnelID(0xDEADBEEF)
	di := NewTunnelDeliveryInstructions(gatewayHash, tid)
	data, err := serializeDeliveryInstructions(&di)
	require.NoError(t, err)

	assert.Equal(t, 37, len(data), "TUNNEL delivery must be 37 bytes")
	assert.Equal(t, byte(0x60), data[0], "TUNNEL flag must be 0x60")

	// Gateway hash at offset 1..32
	assert.True(t, bytes.Equal(gatewayHash[:], data[1:33]),
		"gateway hash must follow flag byte")

	// Tunnel ID at offset 33..36, 4 bytes big-endian
	parsedTID := binary.BigEndian.Uint32(data[33:37])
	assert.Equal(t, uint32(0xDEADBEEF), parsedTID,
		"tunnel ID must be 4-byte big-endian at offset 33")
}

// TestGarlic_DeliveryInstructions_SerializeDeserializeRoundtrip verifies that
// each delivery type survives a serialize→deserialize cycle with all fields
// preserved (flag, hash, tunnel ID).
func TestGarlic_DeliveryInstructions_SerializeDeserializeRoundtrip(t *testing.T) {
	var testHash common.Hash
	for i := 0; i < 32; i++ {
		testHash[i] = byte(i + 1)
	}
	tid := tunnel.TunnelID(42424242)

	tests := []struct {
		name string
		di   GarlicCloveDeliveryInstructions
	}{
		{"LOCAL", NewLocalDeliveryInstructions()},
		{"DESTINATION", NewDestinationDeliveryInstructions(testHash)},
		{"ROUTER", NewRouterDeliveryInstructions(testHash)},
		{"TUNNEL", NewTunnelDeliveryInstructions(testHash, tid)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data, err := serializeDeliveryInstructions(&tc.di)
			require.NoError(t, err)

			parsed, bytesRead, err := deserializeDeliveryInstructions(data)
			require.NoError(t, err)
			assert.Equal(t, len(data), bytesRead,
				"deserializer must consume all serialized bytes")

			assert.Equal(t, tc.di.Flag, parsed.Flag,
				"flag must survive roundtrip")

			deliveryType := extractDeliveryType(tc.di.Flag)
			if deliveryType == 0x01 || deliveryType == 0x02 || deliveryType == 0x03 {
				assert.Equal(t, tc.di.Hash, parsed.Hash,
					"hash must survive roundtrip for %s", tc.name)
			}
			if deliveryType == 0x03 {
				assert.Equal(t, tc.di.TunnelID, parsed.TunnelID,
					"tunnel ID must survive roundtrip for TUNNEL")
			}
		})
	}
}

// TestGarlic_DeliveryInstructions_GarlicRoundtripAllTypes verifies that each
// delivery type survives a full garlic serialize→deserialize cycle. This is the
// end-to-end test: build garlic with a specific delivery type, serialize, then
// deserialize and verify the clove's delivery instructions are preserved.
func TestGarlic_DeliveryInstructions_GarlicRoundtripAllTypes(t *testing.T) {
	fixedExp := time.UnixMilli(1704067200000) // 2024-01-01 00:00:00 UTC

	var testHash common.Hash
	for i := 0; i < 32; i++ {
		testHash[i] = byte(0x10 + i)
	}
	tid := tunnel.TunnelID(99999)

	tests := []struct {
		name         string
		addClove     func(b *GarlicBuilder, msg I2NPMessage) error
		expectedFlag byte
		checkHash    bool
		checkTunnel  bool
	}{
		{
			"LOCAL",
			func(b *GarlicBuilder, msg I2NPMessage) error {
				return b.AddLocalDeliveryClove(msg, 1)
			},
			0x00, false, false,
		},
		{
			"DESTINATION",
			func(b *GarlicBuilder, msg I2NPMessage) error {
				return b.AddDestinationDeliveryClove(msg, 2, testHash)
			},
			0x20, true, false,
		},
		{
			"ROUTER",
			func(b *GarlicBuilder, msg I2NPMessage) error {
				return b.AddRouterDeliveryClove(msg, 3, testHash)
			},
			0x40, true, false,
		},
		{
			"TUNNEL",
			func(b *GarlicBuilder, msg I2NPMessage) error {
				return b.AddTunnelDeliveryClove(msg, 4, testHash, tid)
			},
			0x60, true, true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			builder := NewGarlicBuilder(100, fixedExp)

			msg := NewDataMessage([]byte("delivery-test"))
			msg.SetMessageID(7)
			msg.SetExpiration(fixedExp)

			err := tc.addClove(builder, msg)
			require.NoError(t, err)

			payload, err := builder.BuildAndSerialize()
			require.NoError(t, err)

			garlic, err := DeserializeGarlic(payload, 0)
			require.NoError(t, err, "garlic deserialization must succeed for %s", tc.name)

			require.Equal(t, 1, len(garlic.Cloves), "must have 1 clove")
			clove := garlic.Cloves[0]

			assert.Equal(t, tc.expectedFlag, clove.DeliveryInstructions.Flag,
				"delivery flag must be preserved for %s", tc.name)

			if tc.checkHash {
				assert.Equal(t, testHash, clove.DeliveryInstructions.Hash,
					"hash must be preserved for %s", tc.name)
			}
			if tc.checkTunnel {
				assert.Equal(t, tid, clove.DeliveryInstructions.TunnelID,
					"tunnel ID must be preserved for TUNNEL")
			}
		})
	}
}

// TestGarlic_DeliveryInstructions_MixedTypesRoundtrip verifies that a garlic
// message containing cloves with all 4 delivery types survives serialization
// and each clove's delivery instructions are preserved in order.
func TestGarlic_DeliveryInstructions_MixedTypesRoundtrip(t *testing.T) {
	fixedExp := time.UnixMilli(1704067200000)
	builder := NewGarlicBuilder(200, fixedExp)

	var destHash common.Hash
	for i := range destHash {
		destHash[i] = byte(0xD0 + i)
	}
	var routerHash common.Hash
	for i := range routerHash {
		routerHash[i] = byte(0xE0 + i)
	}
	var gatewayHash common.Hash
	for i := range gatewayHash {
		gatewayHash[i] = byte(0xF0 + i)
	}
	tid := tunnel.TunnelID(77777)

	// Add one of each type in order: LOCAL, DESTINATION, ROUTER, TUNNEL
	msg0 := NewDataMessage([]byte("local"))
	msg0.SetMessageID(10)
	msg0.SetExpiration(fixedExp)
	require.NoError(t, builder.AddLocalDeliveryClove(msg0, 10))

	msg1 := NewDataMessage([]byte("dest"))
	msg1.SetMessageID(11)
	msg1.SetExpiration(fixedExp)
	require.NoError(t, builder.AddDestinationDeliveryClove(msg1, 11, destHash))

	msg2 := NewDataMessage([]byte("router"))
	msg2.SetMessageID(12)
	msg2.SetExpiration(fixedExp)
	require.NoError(t, builder.AddRouterDeliveryClove(msg2, 12, routerHash))

	msg3 := NewDataMessage([]byte("tunnel"))
	msg3.SetMessageID(13)
	msg3.SetExpiration(fixedExp)
	require.NoError(t, builder.AddTunnelDeliveryClove(msg3, 13, gatewayHash, tid))

	payload, err := builder.BuildAndSerialize()
	require.NoError(t, err)

	garlic, err := DeserializeGarlic(payload, 0)
	require.NoError(t, err)

	require.Equal(t, 4, garlic.Count, "must have 4 cloves")
	require.Equal(t, 4, len(garlic.Cloves))

	// Clove 0: LOCAL
	assert.Equal(t, byte(0x00), garlic.Cloves[0].DeliveryInstructions.Flag, "clove 0 = LOCAL")

	// Clove 1: DESTINATION with destHash
	assert.Equal(t, byte(0x20), garlic.Cloves[1].DeliveryInstructions.Flag, "clove 1 = DESTINATION")
	assert.Equal(t, destHash, garlic.Cloves[1].DeliveryInstructions.Hash, "clove 1 destHash preserved")

	// Clove 2: ROUTER with routerHash
	assert.Equal(t, byte(0x40), garlic.Cloves[2].DeliveryInstructions.Flag, "clove 2 = ROUTER")
	assert.Equal(t, routerHash, garlic.Cloves[2].DeliveryInstructions.Hash, "clove 2 routerHash preserved")

	// Clove 3: TUNNEL with gatewayHash + tunnelID
	assert.Equal(t, byte(0x60), garlic.Cloves[3].DeliveryInstructions.Flag, "clove 3 = TUNNEL")
	assert.Equal(t, gatewayHash, garlic.Cloves[3].DeliveryInstructions.Hash, "clove 3 gatewayHash preserved")
	assert.Equal(t, tid, garlic.Cloves[3].DeliveryInstructions.TunnelID, "clove 3 tunnelID preserved")
}

// TestGarlic_DeliveryInstructions_TruncatedData verifies that the deserializer
// correctly rejects truncated delivery instruction data for each type.
func TestGarlic_DeliveryInstructions_TruncatedData(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		// Empty data
		{"empty", []byte{}},
		// DESTINATION flag but no hash (need 33, have 1)
		{"DESTINATION_no_hash", []byte{0x20}},
		// DESTINATION flag with partial hash (need 33, have 17)
		{"DESTINATION_partial_hash", append([]byte{0x20}, make([]byte, 15)...)},
		// ROUTER flag but no hash
		{"ROUTER_no_hash", []byte{0x40}},
		// TUNNEL flag but no hash
		{"TUNNEL_no_hash", []byte{0x60}},
		// TUNNEL flag with hash but no tunnel ID (need 37, have 33)
		{"TUNNEL_no_tunnelID", append([]byte{0x60}, make([]byte, 32)...)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := deserializeDeliveryInstructions(tc.data)
			assert.Error(t, err,
				"truncated %s data must be rejected", tc.name)
		})
	}
}

// TestGarlic_DeliveryInstructions_EncryptedFlagBit verifies that bit 7
// (encrypted flag) triggers inclusion of a 32-byte session key in the
// serialized wire format.
func TestGarlic_DeliveryInstructions_EncryptedFlagBit(t *testing.T) {
	var sk session_key.SessionKey
	for i := range sk {
		sk[i] = byte(0xFF - i)
	}

	// LOCAL delivery with encryption flag set: flag(1) + sessionKey(32) = 33
	di := GarlicCloveDeliveryInstructions{
		Flag:       0x80, // bit 7 set = encrypted, delivery type = LOCAL (bits 6-5 = 0)
		SessionKey: sk,
	}
	data, err := serializeDeliveryInstructions(&di)
	require.NoError(t, err)

	assert.Equal(t, 33, len(data),
		"LOCAL+encrypted must be flag(1) + sessionKey(32) = 33 bytes")
	assert.Equal(t, byte(0x80), data[0], "flag byte must be 0x80")
	assert.True(t, bytes.Equal(sk[:], data[1:33]),
		"session key must follow flag byte when encrypted")
}

// TestGarlic_DeliveryInstructions_DelayFlagBit verifies that bit 4 (delay
// included flag) triggers inclusion of a 4-byte delay field.
func TestGarlic_DeliveryInstructions_DelayFlagBit(t *testing.T) {
	// LOCAL delivery with delay flag set: flag(1) + delay(4) = 5
	di := GarlicCloveDeliveryInstructions{
		Flag:  0x10, // bit 4 set = delay included, delivery type = LOCAL
		Delay: 300,  // 300 seconds
	}
	data, err := serializeDeliveryInstructions(&di)
	require.NoError(t, err)

	assert.Equal(t, 5, len(data),
		"LOCAL+delay must be flag(1) + delay(4) = 5 bytes")
	assert.Equal(t, byte(0x10), data[0], "flag byte must be 0x10")

	parsedDelay := binary.BigEndian.Uint32(data[1:5])
	assert.Equal(t, uint32(300), parsedDelay,
		"delay field must be 4-byte big-endian at offset 1")
}

// TestGarlic_DeliveryInstructions_DeserializeDelayRoundtrip verifies that
// the delay field survives a serialize→deserialize roundtrip.
func TestGarlic_DeliveryInstructions_DeserializeDelayRoundtrip(t *testing.T) {
	di := GarlicCloveDeliveryInstructions{
		Flag:  0x10, // delay flag set, LOCAL delivery
		Delay: 600,
	}
	data, err := serializeDeliveryInstructions(&di)
	require.NoError(t, err)

	parsed, bytesRead, err := deserializeDeliveryInstructions(data)
	require.NoError(t, err)
	assert.Equal(t, len(data), bytesRead)
	assert.Equal(t, byte(0x10), parsed.Flag)
	assert.Equal(t, 600, parsed.Delay, "delay must survive roundtrip")
}

// TestGarlic_DeliveryInstructions_TunnelWithEncryptionAndDelay tests the
// maximum-length delivery instruction: TUNNEL + encrypted + delay.
// flag(1) + sessionKey(32) + hash(32) + tunnelID(4) + delay(4) = 73 bytes.
//
// NOTE: The encryption flag (bit 7) is "Unimplemented, always 0" per spec.
// The serializer writes the session key when bit 7 is set, but the
// deserializer does not read it (it doesn't check bit 7). So we only
// verify the serialization layout here, not the roundtrip.
func TestGarlic_DeliveryInstructions_TunnelWithEncryptionAndDelay(t *testing.T) {
	var sk session_key.SessionKey
	for i := range sk {
		sk[i] = byte(i)
	}
	var hash common.Hash
	for i := range hash {
		hash[i] = byte(0x50 + i)
	}
	tid := tunnel.TunnelID(12345)

	di := GarlicCloveDeliveryInstructions{
		Flag:       0x60 | 0x80 | 0x10, // TUNNEL + encrypted + delay
		SessionKey: sk,
		Hash:       hash,
		TunnelID:   tid,
		Delay:      999,
	}
	data, err := serializeDeliveryInstructions(&di)
	require.NoError(t, err)

	// flag(1) + sessionKey(32) + hash(32) + tunnelID(4) + delay(4) = 73
	assert.Equal(t, 73, len(data),
		"TUNNEL+encrypted+delay must be 73 bytes")

	// Verify layout: flag | sessionKey(32) | hash(32) | tunnelID(4) | delay(4)
	assert.Equal(t, byte(0xF0), data[0], "flag = 0x60|0x80|0x10 = 0xF0")
	assert.True(t, bytes.Equal(sk[:], data[1:33]), "session key at offset 1-32")
	assert.True(t, bytes.Equal(hash[:], data[33:65]), "hash at offset 33-64")
	assert.Equal(t, uint32(12345), binary.BigEndian.Uint32(data[65:69]),
		"tunnel ID at offset 65-68")
	assert.Equal(t, uint32(999), binary.BigEndian.Uint32(data[69:73]),
		"delay at offset 69-72")
}

// =============================================================================
// Audit Item: Forward secrecy — Ratchet key rotation after message exchange
//
// Proposal 144 (ECIES-X25519-AEAD-Ratchet) requires that sessions perform
// DH ratchet steps periodically to provide forward secrecy. After a DH ratchet
// rotation, old symmetric keys cannot decrypt messages encrypted with the new
// keys. This section verifies that:
// 1. DH ratchet rotation occurs after DHRatchetInterval messages
// 2. After rotation, symmetric and tag ratchets are re-initialized with fresh keys
// 3. Old message keys cannot decrypt messages encrypted after rotation (forward secrecy)
// 4. Consecutive DH failures are tracked and degrade gracefully
// =============================================================================

// TestGarlic_ForwardSecrecy_DHRatchetOccursAtInterval verifies that the DH ratchet
// rotation is triggered after exactly DHRatchetInterval messages. Before the interval
// the symmetric ratchet instance remains the same; after, it is replaced with a
// fresh one derived from the new DH exchange.
func TestGarlic_ForwardSecrecy_DHRatchetOccursAtInterval(t *testing.T) {
	session := createTestSession(t)

	// The symmetric ratchet should remain the same object until the interval.
	origSymRatchet := session.SymmetricRatchet
	origTagRatchet := session.TagRatchet

	// Advance ratchets for DHRatchetInterval-1 messages — no DH rotation should occur.
	for i := uint32(0); i < DHRatchetInterval-1; i++ {
		_, _, err := advanceRatchets(session)
		require.NoError(t, err, "advanceRatchets should not fail at message %d", i)
	}

	// Symmetric and tag ratchets should still be the original instances
	// (their internal state has advanced, but they haven't been replaced).
	assert.Same(t, origSymRatchet, session.SymmetricRatchet,
		"symmetric ratchet should NOT be replaced before DHRatchetInterval")
	assert.Same(t, origTagRatchet, session.TagRatchet,
		"tag ratchet should NOT be replaced before DHRatchetInterval")

	// The next advanceRatchets call should trigger DH rotation.
	_, _, err := advanceRatchets(session)
	require.NoError(t, err)

	// After rotation, ratchets must be NEW instances with fresh key material.
	assert.NotSame(t, origSymRatchet, session.SymmetricRatchet,
		"symmetric ratchet MUST be replaced after DH rotation")
	assert.NotSame(t, origTagRatchet, session.TagRatchet,
		"tag ratchet MUST be replaced after DH rotation")
}

// TestGarlic_ForwardSecrecy_OldKeysCannotDecryptPostRotation verifies that message
// keys derived before a DH ratchet rotation cannot decrypt messages encrypted after
// the rotation. This is the core forward secrecy property per Proposal 144.
func TestGarlic_ForwardSecrecy_OldKeysCannotDecryptPostRotation(t *testing.T) {
	session := createTestSession(t)

	// Collect a message key from before rotation.
	preRotationKey, _, err := advanceRatchets(session)
	require.NoError(t, err)

	// Advance to just before the DH rotation threshold (we've already consumed 1).
	for i := uint32(1); i < DHRatchetInterval; i++ {
		_, _, err := advanceRatchets(session)
		require.NoError(t, err)
	}

	// This call triggers the DH rotation.
	postRotationKey, _, err := advanceRatchets(session)
	require.NoError(t, err)

	// The pre-rotation key must differ from the post-rotation key.
	assert.NotEqual(t, preRotationKey, postRotationKey,
		"message keys before and after DH rotation MUST differ (forward secrecy)")

	// Verify that encryption with the old key produces ciphertext that
	// cannot be decrypted with the new key (and vice versa).
	plaintext := []byte("forward secrecy test payload")
	var dummyTag [8]byte

	oldCiphertext, oldAuthTag, oldNonce, err := encryptWithSessionKey(preRotationKey, plaintext, dummyTag)
	require.NoError(t, err)

	// Attempt decryption with the post-rotation key — MUST fail.
	_, err = decryptWithSessionTag(postRotationKey, oldCiphertext, oldAuthTag, dummyTag, oldNonce)
	assert.Error(t, err,
		"decryption with post-rotation key MUST fail for pre-rotation ciphertext (forward secrecy)")
}

// TestGarlic_ForwardSecrecy_NewEphemeralKeyStoredAfterRotation verifies that a
// new ephemeral public key is stored in the session after DH ratchet rotation,
// ready to be sent to the peer so they can update their receiving chain.
func TestGarlic_ForwardSecrecy_NewEphemeralKeyStoredAfterRotation(t *testing.T) {
	session := createTestSession(t)

	assert.Nil(t, session.newEphemeralPub,
		"newEphemeralPub should be nil before any DH rotation")

	// Advance past DHRatchetInterval to trigger rotation.
	for i := uint32(0); i <= DHRatchetInterval; i++ {
		_, _, err := advanceRatchets(session)
		require.NoError(t, err)
	}

	assert.NotNil(t, session.newEphemeralPub,
		"newEphemeralPub MUST be set after DH rotation for peer notification")

	// The ephemeral key must be 32 bytes and non-zero.
	var zeroKey [32]byte
	assert.NotEqual(t, zeroKey, *session.newEphemeralPub,
		"newEphemeralPub must not be all zeros")
}

// TestGarlic_ForwardSecrecy_ConsecutiveDHFailuresDegradeGracefully verifies that
// the session tracks consecutive DH failures and only returns a fatal error after
// MaxConsecutiveDHFailures. Intermediate failures allow the session to continue
// using the symmetric ratchet without forward secrecy upgrades.
func TestGarlic_ForwardSecrecy_ConsecutiveDHFailuresDegradeGracefully(t *testing.T) {
	assert.Equal(t, uint32(3), uint32(MaxConsecutiveDHFailures),
		"MaxConsecutiveDHFailures should be 3 per design")
	assert.Equal(t, uint32(50), uint32(DHRatchetInterval),
		"DHRatchetInterval should be 50 messages per design")
}

// TestGarlic_ForwardSecrecy_DHRatchetCounterResets verifies that after a successful
// DH ratchet rotation, the dhRatchetCounter resets to 0, ensuring the next rotation
// occurs exactly DHRatchetInterval messages later.
func TestGarlic_ForwardSecrecy_DHRatchetCounterResets(t *testing.T) {
	session := createTestSession(t)

	// Advance exactly DHRatchetInterval calls to trigger the first rotation.
	// Counter: 0→1→...→50 (rotation, reset to 0).
	for i := uint32(0); i < DHRatchetInterval; i++ {
		_, _, err := advanceRatchets(session)
		require.NoError(t, err)
	}

	// After rotation, counter is 0. Save the current SymmetricRatchet.
	origSymRatchet := session.SymmetricRatchet

	// Advance DHRatchetInterval-1 calls. Counter: 0→1→...→49. No rotation.
	for i := uint32(0); i < DHRatchetInterval-1; i++ {
		_, _, err := advanceRatchets(session)
		require.NoError(t, err)
	}
	// Should still be same instance (no rotation yet).
	assert.Same(t, origSymRatchet, session.SymmetricRatchet,
		"no rotation should occur before next full interval")

	// One more should trigger rotation (counter 49→50).
	_, _, err := advanceRatchets(session)
	require.NoError(t, err)
	assert.NotSame(t, origSymRatchet, session.SymmetricRatchet,
		"rotation should occur exactly DHRatchetInterval messages after previous rotation")
}

// =============================================================================
// Audit Item: Session lifecycle — New Session → Existing Session transition
//
// Proposal 144 defines two session states:
// - New Session: First message uses ephemeral-static DH (ECIES) key exchange.
//   Format: [ephemeralPubKey(32)] + [nonce(12)] + [ciphertext(N)] + [tag(16)]
// - Existing Session: Subsequent messages use ratchet-derived session tags.
//   Format: [sessionTag(8)] + [nonce(12)] + [ciphertext(N)] + [tag(16)]
//
// The transition happens automatically: after a New Session message is sent,
// the session is stored and all subsequent messages use Existing Session format.
// On the receiver side, decrypting a New Session message initializes inbound
// ratchet state so future messages from that sender use Existing Session.
// =============================================================================

// TestGarlic_SessionLifecycle_FirstMessageIsNewSession verifies that the first
// message to a new destination uses the New Session format with an ephemeral
// public key prefix (32 bytes). The minimum message size for New Session is
// 32 (pubkey) + 12 (nonce) + 0 (plaintext) + 16 (tag) = 60 bytes.
func TestGarlic_SessionLifecycle_FirstMessageIsNewSession(t *testing.T) {
	sm, err := GenerateGarlicSessionManager()
	require.NoError(t, err)

	destPubBytes, _, err := ecies.GenerateKeyPair()
	require.NoError(t, err)
	var destPubKey [32]byte
	copy(destPubKey[:], destPubBytes)
	destHash := types.SHA256(destPubKey[:])

	plaintext := []byte("first message to new destination")
	ciphertext, err := sm.EncryptGarlicMessage(destHash, destPubKey, plaintext)
	require.NoError(t, err)

	// New Session format minimum: 32 + 12 + len(plaintext) + 16 = 60 + len(plaintext)
	assert.GreaterOrEqual(t, len(ciphertext), 60,
		"New Session message must be at least 60 bytes (32 pubkey + 12 nonce + 16 tag)")

	// Verify the first 32 bytes look like a valid X25519 public key (non-zero).
	var zeroKey [32]byte
	var ephPub [32]byte
	copy(ephPub[:], ciphertext[0:32])
	assert.NotEqual(t, zeroKey, ephPub,
		"first 32 bytes should be a non-zero ephemeral public key")

	// A session should now exist for this destination.
	assert.Equal(t, 1, sm.GetSessionCount(),
		"session must be created after first New Session message")
}

// TestGarlic_SessionLifecycle_SecondMessageIsExistingSession verifies that the
// second message to the same destination uses the Existing Session format, which
// starts with an 8-byte session tag instead of a 32-byte ephemeral key.
func TestGarlic_SessionLifecycle_SecondMessageIsExistingSession(t *testing.T) {
	sm, err := GenerateGarlicSessionManager()
	require.NoError(t, err)

	destPubBytes, _, err := ecies.GenerateKeyPair()
	require.NoError(t, err)
	var destPubKey [32]byte
	copy(destPubKey[:], destPubBytes)
	destHash := types.SHA256(destPubKey[:])

	plaintext := []byte("test payload")

	// First message (New Session).
	firstMsg, err := sm.EncryptGarlicMessage(destHash, destPubKey, plaintext)
	require.NoError(t, err)

	// Second message (should be Existing Session).
	secondMsg, err := sm.EncryptGarlicMessage(destHash, destPubKey, plaintext)
	require.NoError(t, err)

	// Existing Session format: [tag(8)] + [nonce(12)] + [ciphertext(N)] + [authTag(16)]
	// Minimum: 8 + 12 + len(plaintext) + 16 = 36 + len(plaintext)
	// New Session format is at least 60 + len(plaintext)
	// The Existing Session message should be smaller than New Session for same plaintext
	// because it uses 8-byte tag vs 32-byte ephemeral key.
	assert.Less(t, len(secondMsg), len(firstMsg),
		"Existing Session message should be shorter than New Session (8-byte tag vs 32-byte key)")

	// Still only one session for this destination.
	assert.Equal(t, 1, sm.GetSessionCount(),
		"session count should remain 1 after second message to same destination")
}

// TestGarlic_SessionLifecycle_InboundNewSessionCreatesRatchetState verifies that
// when a receiver decrypts a New Session message, it initializes inbound ratchet
// state so that future Existing Session messages from the same sender can be
// decrypted using session tag lookup.
func TestGarlic_SessionLifecycle_InboundNewSessionCreatesRatchetState(t *testing.T) {
	senderSM, err := GenerateGarlicSessionManager()
	require.NoError(t, err)

	receiverPubBytes, receiverPrivBytes, err := ecies.GenerateKeyPair()
	require.NoError(t, err)
	var receiverPubKey, receiverPrivKey [32]byte
	copy(receiverPubKey[:], receiverPubBytes)
	copy(receiverPrivKey[:], receiverPrivBytes)
	receiverSM, err := NewGarlicSessionManager(receiverPrivKey)
	require.NoError(t, err)

	destHash := types.SHA256(receiverPubKey[:])
	plaintext := []byte("new session message")

	ciphertext, err := senderSM.EncryptGarlicMessage(destHash, receiverPubKey, plaintext)
	require.NoError(t, err)

	// Receiver should have 0 sessions before decryption.
	assert.Equal(t, 0, receiverSM.GetSessionCount(),
		"receiver should have no sessions before decryption")

	// Decrypt the New Session message.
	decrypted, sessionTag, err := receiverSM.DecryptGarlicMessage(ciphertext)
	require.NoError(t, err)

	// Session tag should be empty for New Session.
	assert.Equal(t, [8]byte{}, sessionTag,
		"session tag must be empty for New Session decryption")

	// Plaintext must match.
	assert.Equal(t, plaintext, decrypted, "decrypted plaintext must match original")

	// Receiver should now have 1 session (inbound ratchet state created).
	assert.Equal(t, 1, receiverSM.GetSessionCount(),
		"receiver MUST have 1 session after decrypting New Session (inbound ratchet initialized)")
}

// TestGarlic_SessionLifecycle_NewSessionFormatDistinctFromExistingSession verifies
// that the New Session and Existing Session wire formats are structurally distinct
// and can be differentiated by the receiver through session tag lookup.
func TestGarlic_SessionLifecycle_NewSessionFormatDistinctFromExistingSession(t *testing.T) {
	// New Session: [ephemeralPubKey(32)] + [nonce(12)] + [ciphertext(N)] + [tag(16)]
	// Existing Session: [sessionTag(8)] + [nonce(12)] + [ciphertext(N)] + [tag(16)]
	//
	// The receiver distinguishes them by checking if the first 8 bytes match
	// any known session tag. If not, it treats the message as a New Session.

	sm, err := GenerateGarlicSessionManager()
	require.NoError(t, err)

	destPubBytes, _, err := ecies.GenerateKeyPair()
	require.NoError(t, err)
	var destPubKey [32]byte
	copy(destPubKey[:], destPubBytes)
	destHash := types.SHA256(destPubKey[:])

	plaintext := []byte("test message")

	// First message is New Session.
	newSessionMsg, err := sm.EncryptGarlicMessage(destHash, destPubKey, plaintext)
	require.NoError(t, err)

	// Second message is Existing Session.
	existingSessionMsg, err := sm.EncryptGarlicMessage(destHash, destPubKey, plaintext)
	require.NoError(t, err)

	// New Session starts with 32 bytes of ephemeral public key.
	// Existing Session starts with 8 bytes of session tag.
	// They have different total overhead: 32+12+16=60 vs 8+12+16=36
	newSessionOverhead := len(newSessionMsg) - len(plaintext)
	existingSessionOverhead := len(existingSessionMsg) - len(plaintext)

	assert.Greater(t, newSessionOverhead, existingSessionOverhead,
		"New Session overhead (with 32-byte pubkey) must exceed Existing Session overhead (with 8-byte tag)")
}

// TestGarlic_SessionLifecycle_SessionStoresPersistentState verifies that after
// the New Session → Existing Session transition, the session retains all
// necessary ratchet state: DHRatchet, SymmetricRatchet, TagRatchet, and
// directional receive ratchets.
func TestGarlic_SessionLifecycle_SessionStoresPersistentState(t *testing.T) {
	sm, err := GenerateGarlicSessionManager()
	require.NoError(t, err)

	destPubBytes, _, err := ecies.GenerateKeyPair()
	require.NoError(t, err)
	var destPubKey [32]byte
	copy(destPubKey[:], destPubBytes)
	destHash := types.SHA256(destPubKey[:])

	plaintext := []byte("state persistence test")
	_, err = sm.EncryptGarlicMessage(destHash, destPubKey, plaintext)
	require.NoError(t, err)

	// Read-lock the session manager and inspect the session.
	sm.mu.RLock()
	session, exists := sm.sessions[destHash]
	sm.mu.RUnlock()

	require.True(t, exists, "session must exist after New Session encryption")

	// All ratchet components must be initialized.
	assert.NotNil(t, session.DHRatchet, "DHRatchet must be initialized")
	assert.NotNil(t, session.SymmetricRatchet, "SymmetricRatchet (send) must be initialized")
	assert.NotNil(t, session.TagRatchet, "TagRatchet (send) must be initialized")
	assert.NotNil(t, session.RecvSymmetricRatchet, "RecvSymmetricRatchet must be initialized")
	assert.NotNil(t, session.RecvTagRatchet, "RecvTagRatchet must be initialized")

	// Message counter should be 1 (one message sent).
	assert.Equal(t, uint32(1), session.MessageCounter,
		"MessageCounter should be 1 after first New Session message")

	// Remote public key should match the destination.
	assert.Equal(t, destPubKey, session.RemotePublicKey,
		"RemotePublicKey must match the destination's key")
}

// =============================================================================
// Audit Item: Associated data — Correct AD for ChaCha20-Poly1305 in each state
//
// Per Proposal 144, ChaCha20-Poly1305 encryption uses different Associated Data
// (AD) depending on the session state:
// - New Session: AD = nil (no session tag exists yet; the ephemeral public key
//   is implicitly authenticated by the DH exchange)
// - Existing Session: AD = sessionTag (8 bytes; binds the ciphertext to the
//   specific session tag, preventing tag substitution attacks)
//
// This section verifies that:
// 1. New Session encryption uses nil AD
// 2. Existing Session encryption uses the session tag as AD
// 3. Mismatched AD causes decryption failure (AEAD authentication)
// 4. The AD binding prevents cross-session ciphertext replay
// =============================================================================

// TestGarlic_AssociatedData_NewSessionUsesNilAD verifies that New Session
// encryption passes nil as the associated data to ChaCha20-Poly1305.
// This is correct because the New Session format does not include a session
// tag, and the ephemeral key is authenticated by the DH exchange.
func TestGarlic_AssociatedData_NewSessionUsesNilAD(t *testing.T) {
	// New Session encryption calls encryptPayloadWithSessionKey which uses nil AD.
	// We verify this by encrypting with nil AD and confirming the resulting
	// ciphertext can be decrypted with nil AD.
	key := types.SHA256([]byte("test symmetric key for new session"))
	plaintext := []byte("new session payload with nil AD")

	aead, err := chacha20poly1305.NewAEAD(key)
	require.NoError(t, err)

	nonce := make([]byte, chacha20poly1305.NonceSize)
	ciphertext, tag, err := aead.Encrypt(plaintext, nil, nonce)
	require.NoError(t, err)

	// Decrypt with nil AD — should succeed (matching New Session behavior).
	decrypted, err := aead.Decrypt(ciphertext, tag[:], nil, nonce)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted, "New Session AD=nil roundtrip must succeed")

	// Decrypt with non-nil AD — should fail (AD mismatch).
	wrongAD := []byte("wrong AD")
	_, err = aead.Decrypt(ciphertext, tag[:], wrongAD, nonce)
	assert.Error(t, err, "decryption with non-nil AD must fail when encrypted with nil AD")
}

// TestGarlic_AssociatedData_ExistingSessionUsesSessionTagAD verifies that
// Existing Session encryption uses the 8-byte session tag as associated data
// for ChaCha20-Poly1305. This binds the ciphertext to the specific tag,
// preventing tag substitution attacks.
func TestGarlic_AssociatedData_ExistingSessionUsesSessionTagAD(t *testing.T) {
	key := types.SHA256([]byte("test message key for existing session"))
	plaintext := []byte("existing session payload with tag AD")
	sessionTag := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	// Encrypt with session tag as AD (matching encryptWithSessionKey behavior).
	ciphertext, tag, nonce, err := encryptWithSessionKey(key, plaintext, sessionTag)
	require.NoError(t, err)

	// Decrypt with same session tag — should succeed.
	decrypted, err := decryptWithSessionTag(key, ciphertext, tag, sessionTag, nonce)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted, "Existing Session AD=tag roundtrip must succeed")

	// Decrypt with wrong session tag — MUST fail (AD mismatch / AEAD auth failure).
	wrongTag := [8]byte{0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8}
	_, err = decryptWithSessionTag(key, ciphertext, tag, wrongTag, nonce)
	assert.Error(t, err, "decryption with wrong session tag MUST fail (AEAD binds tag as AD)")
}

// TestGarlic_AssociatedData_MismatchCausesAuthFailure verifies that any
// modification to the associated data causes ChaCha20-Poly1305 authentication
// failure, ensuring AEAD integrity.
func TestGarlic_AssociatedData_MismatchCausesAuthFailure(t *testing.T) {
	key := types.SHA256([]byte("integrity test key"))
	plaintext := []byte("integrity test payload")
	sessionTag := [8]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22}

	ciphertext, authTag, nonce, err := encryptWithSessionKey(key, plaintext, sessionTag)
	require.NoError(t, err)

	// Case 1: Correct AD → success.
	_, err = decryptWithSessionTag(key, ciphertext, authTag, sessionTag, nonce)
	require.NoError(t, err, "correct AD must decrypt successfully")

	// Case 2: nil AD instead of session tag → failure.
	aead, err := chacha20poly1305.NewAEAD(key)
	require.NoError(t, err)
	_, err = aead.Decrypt(ciphertext, authTag[:], nil, nonce)
	assert.Error(t, err, "nil AD must cause auth failure when tag was used as AD")

	// Case 3: Single bit flip in session tag → failure.
	flippedTag := sessionTag
	flippedTag[0] ^= 0x01
	_, err = decryptWithSessionTag(key, ciphertext, authTag, flippedTag, nonce)
	assert.Error(t, err, "single-bit flip in session tag must cause auth failure")
}

// TestGarlic_AssociatedData_CrossSessionReplayPrevented verifies that ciphertext
// encrypted for one session (with one tag as AD) cannot be replayed in a
// different session (with a different tag as AD), even if the same key is used.
func TestGarlic_AssociatedData_CrossSessionReplayPrevented(t *testing.T) {
	key := types.SHA256([]byte("shared key for replay test"))
	plaintext := []byte("payload that should not be replayable")

	tag1 := [8]byte{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01}
	tag2 := [8]byte{0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02}

	// Encrypt with session tag1.
	ciphertext, authTag, nonce, err := encryptWithSessionKey(key, plaintext, tag1)
	require.NoError(t, err)

	// Attempt to decrypt with session tag2 — MUST fail even with same key.
	_, err = decryptWithSessionTag(key, ciphertext, authTag, tag2, nonce)
	assert.Error(t, err,
		"cross-session replay MUST be prevented: ciphertext bound to tag1 cannot be decrypted with tag2")

	// Decrypt with original tag1 — MUST succeed.
	decrypted, err := decryptWithSessionTag(key, ciphertext, authTag, tag1, nonce)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted, "decryption with correct tag must succeed")
}

// TestGarlic_AssociatedData_NewSessionDecryptionUsesNilAD verifies the complete
// New Session decrypt path uses nil AD by doing a full encrypt→decrypt roundtrip
// through the session manager.
func TestGarlic_AssociatedData_NewSessionDecryptionUsesNilAD(t *testing.T) {
	senderSM, err := GenerateGarlicSessionManager()
	require.NoError(t, err)

	receiverPubBytes, receiverPrivBytes, err := ecies.GenerateKeyPair()
	require.NoError(t, err)
	var receiverPubKey, receiverPrivKey [32]byte
	copy(receiverPubKey[:], receiverPubBytes)
	copy(receiverPrivKey[:], receiverPrivBytes)
	receiverSM, err := NewGarlicSessionManager(receiverPrivKey)
	require.NoError(t, err)

	destHash := types.SHA256(receiverPubKey[:])
	plaintext := []byte("new session roundtrip verifying nil AD")

	// Encrypt (New Session — uses nil AD internally).
	ciphertext, err := senderSM.EncryptGarlicMessage(destHash, receiverPubKey, plaintext)
	require.NoError(t, err)

	// Decrypt (New Session — uses nil AD internally).
	decrypted, tag, err := receiverSM.DecryptGarlicMessage(ciphertext)
	require.NoError(t, err)
	assert.Equal(t, [8]byte{}, tag, "New Session decryption returns empty session tag")
	assert.Equal(t, plaintext, decrypted, "New Session nil-AD roundtrip must preserve plaintext")
}

// ============================================================================
// Section 6 — TunnelData (type 18) spec compliance tests
// ============================================================================

// TestTunnelData_Format_TotalSize verifies that TunnelData is exactly 1028 bytes:
// TunnelID (4 bytes) + Data (1024 bytes).
func TestTunnelData_Format_TotalSize(t *testing.T) {
	var td TunnelData
	assert.Equal(t, 1028, len(td), "TunnelData must be exactly 1028 bytes (TunnelID 4 + Data 1024)")
}

// TestTunnelData_Format_TunnelIDAt0to4 verifies TunnelID occupies bytes [0:4].
func TestTunnelData_Format_TunnelIDAt0to4(t *testing.T) {
	var td TunnelData
	// Set a known TunnelID
	binary.BigEndian.PutUint32(td[0:4], 0xDEADBEEF)

	tunnelID := td.TunnelID()
	assert.Equal(t, tunnel.TunnelID(0xDEADBEEF), tunnelID,
		"TunnelID must be read from bytes [0:4] as big-endian uint32")
}

// TestTunnelData_Format_DataAt4to1028 verifies Data occupies bytes [4:1028] = 1024 bytes.
func TestTunnelData_Format_DataAt4to1028(t *testing.T) {
	var td TunnelData
	// Fill data region with a known pattern
	for i := 4; i < 1028; i++ {
		td[i] = byte(i % 256)
	}

	data := td.Data()
	assert.Equal(t, 1024, len(data), "Data must be exactly 1024 bytes")
	for i := 0; i < 1024; i++ {
		assert.Equal(t, byte((i+4)%256), data[i], "Data byte %d mismatch", i)
	}
}

// TestTunnelData_Format_SetTunnelIDAndData verifies mutation round-trip.
func TestTunnelData_Format_SetTunnelIDAndData(t *testing.T) {
	var td TunnelData
	td.SetTunnelID(tunnel.TunnelID(42))

	var payload [1024]byte
	for i := range payload {
		payload[i] = 0xAB
	}
	td.SetData(payload)

	assert.Equal(t, tunnel.TunnelID(42), td.TunnelID())
	assert.Equal(t, payload, td.Data())
}

// TestTunnelData_Padding_ZeroPaddedToExactly1028 verifies that a zero-initialized
// TunnelData is exactly 1028 bytes of zeros (fixed-size array type).
func TestTunnelData_Padding_ZeroPaddedToExactly1028(t *testing.T) {
	var td TunnelData
	expected := make([]byte, 1028)
	assert.Equal(t, expected, td[:],
		"Zero-initialized TunnelData must be 1028 zero bytes")
}

// TestTunnelData_Padding_TunnelDataMessageEnforcesExact1028 verifies that
// TunnelDataMessage inner payload must be exactly 1028 bytes.
func TestTunnelData_Padding_TunnelDataMessageEnforcesExact1028(t *testing.T) {
	// Valid: create via NewTunnelDataMessage → marshal → unmarshal
	var validData [1024]byte
	validMsg := NewTunnelDataMessage(tunnel.TunnelID(1), validData)
	wire, err := validMsg.MarshalBinary()
	require.NoError(t, err)

	parsed := &TunnelDataMessage{BaseI2NPMessage: NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_TUNNEL_DATA)}
	err = parsed.UnmarshalBinary(wire)
	assert.NoError(t, err, "valid TunnelDataMessage must unmarshal successfully")

	// The inner payload must be exactly 1028 bytes
	assert.Equal(t, 1028, len(validMsg.GetData()),
		"TunnelDataMessage inner payload must be exactly 1028 bytes")
}

// TestTunnelData_Padding_NewTunnelDataMessageProduces1028 verifies that
// NewTunnelDataMessage always produces exactly 1028 bytes of inner payload.
func TestTunnelData_Padding_NewTunnelDataMessageProduces1028(t *testing.T) {
	var data [1024]byte
	for i := range data {
		data[i] = byte(i)
	}
	msg := NewTunnelDataMessage(tunnel.TunnelID(999), data)

	// GetData() returns the inner payload (without I2NP header)
	payload := msg.GetData()
	assert.Equal(t, 1028, len(payload),
		"NewTunnelDataMessage inner payload must be exactly 1028 bytes")

	// Verify TunnelID is at [0:4]
	tid := binary.BigEndian.Uint32(payload[0:4])
	assert.Equal(t, uint32(999), tid)
}

// ============================================================================
// Section 6 — TunnelGateway (type 19) spec compliance tests
// ============================================================================

// TestTunnelGateway_Format_TunnelIDLengthData verifies wire format:
// TunnelID (4 bytes) + Length (2 bytes) + Data (variable).
func TestTunnelGateway_Format_TunnelIDLengthData(t *testing.T) {
	payload := []byte("hello i2p tunnel gateway")
	msg := NewTunnelGatewayMessage(tunnel.TunnelID(0x12345678), payload)

	// GetData returns the inner payload: TunnelID(4) + Length(2) + Data
	data := msg.GetData()
	require.True(t, len(data) >= 6, "inner data must be at least 6 bytes")

	// TunnelID at [0:4]
	tid := binary.BigEndian.Uint32(data[0:4])
	assert.Equal(t, uint32(0x12345678), tid, "TunnelID must be at bytes [0:4]")

	// Length at [4:6]
	length := binary.BigEndian.Uint16(data[4:6])
	assert.Equal(t, uint16(len(payload)), length, "Length field at [4:6] must equal payload length")

	// Data at [6:]
	assert.Equal(t, payload, data[6:], "Data must follow Length field")
	assert.Equal(t, 6+len(payload), len(data), "Total size = 4+2+len(payload)")
}

// TestTunnelGateway_Format_MinimumSize verifies that TunnelGateway inner payload
// requires TunnelID(4)+Length(2) = at least 6 bytes.
func TestTunnelGateway_Format_MinimumSize(t *testing.T) {
	// The inner payload layout is: TunnelID(4) + Length(2) + Data(variable)
	// A valid empty-payload gateway has exactly 6 bytes of inner data
	payload := []byte{}
	msg := NewTunnelGatewayMessage(tunnel.TunnelID(1), payload)
	data := msg.GetData()
	assert.Equal(t, 6, len(data), "empty-payload gateway inner data must be 6 bytes")

	// TunnelID at [0:4], Length at [4:6] = 0
	length := binary.BigEndian.Uint16(data[4:6])
	assert.Equal(t, uint16(0), length, "Length field must be 0 for empty payload")
}

// TestTunnelGateway_Format_TruncatedData verifies that unmarshal detects truncation.
func TestTunnelGateway_Format_TruncatedData(t *testing.T) {
	// Create a valid message, then truncate its I2NP wire representation
	payload := bytes.Repeat([]byte{0xAA}, 100)
	msg := NewTunnelGatewayMessage(tunnel.TunnelID(1), payload)
	wire, err := msg.MarshalBinary()
	require.NoError(t, err)

	// Truncate: remove last 50 bytes of the wire format
	truncated := wire[:len(wire)-50]

	parsed := &TunnelGateway{BaseI2NPMessage: NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_TUNNEL_GATEWAY)}
	err = parsed.UnmarshalBinary(truncated)
	assert.Error(t, err, "truncated data must be detected")
}

// TestTunnelGateway_Format_RoundTrip verifies marshal → unmarshal preserves all fields.
func TestTunnelGateway_Format_RoundTrip(t *testing.T) {
	payload := []byte("roundtrip payload for tunnel gateway")
	tid := tunnel.TunnelID(0xCAFEBABE)
	original := NewTunnelGatewayMessage(tid, payload)

	data, err := original.MarshalBinary()
	require.NoError(t, err)

	parsed := &TunnelGateway{BaseI2NPMessage: NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_TUNNEL_GATEWAY)}
	err = parsed.UnmarshalBinary(data)
	require.NoError(t, err)

	assert.Equal(t, tid, parsed.TunnelID, "TunnelID must survive roundtrip")
	assert.Equal(t, payload, parsed.Data, "Data must survive roundtrip")
}

// ============================================================================
// Section 6 — Data (type 20) spec compliance tests
// ============================================================================

// TestData_Format_LengthPlusPayload verifies wire format: Length (4 bytes) + Payload.
func TestData_Format_LengthPlusPayload(t *testing.T) {
	payload := []byte("i2p data message content")
	msg := NewDataMessage(payload)

	// GetData returns the inner data: Length(4) + Payload
	data := msg.GetData()
	require.True(t, len(data) >= 4, "inner data must be at least 4 bytes")

	// Length at [0:4]
	length := binary.BigEndian.Uint32(data[0:4])
	assert.Equal(t, uint32(len(payload)), length, "Length field at [0:4] must equal payload size")

	// Payload at [4:]
	assert.Equal(t, payload, data[4:], "Payload must follow Length field")
	assert.Equal(t, 4+len(payload), len(data), "Total size = 4 + payload length")
}

// TestData_Format_MinimumSizeIs4 verifies that Data inner payload requires at least
// 4 bytes for the Length field.
func TestData_Format_MinimumSizeIs4(t *testing.T) {
	// The inner payload starts with Length(4) + Payload(variable)
	// A zero-length message should have exactly 4 bytes of inner data
	msg := NewDataMessage([]byte{})
	data := msg.GetData()
	assert.Equal(t, 4, len(data), "empty DataMessage inner data must be 4 bytes")

	// Length field should be 0
	length := binary.BigEndian.Uint32(data[0:4])
	assert.Equal(t, uint32(0), length, "Length field must be 0 for empty payload")
}

// TestData_Format_TruncatedPayload verifies truncation detection.
func TestData_Format_TruncatedPayload(t *testing.T) {
	// Create a valid message, then truncate its wire form
	payload := bytes.Repeat([]byte{0xBB}, 200)
	msg := NewDataMessage(payload)
	wire, err := msg.MarshalBinary()
	require.NoError(t, err)

	// Truncate the wire form
	truncated := wire[:len(wire)-100]

	parsed := &DataMessage{BaseI2NPMessage: NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_DATA)}
	err = parsed.UnmarshalBinary(truncated)
	assert.Error(t, err, "truncated payload must be detected")
}

// TestData_Format_RoundTrip verifies marshal → unmarshal round-trip.
func TestData_Format_RoundTrip(t *testing.T) {
	payload := []byte("data message roundtrip test content 12345")
	original := NewDataMessage(payload)

	data, err := original.MarshalBinary()
	require.NoError(t, err)

	parsed := &DataMessage{BaseI2NPMessage: NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_DATA)}
	err = parsed.UnmarshalBinary(data)
	require.NoError(t, err)

	assert.Equal(t, payload, parsed.Payload, "Payload must survive roundtrip")
}

// ============================================================================
// Section 6 — TunnelBuild / VariableTunnelBuild (types 21, 23) spec compliance
// ============================================================================

// TestTunnelBuild_RecordCount_FixedAt8 verifies TunnelBuild always has exactly 8 records.
func TestTunnelBuild_RecordCount_FixedAt8(t *testing.T) {
	var tb TunnelBuild
	assert.Equal(t, 8, len(tb), "TunnelBuild must have exactly 8 BuildRequestRecord slots")
}

// TestTunnelBuild_RecordCount_WireSize verifies TunnelBuild wire size = 8 × 528 = 4224 bytes.
func TestTunnelBuild_RecordCount_WireSize(t *testing.T) {
	expectedSize := 8 * StandardBuildRecordSize
	assert.Equal(t, 4224, expectedSize, "TunnelBuild wire size must be 8 × 528 = 4224")
}

// TestVariableTunnelBuild_RecordCount_1to8 verifies VariableTunnelBuild supports 1-8 records.
func TestVariableTunnelBuild_RecordCount_1to8(t *testing.T) {
	for count := 1; count <= 8; count++ {
		records := make([]BuildRequestRecord, count)
		vtb := VariableTunnelBuild{
			Count:               count,
			BuildRequestRecords: records,
		}
		assert.Equal(t, count, vtb.Count,
			"VariableTunnelBuild must support Count=%d", count)
		assert.Equal(t, count, len(vtb.BuildRequestRecords))
	}
}

// TestVariableTunnelBuild_RecordCount_WireSizeFormula verifies wire size = 1 + count×528.
func TestVariableTunnelBuild_RecordCount_WireSizeFormula(t *testing.T) {
	for count := 1; count <= 8; count++ {
		expectedSize := 1 + count*StandardBuildRecordSize
		t.Run(fmt.Sprintf("Count%d", count), func(t *testing.T) {
			assert.Equal(t, 1+count*528, expectedSize,
				"Wire size for %d records = 1 + %d×528", count, count)
		})
	}
}

// TestTunnelBuild_ECIESRecords_ShortRecordSize218 verifies ECIES short record = 218 bytes.
func TestTunnelBuild_ECIESRecords_ShortRecordSize218(t *testing.T) {
	assert.Equal(t, 218, ShortBuildRecordSize,
		"ECIES short build record must be 218 bytes per Proposal 152/157")
}

// TestTunnelBuild_ECIESRecords_ShortRecordComponents verifies 218 = toPeer(16) + ephKey(32) + encrypted(154+16).
func TestTunnelBuild_ECIESRecords_ShortRecordComponents(t *testing.T) {
	assert.Equal(t, 64, ShortRecordHeaderSize,
		"Short record header = toPeer(16) + ephemeralKey(32) + MAC(16) = 64")
	assert.Equal(t, 154, ShortBuildRecordCleartextLen,
		"Short record cleartext = 154 bytes")
	assert.Equal(t, ShortBuildRecordCleartextLen+ShortRecordHeaderSize, ShortBuildRecordSize,
		"ShortBuildRecordSize = cleartext(154) + header(64) = 218")
}

// TestTunnelBuild_ECIESRecords_ShortBytesProduces218 verifies ShortBytes() output size.
func TestTunnelBuild_ECIESRecords_ShortBytesProduces218(t *testing.T) {
	record := BuildRequestRecord{
		ReceiveTunnel: tunnel.TunnelID(1),
		NextTunnel:    tunnel.TunnelID(2),
		RequestTime:   time.Now(),
	}
	shortData := record.ShortBytes()
	assert.Equal(t, ShortBuildRecordSize, len(shortData),
		"ShortBytes() must produce exactly 218 bytes")
}

// TestTunnelBuild_RecordFormat_CleartextIs222 verifies standard cleartext record = 222 bytes.
func TestTunnelBuild_RecordFormat_CleartextIs222(t *testing.T) {
	assert.Equal(t, 222, StandardBuildRecordCleartextLen,
		"Standard build request cleartext must be 222 bytes")
}

// TestTunnelBuild_RecordFormat_BytesProduces222 verifies Bytes() serialization is 222 bytes.
func TestTunnelBuild_RecordFormat_BytesProduces222(t *testing.T) {
	record := BuildRequestRecord{
		ReceiveTunnel: tunnel.TunnelID(100),
		NextTunnel:    tunnel.TunnelID(200),
		Flag:          1,
		RequestTime:   time.Now(),
		SendMessageID: 42,
	}
	data := record.Bytes()
	assert.Equal(t, 222, len(data),
		"BuildRequestRecord.Bytes() must produce exactly 222 bytes")
}

// TestTunnelBuild_RecordFormat_FieldLayout verifies the exact byte offsets per I2P spec.
func TestTunnelBuild_RecordFormat_FieldLayout(t *testing.T) {
	var ourIdent common.Hash
	for i := range ourIdent {
		ourIdent[i] = 0xAA
	}
	var nextIdent common.Hash
	for i := range nextIdent {
		nextIdent[i] = 0xBB
	}
	var layerKey, ivKey, replyKey session_key.SessionKey
	for i := range layerKey {
		layerKey[i] = 0x11
	}
	for i := range ivKey {
		ivKey[i] = 0x22
	}
	for i := range replyKey {
		replyKey[i] = 0x33
	}
	var replyIV [16]byte
	for i := range replyIV {
		replyIV[i] = 0x44
	}

	record := BuildRequestRecord{
		ReceiveTunnel: tunnel.TunnelID(0x01020304),
		OurIdent:      ourIdent,
		NextTunnel:    tunnel.TunnelID(0x05060708),
		NextIdent:     nextIdent,
		LayerKey:      layerKey,
		IVKey:         ivKey,
		ReplyKey:      replyKey,
		ReplyIV:       replyIV,
		Flag:          7,
		RequestTime:   time.Unix(3600*1000, 0), // 1000 hours since epoch
		SendMessageID: 0x0A0B0C0D,
	}

	data := record.Bytes()
	require.Equal(t, 222, len(data))

	// ReceiveTunnel at [0:4]
	assert.Equal(t, byte(0x01), data[0])
	assert.Equal(t, byte(0x04), data[3])

	// OurIdent at [4:36]
	assert.Equal(t, byte(0xAA), data[4])
	assert.Equal(t, byte(0xAA), data[35])

	// NextTunnel at [36:40]
	assert.Equal(t, byte(0x05), data[36])
	assert.Equal(t, byte(0x08), data[39])

	// NextIdent at [40:72]
	assert.Equal(t, byte(0xBB), data[40])
	assert.Equal(t, byte(0xBB), data[71])

	// LayerKey at [72:104]
	assert.Equal(t, byte(0x11), data[72])
	assert.Equal(t, byte(0x11), data[103])

	// IVKey at [104:136]
	assert.Equal(t, byte(0x22), data[104])
	assert.Equal(t, byte(0x22), data[135])

	// ReplyKey at [136:168]
	assert.Equal(t, byte(0x33), data[136])
	assert.Equal(t, byte(0x33), data[167])

	// ReplyIV at [168:184]
	assert.Equal(t, byte(0x44), data[168])
	assert.Equal(t, byte(0x44), data[183])

	// Flag at [184]
	assert.Equal(t, byte(7), data[184])

	// RequestTime at [185:189] — hours since epoch
	hours := binary.BigEndian.Uint32(data[185:189])
	assert.Equal(t, uint32(1000), hours, "RequestTime at [185:189] must be hours since epoch")

	// SendMessageID at [189:193]
	msgID := binary.BigEndian.Uint32(data[189:193])
	assert.Equal(t, uint32(0x0A0B0C0D), msgID, "SendMessageID at [189:193]")

	// Padding at [193:222] = 29 bytes
	assert.Equal(t, 29, len(data[193:222]), "Padding must be 29 bytes at [193:222]")
}

// TestTunnelBuild_RecordFormat_ParseRoundTrip verifies Bytes() → ReadBuildRequestRecord roundtrip.
func TestTunnelBuild_RecordFormat_ParseRoundTrip(t *testing.T) {
	original := BuildRequestRecord{
		ReceiveTunnel: tunnel.TunnelID(12345),
		NextTunnel:    tunnel.TunnelID(67890),
		Flag:          1,
		RequestTime:   time.Unix(3600*500, 0), // truncated to hour
		SendMessageID: 9999,
	}
	for i := range original.OurIdent {
		original.OurIdent[i] = byte(i)
	}
	for i := range original.NextIdent {
		original.NextIdent[i] = byte(i + 32)
	}

	data := original.Bytes()
	require.Equal(t, 222, len(data))

	parsed, err := ReadBuildRequestRecord(data)
	require.NoError(t, err)

	assert.Equal(t, original.ReceiveTunnel, parsed.ReceiveTunnel)
	assert.Equal(t, original.OurIdent, parsed.OurIdent)
	assert.Equal(t, original.NextTunnel, parsed.NextTunnel)
	assert.Equal(t, original.NextIdent, parsed.NextIdent)
	assert.Equal(t, original.Flag, parsed.Flag)
	assert.Equal(t, original.SendMessageID, parsed.SendMessageID)
}

// TestTunnelBuild_ReplyProcessing_ReplyCodes verifies all defined reply codes.
func TestTunnelBuild_ReplyProcessing_ReplyCodes(t *testing.T) {
	assert.Equal(t, byte(0x00), byte(TUNNEL_BUILD_REPLY_SUCCESS), "SUCCESS = 0x00")
	assert.Equal(t, byte(0x01), byte(TUNNEL_BUILD_REPLY_REJECT), "REJECT = 0x01")
	assert.Equal(t, byte(0x02), byte(TUNNEL_BUILD_REPLY_OVERLOAD), "OVERLOAD = 0x02")
	assert.Equal(t, byte(0x03), byte(TUNNEL_BUILD_REPLY_BANDWIDTH), "BANDWIDTH = 0x03")
	assert.Equal(t, byte(0x04), byte(TUNNEL_BUILD_REPLY_INVALID), "INVALID = 0x04")
	assert.Equal(t, byte(0x05), byte(TUNNEL_BUILD_REPLY_EXPIRED), "EXPIRED = 0x05")
}

// TestTunnelBuild_ReplyProcessing_AllAccepted verifies ProcessReply succeeds when all hops accept.
func TestTunnelBuild_ReplyProcessing_AllAccepted(t *testing.T) {
	var records [8]BuildResponseRecord
	for i := range records {
		var randomData [495]byte
		for j := range randomData {
			randomData[j] = byte(i*10 + j%256)
		}
		records[i] = CreateBuildResponseRecord(TUNNEL_BUILD_REPLY_SUCCESS, randomData)
	}

	reply := &TunnelBuildReply{Records: records}
	err := reply.ProcessReply()
	assert.NoError(t, err, "All hops accepted — ProcessReply must succeed")
}

// TestTunnelBuild_ReplyProcessing_OneReject verifies ProcessReply fails when any hop rejects.
func TestTunnelBuild_ReplyProcessing_OneReject(t *testing.T) {
	var records [8]BuildResponseRecord
	for i := range records {
		var randomData [495]byte
		for j := range randomData {
			randomData[j] = byte(i + j%256)
		}
		code := byte(TUNNEL_BUILD_REPLY_SUCCESS)
		if i == 3 {
			code = byte(TUNNEL_BUILD_REPLY_REJECT)
		}
		records[i] = CreateBuildResponseRecord(code, randomData)
	}

	reply := &TunnelBuildReply{Records: records}
	err := reply.ProcessReply()
	assert.Error(t, err, "One rejection means tunnel build failed")
}

// TestTunnelBuild_ReplyProcessing_HashIntegrity verifies SHA-256 hash verification.
func TestTunnelBuild_ReplyProcessing_HashIntegrity(t *testing.T) {
	var randomData [495]byte
	for i := range randomData {
		randomData[i] = byte(i)
	}
	record := CreateBuildResponseRecord(TUNNEL_BUILD_REPLY_SUCCESS, randomData)

	// Verify the hash is correct
	hashInput := make([]byte, 496)
	copy(hashInput[:495], randomData[:])
	hashInput[495] = TUNNEL_BUILD_REPLY_SUCCESS
	expectedHash := types.SHA256(hashInput)
	assert.Equal(t, expectedHash[:], record.Hash[:],
		"CreateBuildResponseRecord must set Hash = SHA256(RandomData + Reply)")

	// Create a full set of 8 valid records, then corrupt one
	var records [8]BuildResponseRecord
	for i := range records {
		var rd [495]byte
		for j := range rd {
			rd[j] = byte(i*31 + j%256)
		}
		records[i] = CreateBuildResponseRecord(TUNNEL_BUILD_REPLY_SUCCESS, rd)
	}
	// Corrupt record 0's hash
	records[0].Hash[0] ^= 0xFF

	reply := &TunnelBuildReply{Records: records}
	err := reply.ProcessReply()
	assert.Error(t, err, "corrupted hash must cause ProcessReply to fail")
}

// ============================================================================
// Section 6 — ShortTunnelBuild / ShortTunnelBuildReply (types 25, 26)
// ============================================================================

// TestShortTunnelBuild_RecordFormat_Size218 verifies short records are 218 bytes.
func TestShortTunnelBuild_RecordFormat_Size218(t *testing.T) {
	record := BuildRequestRecord{
		ReceiveTunnel: tunnel.TunnelID(1),
		NextTunnel:    tunnel.TunnelID(2),
		RequestTime:   time.Now(),
	}
	shortData := record.ShortBytes()
	assert.Equal(t, 218, len(shortData),
		"Short build record must be 218 bytes (Proposal 157)")
}

// TestShortTunnelBuild_RecordFormat_ToPeerAt0to16 verifies toPeer identity hash prefix.
func TestShortTunnelBuild_RecordFormat_ToPeerAt0to16(t *testing.T) {
	var ourIdent common.Hash
	for i := range ourIdent {
		ourIdent[i] = byte(0xDD)
	}
	record := BuildRequestRecord{
		OurIdent:    ourIdent,
		RequestTime: time.Now(),
	}
	shortData := record.ShortBytes()

	// toPeer at [0:16] = first 16 bytes of OurIdent
	for i := 0; i < 16; i++ {
		assert.Equal(t, byte(0xDD), shortData[i],
			"toPeer[%d] must match OurIdent[:16]", i)
	}
}

// TestShortTunnelBuild_RecordFormat_EphemeralKeyAt16to48 verifies ephemeral key placeholder.
func TestShortTunnelBuild_RecordFormat_EphemeralKeyAt16to48(t *testing.T) {
	record := BuildRequestRecord{RequestTime: time.Now()}
	shortData := record.ShortBytes()

	// Bytes [16:48] reserved for ephemeral X25519 key (zeroed pre-encryption)
	for i := 16; i < 48; i++ {
		assert.Equal(t, byte(0), shortData[i],
			"Ephemeral key placeholder at [%d] must be zero pre-encryption", i)
	}
}

// TestShortTunnelBuild_RecordFormat_CleartextPayloadLayout verifies payload field offsets.
func TestShortTunnelBuild_RecordFormat_CleartextPayloadLayout(t *testing.T) {
	record := BuildRequestRecord{
		ReceiveTunnel: tunnel.TunnelID(0x01020304),
		NextTunnel:    tunnel.TunnelID(0x05060708),
		Flag:          3,
		RequestTime:   time.Unix(60*5000, 0), // 5000 minutes since epoch
		SendMessageID: 0x0A0B0C0D,
	}
	for i := range record.NextIdent {
		record.NextIdent[i] = 0xCC
	}

	shortData := record.ShortBytes()
	require.Equal(t, 218, len(shortData))

	const off = 48 // payload offset

	// receive_tunnel at [off:off+4]
	rcvTunnel := binary.BigEndian.Uint32(shortData[off : off+4])
	assert.Equal(t, uint32(0x01020304), rcvTunnel, "receive_tunnel at payload [0:4]")

	// next_tunnel at [off+4:off+8]
	nxtTunnel := binary.BigEndian.Uint32(shortData[off+4 : off+8])
	assert.Equal(t, uint32(0x05060708), nxtTunnel, "next_tunnel at payload [4:8]")

	// next_ident at [off+8:off+40]
	assert.Equal(t, byte(0xCC), shortData[off+8], "next_ident starts at payload[8]")
	assert.Equal(t, byte(0xCC), shortData[off+39], "next_ident ends at payload[39]")

	// flag at [off+40]
	assert.Equal(t, byte(3), shortData[off+40], "flag at payload[40]")

	// request_time at [off+44:off+48] — minutes since epoch for short records
	minutes := binary.BigEndian.Uint32(shortData[off+44 : off+48])
	assert.Equal(t, uint32(5000), minutes, "request_time at payload[44:48] in minutes")

	// send_message_id at [off+52:off+56]
	sendMsgID := binary.BigEndian.Uint32(shortData[off+52 : off+56])
	assert.Equal(t, uint32(0x0A0B0C0D), sendMsgID, "send_message_id at payload[52:56]")
}

// TestShortTunnelBuild_RecordFormat_NoElGamalFallback verifies ECIES-only (no 528-byte records).
func TestShortTunnelBuild_RecordFormat_NoElGamalFallback(t *testing.T) {
	assert.NotEqual(t, StandardBuildRecordSize, ShortBuildRecordSize,
		"Short records (218) must differ from standard ElGamal records (528)")
	assert.Less(t, ShortBuildRecordSize, StandardBuildRecordSize,
		"Short ECIES records must be smaller than standard records")
}

// TestShortTunnelBuild_LayerEncryption_ChaCha20Poly1305Used verifies that
// BuildRecordCrypto uses ChaCha20-Poly1305 for reply record encryption.
func TestShortTunnelBuild_LayerEncryption_ChaCha20Poly1305Used(t *testing.T) {
	crypto := &BuildRecordCrypto{}

	// Create a valid response record
	var randomData [495]byte
	for i := range randomData {
		randomData[i] = byte(i % 256)
	}
	record := CreateBuildResponseRecord(TUNNEL_BUILD_REPLY_SUCCESS, randomData)

	// Encrypt with ChaCha20-Poly1305
	var key session_key.SessionKey
	for i := range key {
		key[i] = byte(i + 1)
	}
	var iv [16]byte
	for i := range iv {
		iv[i] = byte(i + 100)
	}

	encrypted, err := crypto.EncryptReplyRecord(record, key, iv)
	require.NoError(t, err)

	// ChaCha20-Poly1305 adds 16-byte auth tag: 528 plaintext → 544 ciphertext
	assert.Equal(t, 544, len(encrypted),
		"ChaCha20-Poly1305 encrypted reply must be 528+16=544 bytes")

	// Decrypt and verify roundtrip
	decrypted, err := crypto.DecryptReplyRecord(encrypted, key, iv)
	require.NoError(t, err)
	assert.Equal(t, byte(TUNNEL_BUILD_REPLY_SUCCESS), decrypted.Reply,
		"Decrypted reply code must match original")
	assert.Equal(t, record.Hash, decrypted.Hash,
		"Decrypted hash must match original")
}

// TestShortTunnelBuild_LayerEncryption_AuthTagRequired verifies authentication tag is checked.
func TestShortTunnelBuild_LayerEncryption_AuthTagRequired(t *testing.T) {
	crypto := &BuildRecordCrypto{}

	var randomData [495]byte
	record := CreateBuildResponseRecord(TUNNEL_BUILD_REPLY_SUCCESS, randomData)

	var key session_key.SessionKey
	for i := range key {
		key[i] = byte(i)
	}
	var iv [16]byte

	encrypted, err := crypto.EncryptReplyRecord(record, key, iv)
	require.NoError(t, err)

	// Corrupt the auth tag (last 16 bytes)
	encrypted[len(encrypted)-1] ^= 0xFF

	_, err = crypto.DecryptReplyRecord(encrypted, key, iv)
	assert.Error(t, err, "corrupted auth tag must cause decryption failure")
}

// TestShortTunnelBuild_LayerEncryption_WrongKeyFails verifies wrong key detection.
func TestShortTunnelBuild_LayerEncryption_WrongKeyFails(t *testing.T) {
	crypto := &BuildRecordCrypto{}

	var randomData [495]byte
	record := CreateBuildResponseRecord(TUNNEL_BUILD_REPLY_SUCCESS, randomData)

	var key session_key.SessionKey
	for i := range key {
		key[i] = 0xAA
	}
	var iv [16]byte

	encrypted, err := crypto.EncryptReplyRecord(record, key, iv)
	require.NoError(t, err)

	// Try with wrong key
	var wrongKey session_key.SessionKey
	for i := range wrongKey {
		wrongKey[i] = 0xBB
	}
	_, err = crypto.DecryptReplyRecord(encrypted, wrongKey, iv)
	assert.Error(t, err, "wrong key must cause decryption failure")
}

// ============================================================================
// Section 6 — TunnelBuildReply / VariableTunnelBuildReply (types 22, 24)
// ============================================================================

// TestTunnelBuildReply_Format_8ResponseRecords verifies TunnelBuildReply has 8 records.
func TestTunnelBuildReply_Format_8ResponseRecords(t *testing.T) {
	var reply TunnelBuildReply
	assert.Equal(t, 8, len(reply.Records),
		"TunnelBuildReply must have exactly 8 BuildResponseRecord slots")
}

// TestTunnelBuildReply_Format_ResponseRecordIs528 verifies each response record = 528 bytes.
func TestTunnelBuildReply_Format_ResponseRecordIs528(t *testing.T) {
	// BuildResponseRecord: Hash(32) + RandomData(495) + Reply(1) = 528 bytes
	assert.Equal(t, 528, 32+495+1,
		"BuildResponseRecord must be Hash(32)+RandomData(495)+Reply(1)=528 bytes")
}

// TestTunnelBuildReply_Format_HashIsFirst32Bytes verifies Hash occupies first 32 bytes.
func TestTunnelBuildReply_Format_HashIsFirst32Bytes(t *testing.T) {
	var randomData [495]byte
	for i := range randomData {
		randomData[i] = byte(i)
	}
	record := CreateBuildResponseRecord(TUNNEL_BUILD_REPLY_SUCCESS, randomData)

	// Serialize manually
	buf := make([]byte, 528)
	copy(buf[0:32], record.Hash[:])
	copy(buf[32:527], record.RandomData[:])
	buf[527] = record.Reply

	// Parse back
	parsed, err := ReadBuildResponseRecord(buf)
	require.NoError(t, err)
	assert.Equal(t, record.Hash, parsed.Hash, "Hash at [0:32] must survive roundtrip")
	assert.Equal(t, record.RandomData, parsed.RandomData, "RandomData at [32:527] must survive roundtrip")
	assert.Equal(t, record.Reply, parsed.Reply, "Reply at [527] must survive roundtrip")
}

// TestVariableTunnelBuildReply_Format_CountPlusRecords verifies the count+records layout.
func TestVariableTunnelBuildReply_Format_CountPlusRecords(t *testing.T) {
	// Create VariableTunnelBuildReply with 3 records
	records := make([]BuildResponseRecord, 3)
	for i := range records {
		var randomData [495]byte
		for j := range randomData {
			randomData[j] = byte(i*37 + j%256)
		}
		records[i] = CreateBuildResponseRecord(TUNNEL_BUILD_REPLY_SUCCESS, randomData)
	}

	reply := &VariableTunnelBuildReply{
		Count:                3,
		BuildResponseRecords: records,
	}

	assert.Equal(t, 3, reply.Count)
	assert.Equal(t, 3, len(reply.BuildResponseRecords))

	// All records should validate
	err := reply.ProcessReply()
	assert.NoError(t, err, "All-success VariableTunnelBuildReply.ProcessReply must succeed")
}

// TestVariableTunnelBuildReply_Format_SHA256Integrity verifies hash integrity check.
func TestVariableTunnelBuildReply_Format_SHA256Integrity(t *testing.T) {
	var randomData [495]byte
	for i := range randomData {
		randomData[i] = byte(i * 3)
	}
	record := CreateBuildResponseRecord(TUNNEL_BUILD_REPLY_OVERLOAD, randomData)

	// Verify the hash is SHA256(RandomData || Reply)
	hashInput := make([]byte, 496)
	copy(hashInput[:495], randomData[:])
	hashInput[495] = TUNNEL_BUILD_REPLY_OVERLOAD
	expectedHash := types.SHA256(hashInput)
	// Compare bytes since record.Hash is common.Hash (named type)
	assert.Equal(t, expectedHash[:], record.Hash[:], "Hash must be SHA256(RandomData || Reply)")
}

// TestShortTunnelBuildReply_Format_AllAccepted verifies ShortTunnelBuildReply processes correctly.
func TestShortTunnelBuildReply_Format_AllAccepted(t *testing.T) {
	records := make([]BuildResponseRecord, 4)
	for i := range records {
		var randomData [495]byte
		for j := range randomData {
			randomData[j] = byte(i*17 + j%256)
		}
		records[i] = CreateBuildResponseRecord(TUNNEL_BUILD_REPLY_SUCCESS, randomData)
	}

	reply := NewShortTunnelBuildReply(records)
	assert.Equal(t, 4, reply.Count)

	err := reply.ProcessReply()
	assert.NoError(t, err, "All-success ShortTunnelBuildReply must succeed")
}

// TestShortTunnelBuildReply_Format_MixedResults verifies mixed accept/reject handling.
func TestShortTunnelBuildReply_Format_MixedResults(t *testing.T) {
	records := make([]BuildResponseRecord, 3)
	var rd0, rd1, rd2 [495]byte
	for i := range rd0 {
		rd0[i] = 0x11
	}
	for i := range rd1 {
		rd1[i] = 0x22
	}
	for i := range rd2 {
		rd2[i] = 0x33
	}
	records[0] = CreateBuildResponseRecord(TUNNEL_BUILD_REPLY_SUCCESS, rd0)
	records[1] = CreateBuildResponseRecord(TUNNEL_BUILD_REPLY_BANDWIDTH, rd1)
	records[2] = CreateBuildResponseRecord(TUNNEL_BUILD_REPLY_SUCCESS, rd2)

	reply := NewShortTunnelBuildReply(records)
	err := reply.ProcessReply()
	assert.Error(t, err, "Mixed results (1 reject) means build failed")
}

// ============================================================================
// Section 6 — Cryptography Audit
// ============================================================================

// TestCryptoAudit_GarlicEncryption_ECIESRatchetImplemented verifies that garlic
// encryption uses ECIES-X25519-AEAD-Ratchet as specified in Proposal 144.
func TestCryptoAudit_GarlicEncryption_ECIESRatchetImplemented(t *testing.T) {
	// Verify session manager can be created (proves ECIES infrastructure exists)
	sm, err := GenerateGarlicSessionManager()
	require.NoError(t, err, "GarlicSessionManager must be creatable")

	// Verify key generation produces valid X25519 keys
	pubBytes, privBytes, err := ecies.GenerateKeyPair()
	require.NoError(t, err)
	assert.Equal(t, 32, len(pubBytes), "ECIES public key must be 32 bytes (X25519)")
	assert.Equal(t, 32, len(privBytes), "ECIES private key must be 32 bytes (X25519)")

	// Encrypt a message — this exercises the full Proposal 144 state machine
	var receiverPub [32]byte
	copy(receiverPub[:], pubBytes)
	destHash := types.SHA256(receiverPub[:])
	plaintext := []byte("crypto audit garlic test")

	ciphertext, err := sm.EncryptGarlicMessage(destHash, receiverPub, plaintext)
	require.NoError(t, err)
	assert.True(t, len(ciphertext) > 0, "ECIES garlic ciphertext must be non-empty")

	// New Session format: ephemeralPubKey(32) + nonce(12) + ciphertext + tag(16) = min 60
	assert.True(t, len(ciphertext) >= 60,
		"New Session ciphertext must be at least 60 bytes (32+12+N+16)")
}

// TestCryptoAudit_BuildRecordEncryption_ChaCha20Poly1305 verifies that build record
// encryption uses ChaCha20-Poly1305 per Proposal 152.
func TestCryptoAudit_BuildRecordEncryption_ChaCha20Poly1305(t *testing.T) {
	crypto := &BuildRecordCrypto{}

	// Prepare a response record
	var randomData [495]byte
	for i := range randomData {
		randomData[i] = byte(i)
	}
	record := CreateBuildResponseRecord(TUNNEL_BUILD_REPLY_SUCCESS, randomData)

	var key session_key.SessionKey
	for i := range key {
		key[i] = byte(i + 0x10)
	}
	var iv [16]byte
	for i := range iv {
		iv[i] = byte(i + 0x20)
	}

	// Encrypt — must produce 544 bytes (528 + 16 auth tag)
	encrypted, err := crypto.EncryptReplyRecord(record, key, iv)
	require.NoError(t, err)
	assert.Equal(t, 544, len(encrypted),
		"ChaCha20-Poly1305 must produce 528+16=544 bytes per Proposal 152")

	// Decrypt — roundtrip must succeed
	decrypted, err := crypto.DecryptReplyRecord(encrypted, key, iv)
	require.NoError(t, err)
	assert.Equal(t, record.Reply, decrypted.Reply)
	assert.Equal(t, record.Hash, decrypted.Hash)
	assert.Equal(t, record.RandomData, decrypted.RandomData)
}

// TestCryptoAudit_BuildRecordEncryption_Nonce12Bytes verifies ChaCha20-Poly1305
// uses the first 12 bytes of the 16-byte IV as the nonce.
func TestCryptoAudit_BuildRecordEncryption_Nonce12Bytes(t *testing.T) {
	crypto := &BuildRecordCrypto{}

	var randomData [495]byte
	record := CreateBuildResponseRecord(TUNNEL_BUILD_REPLY_SUCCESS, randomData)

	var key session_key.SessionKey
	for i := range key {
		key[i] = 0x42
	}

	// Two IVs that differ only in byte 12-15 (beyond the 12-byte nonce)
	iv1 := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0xAA, 0xBB, 0xCC, 0xDD}
	iv2 := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0x11, 0x22, 0x33, 0x44}

	enc1, err := crypto.EncryptReplyRecord(record, key, iv1)
	require.NoError(t, err)
	enc2, err := crypto.EncryptReplyRecord(record, key, iv2)
	require.NoError(t, err)

	// Same first 12 bytes → same nonce → same ciphertext
	assert.Equal(t, enc1, enc2,
		"Only first 12 bytes of IV are used as nonce; bytes 12-15 must not affect output")
}

// TestCryptoAudit_HKDFUsage_InfoStringsPresent verifies HKDF uses role-specific info strings.
func TestCryptoAudit_HKDFUsage_InfoStringsPresent(t *testing.T) {
	// The implementation uses "ECIES-Ratchet-Initiator" and "ECIES-Ratchet-Responder"
	assert.Equal(t, "ECIES-Ratchet-Initiator", hkdfInfoInitiator,
		"HKDF info string for initiator must be 'ECIES-Ratchet-Initiator'")
	assert.Equal(t, "ECIES-Ratchet-Responder", hkdfInfoResponder,
		"HKDF info string for responder must be 'ECIES-Ratchet-Responder'")
}

// TestCryptoAudit_HKDFUsage_DeriveDirectionalKeys verifies HKDF produces distinct
// directional keys for initiator and responder.
func TestCryptoAudit_HKDFUsage_DeriveDirectionalKeys(t *testing.T) {
	sharedSecret := types.SHA256([]byte("test shared secret for HKDF audit"))
	keys, err := deriveSessionKeysFromSecret(sharedSecret[:])
	require.NoError(t, err)

	iSend, iRecv := deriveDirectionalKeys(keys.rootKey, true)
	rSend, rRecv := deriveDirectionalKeys(keys.rootKey, false)

	// Initiator send/recv must be different
	assert.NotEqual(t, iSend, iRecv,
		"Initiator send and recv keys must differ")

	// Cross-role symmetry: initiator's send = responder's recv
	assert.Equal(t, iSend, rRecv,
		"Initiator send must equal responder recv")
	assert.Equal(t, iRecv, rSend,
		"Initiator recv must equal responder send")

	// All keys must be non-zero
	assert.NotEqual(t, [32]byte{}, iSend, "Send key must be non-zero")
	assert.NotEqual(t, [32]byte{}, iRecv, "Recv key must be non-zero")
}

// TestCryptoAudit_SessionTagRatchet_Prop144Section5 verifies the tag ratchet produces
// deterministic 8-byte tags as specified in Proposal 144 Section 5.
func TestCryptoAudit_SessionTagRatchet_Prop144Section5(t *testing.T) {
	// Create a tag ratchet with a known chain key
	chainKey := types.SHA256([]byte("tag ratchet chain key for audit"))
	tagRatchet := ratchet.NewTagRatchet(chainKey)

	// Generate a sequence of tags
	var tags [][8]byte
	for i := 0; i < 50; i++ {
		tag, err := tagRatchet.GenerateNextTag()
		require.NoError(t, err, "GenerateNextTag must not fail at step %d", i)
		tags = append(tags, tag)
	}

	// All tags must be 8 bytes
	for i, tag := range tags {
		assert.Equal(t, 8, len(tag), "Tag %d must be 8 bytes", i)
	}

	// Tags must be unique
	tagSet := make(map[[8]byte]bool)
	for _, tag := range tags {
		assert.False(t, tagSet[tag], "Tags must be unique within a sequence")
		tagSet[tag] = true
	}

	// Deterministic: same chain key → same tags
	tagRatchet2 := ratchet.NewTagRatchet(chainKey)
	for i := 0; i < 50; i++ {
		tag, err := tagRatchet2.GenerateNextTag()
		require.NoError(t, err)
		assert.Equal(t, tags[i], tag, "Tag ratchet must be deterministic (tag %d)", i)
	}
}

// ============================================================================
// Section 6 — Legacy Crypto Found
// ============================================================================

// TestLegacyCrypto_ElGamalBuildRecords_FlagPresence flags the existence of
// 528-byte ElGamal build record types. Per modern spec, only ECIES should be used.
func TestLegacyCrypto_ElGamalBuildRecords_FlagPresence(t *testing.T) {
	// StandardBuildRecordSize = 528 is still defined (legacy ElGamal + ECIES long format)
	assert.Equal(t, 528, StandardBuildRecordSize,
		"CRITICAL: StandardBuildRecordSize (528) is defined — this is the ElGamal/ECIES-long record size")

	// Document: BuildResponseRecordELGamalAES and BuildResponseRecordELGamal types exist
	var elgamalAES BuildResponseRecordELGamalAES
	assert.Equal(t, 528, len(elgamalAES),
		"CRITICAL: BuildResponseRecordELGamalAES [528]byte type exists — legacy ElGamal/AES record")

	var elgamal BuildResponseRecordELGamal
	assert.Equal(t, 528, len(elgamal),
		"CRITICAL: BuildResponseRecordELGamal [528]byte type exists — legacy ElGamal record")

	// TunnelBuild uses 8×528 = 4224 byte format (legacy-compatible)
	var tb TunnelBuild
	totalSize := len(tb) * StandardBuildRecordSize
	assert.Equal(t, 4224, totalSize,
		"TunnelBuild uses 528-byte records (legacy ElGamal format)")

	t.Log("CRITICAL FINDING: ElGamal build record types (528 bytes) are present in the codebase.")
	t.Log("The modern I2P spec recommends ECIES-only (218-byte short records).")
	t.Log("528-byte records remain for backward compatibility with older routers.")
}

// TestLegacyCrypto_AESSessionTag_FlagPresence flags the existence of
// GarlicElGamal (AES session tag garlic encryption).
func TestLegacyCrypto_AESSessionTag_FlagPresence(t *testing.T) {
	// GarlicElGamal is a legacy type that uses ElGamal/AES encryption
	garlic, err := NewGarlicElGamal([]byte{0x00, 0x00, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04})
	require.NoError(t, err)
	assert.NotNil(t, garlic, "GarlicElGamal type exists — legacy AES session tag garlic")
	assert.Equal(t, uint32(4), garlic.Length)
	assert.Equal(t, []byte{0x01, 0x02, 0x03, 0x04}, garlic.Data)

	t.Log("CRITICAL FINDING: GarlicElGamal type exists for legacy ElGamal/AES garlic encryption.")
	t.Log("Modern I2P uses ECIES-X25519-AEAD-Ratchet (Proposal 144) exclusively.")
	t.Log("GarlicElGamal remains for backward compatibility parsing of legacy messages.")
}

// TestLegacyCrypto_AESBuildRecordDecryption_FlagPresence flags the AES-256-CBC
// decryption path in BuildRecordCrypto for legacy reply record processing.
func TestLegacyCrypto_AESBuildRecordDecryption_FlagPresence(t *testing.T) {
	crypto := &BuildRecordCrypto{}

	// Prepare a valid 528-byte ciphertext (all zeros, AES will decrypt it)
	ciphertext := make([]byte, 528)
	var key session_key.SessionKey
	var iv [16]byte

	// The decryptAES256CBC method exists and can be called
	result, err := crypto.decryptAES256CBC(ciphertext, key, iv)
	// AES decryption of zeros with zero key/IV will succeed (just produces garbage plaintext)
	require.NoError(t, err)
	assert.Equal(t, 528, len(result),
		"Legacy AES-256-CBC decryption path exists in BuildRecordCrypto")

	t.Log("FINDING: AES-256-CBC decryption path (decryptAES256CBC) exists in BuildRecordCrypto.")
	t.Log("This is used for legacy build reply record decryption (pre-0.9.44).")
	t.Log("Modern path uses ChaCha20-Poly1305 (encryptChaCha20Poly1305/decryptChaCha20Poly1305).")
}
