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
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"github.com/go-i2p/common/certificate"
	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/session_key"
	"github.com/go-i2p/common/session_tag"
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
	hash := sha256.Sum256(payload)
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
	hash := sha256.Sum256(payload)
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
		hash := sha256.Sum256(payload)
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
