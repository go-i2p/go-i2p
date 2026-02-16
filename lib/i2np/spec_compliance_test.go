package i2np

// spec_compliance_test.go — I2P specification compliance tests for I2NP headers.
//
// These tests verify that the lib/i2np package correctly implements the I2NP
// message header format as defined in i2np.rst. Each test group maps to a
// specific audit checklist item in Section 6 of AUDIT.md.
//
// Spec reference: https://geti2p.net/spec/i2np (version 0.9.66+)

import (
	"crypto/sha256"
	"encoding/binary"
	"testing"
	"time"

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
