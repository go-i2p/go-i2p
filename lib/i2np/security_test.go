package i2np

import (
	"bytes"
	"crypto/sha256"
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Security Audit Tests for lib/i2np package
// These tests verify bounds checking, input validation, and error handling
// for all I2NP message types.

// =============================================================================
// Message Parsing Bounds Checking Tests
// =============================================================================

// TestBaseI2NPMessage_BoundsChecking verifies bounds checking in BaseI2NPMessage
func TestBaseI2NPMessage_BoundsChecking(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		expectError bool
		errContains string
	}{
		{
			name:        "empty data",
			data:        []byte{},
			expectError: true,
			errContains: "too short",
		},
		{
			name:        "header only - no data",
			data:        make([]byte, 15), // Less than 16 byte header
			expectError: true,
			errContains: "too short",
		},
		{
			name:        "header with invalid size field",
			data:        createInvalidI2NPMessage(1000, 10), // Claims 1000 bytes, has 10
			expectError: true,
			errContains: "truncated",
		},
		{
			name:        "header with checksum mismatch",
			data:        createI2NPMessageWithBadChecksum(),
			expectError: true,
			errContains: "checksum",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := &BaseI2NPMessage{}
			err := msg.UnmarshalBinary(tt.data)
			if tt.expectError {
				require.Error(t, err, "expected error for test case: %s", tt.name)
				assert.Contains(t, err.Error(), tt.errContains)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestDataMessage_BoundsChecking verifies bounds checking in DataMessage
func TestDataMessage_BoundsChecking(t *testing.T) {
	tests := []struct {
		name        string
		setupMsg    func() []byte
		expectError bool
		errContains string
	}{
		{
			name: "payload length exceeds available data",
			setupMsg: func() []byte {
				// Create a valid base message with truncated payload
				payload := make([]byte, 4)
				// Set length field to 1000 but only provide 0 actual bytes
				payload[0], payload[1], payload[2], payload[3] = 0, 0, 3, 232 // 1000 in big-endian
				return createValidI2NPMessage(I2NP_MESSAGE_TYPE_DATA, payload)
			},
			expectError: true,
			errContains: "truncated",
		},
		{
			name: "payload too short for length field",
			setupMsg: func() []byte {
				// Create valid I2NP wrapper with only 2 bytes of payload (need 4 for length)
				return createValidI2NPMessage(I2NP_MESSAGE_TYPE_DATA, []byte{0, 0})
			},
			expectError: true,
			errContains: "too short",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := &DataMessage{BaseI2NPMessage: &BaseI2NPMessage{}}
			err := msg.UnmarshalBinary(tt.setupMsg())
			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestDeliveryStatusMessage_BoundsChecking verifies bounds checking in DeliveryStatusMessage
func TestDeliveryStatusMessage_BoundsChecking(t *testing.T) {
	tests := []struct {
		name        string
		payloadSize int
		expectError bool
	}{
		{"payload too short - 0 bytes", 0, true},
		{"payload too short - 4 bytes", 4, true},
		{"payload too short - 11 bytes", 11, true},
		{"payload exactly 12 bytes", 12, false},
		{"payload with extra bytes", 20, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := make([]byte, tt.payloadSize)
			data := createValidI2NPMessage(I2NP_MESSAGE_TYPE_DELIVERY_STATUS, payload)

			msg := &DeliveryStatusMessage{BaseI2NPMessage: &BaseI2NPMessage{}}
			err := msg.UnmarshalBinary(data)
			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestTunnelDataMessage_BoundsChecking verifies exact size requirement (1028 bytes: 4 TunnelID + 1024 Data)
func TestTunnelDataMessage_BoundsChecking(t *testing.T) {
	tests := []struct {
		name        string
		payloadSize int
		expectError bool
	}{
		{"payload too short - 0 bytes", 0, true},
		{"payload too short - 512 bytes", 512, true},
		{"payload too short - 1024 bytes (missing TunnelID)", 1024, true},
		{"payload too short - 1027 bytes", 1027, true},
		{"payload exactly 1028 bytes", 1028, false},
		{"payload too long - 1029 bytes", 1029, true},
		{"payload too long - 2048 bytes", 2048, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := make([]byte, tt.payloadSize)
			data := createValidI2NPMessage(I2NP_MESSAGE_TYPE_TUNNEL_DATA, payload)

			msg := &TunnelDataMessage{BaseI2NPMessage: &BaseI2NPMessage{}}
			err := msg.UnmarshalBinary(data)
			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "wrong size")
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestTunnelBuildMessage_BoundsChecking verifies TunnelBuild size requirements
func TestTunnelBuildMessage_BoundsChecking(t *testing.T) {
	tests := []struct {
		name        string
		payloadSize int
		expectError bool
	}{
		{"payload too short - 0 bytes", 0, true},
		{"payload too short - 528 bytes (1 record)", 528, true},
		{"payload too short - 4223 bytes (8 records - 1 byte)", 8*528 - 1, true},
		{"payload exactly 4224 bytes (8 records)", 8 * 528, false},
		{"payload too long - 4225 bytes", 8*528 + 1, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := make([]byte, tt.payloadSize)
			data := createValidI2NPMessage(I2NP_MESSAGE_TYPE_TUNNEL_BUILD, payload)

			msg := &TunnelBuildMessage{BaseI2NPMessage: &BaseI2NPMessage{}}
			err := msg.UnmarshalBinary(data)
			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// =============================================================================
// DatabaseLookup Bounds Checking Tests
// =============================================================================

func TestDatabaseLookup_BoundsChecking(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		expectError bool
	}{
		{
			name:        "empty data",
			data:        []byte{},
			expectError: true,
		},
		{
			name:        "key only - missing from field",
			data:        make([]byte, 31), // Less than 32 bytes for key
			expectError: true,
		},
		{
			name:        "key + from - missing flags",
			data:        make([]byte, 64), // Key(32) + From(32), no flags
			expectError: true,
		},
		{
			name:        "with tunnel flag but missing tunnel ID",
			data:        createDatabaseLookupWithTunnelFlag(false), // Has tunnel flag but no tunnel ID
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ReadDatabaseLookup(tt.data)
			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestDatabaseLookup_ExcludedPeersLimit verifies the 512 peer limit
func TestDatabaseLookup_ExcludedPeersLimit(t *testing.T) {
	tests := []struct {
		name        string
		peerCount   int
		expectError bool
	}{
		{"0 peers - valid", 0, false},
		{"256 peers - valid", 256, false},
		{"512 peers - valid (max)", 512, false},
		{"513 peers - invalid (exceeds max)", 513, true},
		{"1000 peers - invalid", 1000, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := createDatabaseLookupWithPeerCount(tt.peerCount)
			_, err := ReadDatabaseLookup(data)
			if tt.expectError {
				require.Error(t, err)
				assert.Equal(t, ERR_DATABASE_LOOKUP_INVALID_SIZE, err)
			} else {
				// May still fail due to insufficient data for actual peers,
				// but should not fail on size validation
				if err != nil {
					assert.NotEqual(t, ERR_DATABASE_LOOKUP_INVALID_SIZE, err)
				}
			}
		})
	}
}

// =============================================================================
// DatabaseStore Bounds Checking Tests
// =============================================================================

func TestDatabaseStore_BoundsChecking(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		expectError bool
	}{
		{
			name:        "empty data",
			data:        []byte{},
			expectError: true,
		},
		{
			name:        "key only - truncated",
			data:        make([]byte, 31), // Less than minimum 37 bytes
			expectError: true,
		},
		{
			name:        "minimum valid size (no reply)",
			data:        createMinimalDatabaseStore(false),
			expectError: false,
		},
		{
			name:        "with reply token but missing gateway",
			data:        createDatabaseStoreWithTruncatedReply(),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &DatabaseStore{}
			err := store.UnmarshalBinary(tt.data)
			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestDatabaseStore_SizeLimits verifies size limits for different store types
func TestDatabaseStore_SizeLimits(t *testing.T) {
	tests := []struct {
		name        string
		storeType   byte
		dataSize    int
		expectError bool
	}{
		{"RouterInfo - valid small", DATABASE_STORE_TYPE_ROUTER_INFO, 1000, false},
		{"RouterInfo - valid max", DATABASE_STORE_TYPE_ROUTER_INFO, MaxRouterInfoSize, false},
		{"RouterInfo - exceeds max", DATABASE_STORE_TYPE_ROUTER_INFO, MaxRouterInfoSize + 1, true},
		{"LeaseSet - valid small", DATABASE_STORE_TYPE_LEASESET, 500, false},
		{"LeaseSet - valid max", DATABASE_STORE_TYPE_LEASESET, MaxLeaseSetSize, false},
		{"LeaseSet - exceeds max", DATABASE_STORE_TYPE_LEASESET, MaxLeaseSetSize + 1, true},
		{"LeaseSet2 - valid", DATABASE_STORE_TYPE_LEASESET2, 1000, false},
		{"LeaseSet2 - exceeds max", DATABASE_STORE_TYPE_LEASESET2, MaxLeaseSetSize + 1, true},
		{"Unknown type - uses conservative limit", 15, MaxLeaseSetSize, false},
		{"Unknown type - exceeds conservative limit", 15, MaxLeaseSetSize + 1, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDatabaseStoreSize(tt.storeType, tt.dataSize)
			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// =============================================================================
// BuildRequestRecord Bounds Checking Tests
// =============================================================================

func TestBuildRequestRecord_BoundsChecking(t *testing.T) {
	tests := []struct {
		name        string
		dataSize    int
		expectError bool
	}{
		{"empty data", 0, true},
		{"partial - 3 bytes", 3, true},
		{"partial - 35 bytes (missing OurIdent)", 35, true},
		{"partial - 71 bytes (missing NextIdent)", 71, true},
		{"partial - 183 bytes (missing ReplyIV)", 183, true},
		{"partial - 221 bytes (missing Padding)", 221, true},
		{"complete - 222 bytes", 222, false},
		{"extra data - 500 bytes", 500, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := make([]byte, tt.dataSize)
			_, err := ReadBuildRequestRecord(data)
			if tt.expectError {
				require.Error(t, err)
				assert.Equal(t, ERR_BUILD_REQUEST_RECORD_NOT_ENOUGH_DATA, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// =============================================================================
// BuildResponseRecord Bounds Checking Tests
// =============================================================================

func TestBuildResponseRecord_BoundsChecking(t *testing.T) {
	tests := []struct {
		name        string
		dataSize    int
		expectError bool
	}{
		{"empty data", 0, true},
		{"partial - 31 bytes (missing Hash)", 31, true},
		{"partial - 526 bytes (missing RandomData)", 526, true},
		{"partial - 527 bytes (missing Reply)", 527, true},
		{"complete - 528 bytes", 528, false},
		{"extra data - 600 bytes", 600, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := make([]byte, tt.dataSize)
			_, err := ReadBuildResponseRecord(data)
			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// =============================================================================
// GarlicElGamal Bounds Checking Tests
// =============================================================================

func TestGarlicElGamal_BoundsChecking(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		expectError bool
		errContains string
	}{
		{
			name:        "empty data",
			data:        []byte{},
			expectError: true,
			errContains: "at least 4 bytes",
		},
		{
			name:        "only length field - 3 bytes",
			data:        []byte{0, 0, 0},
			expectError: true,
			errContains: "at least 4 bytes",
		},
		{
			name:        "length says 100 but only 10 available",
			data:        append([]byte{0, 0, 0, 100}, make([]byte, 10)...),
			expectError: true,
			errContains: "insufficient data",
		},
		{
			name:        "length matches available data",
			data:        append([]byte{0, 0, 0, 10}, make([]byte, 10)...),
			expectError: false,
		},
		{
			name:        "zero length",
			data:        []byte{0, 0, 0, 0},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewGarlicElGamal(tt.data)
			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// =============================================================================
// I2NP Header Parsing Tests (utils.go)
// =============================================================================

func TestI2NPHeaderParsing_BoundsChecking(t *testing.T) {
	t.Run("ReadI2NPType", func(t *testing.T) {
		_, err := ReadI2NPType([]byte{})
		assert.Equal(t, ERR_I2NP_NOT_ENOUGH_DATA, err)

		mtype, err := ReadI2NPType([]byte{0x01})
		assert.NoError(t, err)
		assert.Equal(t, 1, mtype)
	})

	t.Run("ReadI2NPNTCPMessageID", func(t *testing.T) {
		_, err := ReadI2NPNTCPMessageID([]byte{0, 0, 0, 0}) // 4 bytes, need 5
		assert.Equal(t, ERR_I2NP_NOT_ENOUGH_DATA, err)

		mid, err := ReadI2NPNTCPMessageID([]byte{0, 0, 0, 0, 1})
		assert.NoError(t, err)
		assert.Equal(t, 1, mid)
	})

	t.Run("ReadI2NPNTCPMessageExpiration", func(t *testing.T) {
		_, err := ReadI2NPNTCPMessageExpiration(make([]byte, 12)) // Need 13
		assert.Equal(t, ERR_I2NP_NOT_ENOUGH_DATA, err)
	})

	t.Run("ReadI2NPNTCPMessageSize", func(t *testing.T) {
		_, err := ReadI2NPNTCPMessageSize(make([]byte, 14)) // Need 15
		assert.Equal(t, ERR_I2NP_NOT_ENOUGH_DATA, err)
	})

	t.Run("ReadI2NPNTCPMessageChecksum", func(t *testing.T) {
		_, err := ReadI2NPNTCPMessageChecksum(make([]byte, 15)) // Need 16
		assert.Equal(t, ERR_I2NP_NOT_ENOUGH_DATA, err)
	})

	t.Run("ReadI2NPNTCPData", func(t *testing.T) {
		_, err := ReadI2NPNTCPData(make([]byte, 20), 10) // Need 16+10=26
		assert.Equal(t, ERR_I2NP_NOT_ENOUGH_DATA, err)

		data, err := ReadI2NPNTCPData(make([]byte, 26), 10)
		assert.NoError(t, err)
		assert.Len(t, data, 10)
	})

	t.Run("ReadI2NPSecondGenTransportHeader", func(t *testing.T) {
		_, err := ReadI2NPSecondGenTransportHeader(make([]byte, 8)) // Need 9
		assert.Equal(t, ERR_I2NP_NOT_ENOUGH_DATA, err)
	})

	t.Run("ReadI2NPSSUHeader", func(t *testing.T) {
		_, err := ReadI2NPSSUHeader(make([]byte, 4)) // Need 5
		assert.Error(t, err)
	})
}

// =============================================================================
// Checksum Verification Tests
// =============================================================================

func TestI2NPMessage_ChecksumVerification(t *testing.T) {
	t.Run("valid checksum passes", func(t *testing.T) {
		// Create a valid message
		msg := NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_DATA)
		msg.SetData([]byte("test payload"))

		data, err := msg.MarshalBinary()
		require.NoError(t, err)

		// Unmarshal should succeed
		msg2 := &BaseI2NPMessage{}
		err = msg2.UnmarshalBinary(data)
		require.NoError(t, err)
	})

	t.Run("corrupted data fails checksum", func(t *testing.T) {
		// Create a valid message
		msg := NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_DATA)
		msg.SetData([]byte("test payload"))

		data, err := msg.MarshalBinary()
		require.NoError(t, err)

		// Corrupt the payload data
		if len(data) > 17 {
			data[17] ^= 0xFF // Flip bits in payload
		}

		// Unmarshal should fail with checksum error
		msg2 := &BaseI2NPMessage{}
		err = msg2.UnmarshalBinary(data)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "checksum")
	})
}

// =============================================================================
// Round-Trip Serialization Tests
// =============================================================================

func TestI2NPMessage_RoundTrip(t *testing.T) {
	t.Run("BaseI2NPMessage", func(t *testing.T) {
		original := NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_DATA)
		original.SetMessageID(12345)
		original.SetExpiration(time.Now().Add(time.Hour).Truncate(time.Millisecond))
		original.SetData([]byte("round trip test data"))

		data, err := original.MarshalBinary()
		require.NoError(t, err)

		restored := &BaseI2NPMessage{}
		err = restored.UnmarshalBinary(data)
		require.NoError(t, err)

		assert.Equal(t, original.Type(), restored.Type())
		assert.Equal(t, original.MessageID(), restored.MessageID())
		assert.Equal(t, original.GetData(), restored.GetData())
	})

	t.Run("DataMessage", func(t *testing.T) {
		payload := []byte("test data message payload")
		original := NewDataMessage(payload)

		data, err := original.MarshalBinary()
		require.NoError(t, err)

		restored := &DataMessage{BaseI2NPMessage: &BaseI2NPMessage{}}
		err = restored.UnmarshalBinary(data)
		require.NoError(t, err)

		assert.Equal(t, payload, restored.GetPayload())
	})

	t.Run("DatabaseStore", func(t *testing.T) {
		key := common.Hash{}
		copy(key[:], bytes.Repeat([]byte{0xAB}, 32))
		storeData := []byte("router info data")

		original := NewDatabaseStore(key, storeData, DATABASE_STORE_TYPE_ROUTER_INFO)

		// MarshalBinary now produces header + payload; verify it includes the header
		fullData, err := original.MarshalBinary()
		require.NoError(t, err)
		assert.True(t, len(fullData) >= 16, "MarshalBinary should include 16-byte I2NP header")

		// UnmarshalBinary expects payload only (header is stripped by I2NP framing layer)
		// Use MarshalPayload for the round-trip test
		payloadData, err := original.MarshalPayload()
		require.NoError(t, err)

		restored := &DatabaseStore{BaseI2NPMessage: NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_DATABASE_STORE)}
		err = restored.UnmarshalBinary(payloadData)
		require.NoError(t, err)

		assert.Equal(t, original.Key, restored.Key)
		assert.Equal(t, original.StoreType, restored.StoreType)
		assert.Equal(t, original.Data, restored.Data)
	})
}

// =============================================================================
// Error Message Information Leakage Tests
// =============================================================================

func TestErrorMessages_NoSensitiveDataLeakage(t *testing.T) {
	// Verify error messages don't contain raw data that could be exploited
	testCases := []struct {
		name   string
		errGen func() error
	}{
		{
			name: "BaseI2NPMessage short data",
			errGen: func() error {
				msg := &BaseI2NPMessage{}
				return msg.UnmarshalBinary([]byte{0x01, 0x02, 0x03})
			},
		},
		{
			name: "DatabaseLookup not enough data",
			errGen: func() error {
				_, err := ReadDatabaseLookup([]byte{0x01, 0x02, 0x03})
				return err
			},
		},
		{
			name: "BuildRequestRecord not enough data",
			errGen: func() error {
				_, err := ReadBuildRequestRecord([]byte{0x01, 0x02, 0x03})
				return err
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.errGen()
			require.Error(t, err)

			errStr := err.Error()
			// Error should not contain raw hex dumps of data
			assert.NotContains(t, errStr, "0x01020304")
			// Error should describe the problem generically
			assert.True(t,
				contains(errStr, "not enough") ||
					contains(errStr, "too short") ||
					contains(errStr, "truncated"),
				"error should describe insufficient data: %s", errStr)
		})
	}
}

// =============================================================================
// Helper Functions
// =============================================================================

// createValidI2NPMessage creates a valid I2NP message with the given type and payload
func createValidI2NPMessage(msgType int, payload []byte) []byte {
	// Header: type(1) + msgID(4) + expiration(8) + size(2) + checksum(1) = 16 bytes
	header := make([]byte, 16)
	header[0] = byte(msgType)

	// Message ID (4 bytes)
	header[1], header[2], header[3], header[4] = 0, 0, 0, 1

	// Expiration (8 bytes) - set to current time + 1 hour
	exp := time.Now().Add(time.Hour)
	expMs := exp.UnixNano() / 1e6
	for i := 0; i < 8; i++ {
		header[5+i] = byte(expMs >> (56 - i*8))
	}

	// Size (2 bytes)
	size := len(payload)
	header[13] = byte(size >> 8)
	header[14] = byte(size)

	// Checksum (1 byte)
	hash := sha256.Sum256(payload)
	header[15] = hash[0]

	return append(header, payload...)
}

// createInvalidI2NPMessage creates an I2NP message with mismatched size
func createInvalidI2NPMessage(claimedSize, actualSize int) []byte {
	header := make([]byte, 16)
	header[0] = byte(I2NP_MESSAGE_TYPE_DATA)

	// Size (2 bytes) - claims more than available
	header[13] = byte(claimedSize >> 8)
	header[14] = byte(claimedSize)

	// Actual payload
	payload := make([]byte, actualSize)
	hash := sha256.Sum256(payload)
	header[15] = hash[0]

	return append(header, payload...)
}

// createI2NPMessageWithBadChecksum creates a message with invalid checksum
func createI2NPMessageWithBadChecksum() []byte {
	payload := []byte("test data")
	msg := createValidI2NPMessage(I2NP_MESSAGE_TYPE_DATA, payload)

	// Corrupt the checksum
	msg[15] ^= 0xFF

	return msg
}

// createDatabaseLookupWithTunnelFlag creates a DatabaseLookup with tunnel flag set
func createDatabaseLookupWithTunnelFlag(includeTunnelID bool) []byte {
	// Key(32) + From(32) + Flags(1) + optional TunnelID(4) + Size(2)
	size := 32 + 32 + 1 + 2
	if includeTunnelID {
		size += 4
	}
	data := make([]byte, size)

	// Set tunnel flag (bit 0)
	data[64] = 0x01

	return data
}

// createDatabaseLookupWithPeerCount creates a DatabaseLookup with specified peer count
func createDatabaseLookupWithPeerCount(count int) []byte {
	// Key(32) + From(32) + Flags(1) + Size(2)
	data := make([]byte, 67)

	// Size field (2 bytes, big-endian)
	data[65] = byte(count >> 8)
	data[66] = byte(count)

	return data
}

// createMinimalDatabaseStore creates a minimal valid DatabaseStore
func createMinimalDatabaseStore(withReply bool) []byte {
	if withReply {
		// Key(32) + Type(1) + ReplyToken(4) + TunnelID(4) + Gateway(32) + Data(1)
		data := make([]byte, 74)
		// Set non-zero reply token
		data[33], data[34], data[35], data[36] = 0, 0, 0, 1
		return data
	}
	// Key(32) + Type(1) + ReplyToken(4) + Data(1) = 38 bytes minimum
	return make([]byte, 38)
}

// createDatabaseStoreWithTruncatedReply creates a DatabaseStore with reply token but missing gateway
func createDatabaseStoreWithTruncatedReply() []byte {
	// Key(32) + Type(1) + ReplyToken(4) = 37 bytes, missing TunnelID and Gateway
	data := make([]byte, 37)
	// Set non-zero reply token
	data[33], data[34], data[35], data[36] = 0, 0, 0, 1
	return data
}

// contains checks if str contains substr (case-sensitive)
func contains(str, substr string) bool {
	return bytes.Contains([]byte(str), []byte(substr))
}
