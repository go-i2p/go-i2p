package i2np

import (
	"crypto/sha256"
	"encoding/binary"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDeserializeGarlicClove_MessageLengthParsing tests that I2NP message length
// is correctly read from the header instead of using a hardcoded placeholder.
func TestDeserializeGarlicClove_MessageLengthParsing(t *testing.T) {
	tests := []struct {
		name           string
		messageSize    int
		expectError    bool
		errorSubstring string
	}{
		{
			name:        "small message (10 bytes)",
			messageSize: 10,
			expectError: false,
		},
		{
			name:        "medium message (100 bytes)",
			messageSize: 100,
			expectError: false,
		},
		{
			name:        "large message (1000 bytes)",
			messageSize: 1000,
			expectError: false,
		},
		{
			name:        "maximum reasonable message (8192 bytes)",
			messageSize: 8192,
			expectError: false,
		},
		{
			name:        "zero-length message",
			messageSize: 0,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build a valid garlic clove with LOCAL delivery and I2NP message
			cloveData := buildTestGarlicCloveData(tt.messageSize)

			// Deserialize the clove
			clove, bytesRead, err := deserializeGarlicClove(cloveData, 0)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorSubstring != "" {
					assert.Contains(t, err.Error(), tt.errorSubstring)
				}
			} else {
				require.NoError(t, err, "Failed to deserialize clove with message size %d", tt.messageSize)
				require.NotNil(t, clove)

				// Verify the correct number of bytes were consumed
				// Expected: delivery instructions (1 byte for LOCAL flag) +
				//           I2NP header (16 bytes) +
				//           I2NP data (messageSize bytes) +
				//           clove trailer (4 + 8 + 3 = 15 bytes)
				expectedBytes := 1 + 16 + tt.messageSize + 15
				assert.Equal(t, expectedBytes, bytesRead,
					"Expected to consume %d bytes, but consumed %d", expectedBytes, bytesRead)

				// Verify clove was parsed correctly
				assert.NotNil(t, clove.DeliveryInstructions)
				assert.Equal(t, byte(0x00), clove.DeliveryInstructions.Flag, "Expected LOCAL delivery flag")
			}
		})
	}
}

// TestDeserializeGarlicClove_InsufficientDataForHeader tests error handling
// when there's not enough data for the I2NP message header.
func TestDeserializeGarlicClove_InsufficientDataForHeader(t *testing.T) {
	// Create clove data with delivery instructions but incomplete I2NP header
	cloveData := []byte{0x00} // LOCAL delivery flag only

	// Add partial I2NP header (less than 16 bytes required)
	partialHeader := make([]byte, 10)
	cloveData = append(cloveData, partialHeader...)

	clove, _, err := deserializeGarlicClove(cloveData, 0)

	require.Error(t, err)
	assert.Nil(t, clove)
	assert.Contains(t, err.Error(), "insufficient data for I2NP message header")
}

// TestDeserializeGarlicClove_InsufficientDataForMessage tests error handling
// when the I2NP header specifies a size larger than available data.
func TestDeserializeGarlicClove_InsufficientDataForMessage(t *testing.T) {
	// Build delivery instructions (LOCAL)
	cloveData := []byte{0x00}

	// Build I2NP header claiming 500 bytes of data
	i2npHeader := buildI2NPHeader(500, 0x00)
	cloveData = append(cloveData, i2npHeader...)

	// But only provide 100 bytes of actual data
	messageData := make([]byte, 100)
	cloveData = append(cloveData, messageData...)

	clove, _, err := deserializeGarlicClove(cloveData, 0)

	require.Error(t, err)
	assert.Nil(t, clove)
	assert.Contains(t, err.Error(), "insufficient data for I2NP message")
}

// TestDeserializeGarlicClove_ValidCloveStructure tests a complete valid clove
// with all components properly sized.
func TestDeserializeGarlicClove_ValidCloveStructure(t *testing.T) {
	messageSize := 256
	cloveData := buildTestGarlicCloveData(messageSize)

	clove, bytesRead, err := deserializeGarlicClove(cloveData, 0)

	require.NoError(t, err)
	require.NotNil(t, clove)

	// Verify all clove components
	assert.NotNil(t, clove.DeliveryInstructions)
	assert.Equal(t, byte(0x00), clove.DeliveryInstructions.Flag)

	// Verify clove metadata
	assert.Equal(t, 42, clove.CloveID, "Expected clove ID 42")

	// Verify expiration is reasonable
	assert.True(t, clove.Expiration.After(time.Now()), "Clove expiration should be in future")

	// Verify bytes consumed
	expectedBytes := 1 + 16 + messageSize + 15
	assert.Equal(t, expectedBytes, bytesRead)
}

// TestDeserializeGarlicClove_ExactBufferSize tests that deserialization works
// when buffer size exactly matches requirements (no extra bytes).
func TestDeserializeGarlicClove_ExactBufferSize(t *testing.T) {
	messageSize := 128
	cloveData := buildTestGarlicCloveData(messageSize)

	// Verify data is exactly the size needed
	expectedSize := 1 + 16 + messageSize + 15
	require.Equal(t, expectedSize, len(cloveData), "Test data should be exact size")

	clove, bytesRead, err := deserializeGarlicClove(cloveData, 0)

	require.NoError(t, err)
	require.NotNil(t, clove)
	assert.Equal(t, expectedSize, bytesRead)
}

// TestDeserializeGarlicClove_ExtraDataIgnored tests that extra bytes after
// a valid clove are ignored (not consumed).
func TestDeserializeGarlicClove_ExtraDataIgnored(t *testing.T) {
	messageSize := 64
	cloveData := buildTestGarlicCloveData(messageSize)

	// Add extra bytes that should not be consumed
	extraData := []byte{0xFF, 0xFF, 0xFF, 0xFF}
	cloveData = append(cloveData, extraData...)

	clove, bytesRead, err := deserializeGarlicClove(cloveData, 0)

	require.NoError(t, err)
	require.NotNil(t, clove)

	// Verify only the clove bytes were consumed, not the extra data
	expectedBytes := 1 + 16 + messageSize + 15
	assert.Equal(t, expectedBytes, bytesRead)
	assert.Less(t, bytesRead, len(cloveData), "Should not consume extra data")
}

// TestDeserializeGarlicClove_DifferentMessageSizes tests various message sizes
// to ensure the size parsing works correctly for edge cases.
func TestDeserializeGarlicClove_DifferentMessageSizes(t *testing.T) {
	messageSizes := []int{
		1,     // Minimum
		127,   // Just under 128
		128,   // Power of 2
		255,   // One byte max
		256,   // Two bytes required
		512,   // Common size
		1024,  // 1KB
		4096,  // 4KB
		16383, // Max for 14 bits
	}

	for _, size := range messageSizes {
		t.Run(string(rune(size)), func(t *testing.T) {
			cloveData := buildTestGarlicCloveData(size)

			clove, bytesRead, err := deserializeGarlicClove(cloveData, 0)

			require.NoError(t, err, "Failed with message size %d", size)
			require.NotNil(t, clove)

			expectedBytes := 1 + 16 + size + 15
			assert.Equal(t, expectedBytes, bytesRead,
				"Incorrect byte count for message size %d", size)
		})
	}
}

// buildTestGarlicCloveData creates a properly formatted garlic clove byte sequence
// with LOCAL delivery and an I2NP message of the specified size.
func buildTestGarlicCloveData(messageSize int) []byte {
	var buf []byte

	// 1. Delivery Instructions (LOCAL = 0x00, no additional data)
	buf = append(buf, 0x00)

	// I2NP message data (filled with test pattern)
	messageData := make([]byte, messageSize)
	for i := range messageData {
		messageData[i] = byte(i % 256)
	}

	// Compute correct checksum: first byte of SHA-256 over message data
	hash := sha256.Sum256(messageData)
	checksum := hash[0]

	// 2. I2NP Message Header (16 bytes) + Data
	i2npHeader := buildI2NPHeader(messageSize, checksum)
	buf = append(buf, i2npHeader...)
	buf = append(buf, messageData...)

	// 3. Clove Trailer
	// Clove ID (4 bytes)
	cloveID := make([]byte, 4)
	binary.BigEndian.PutUint32(cloveID, 42)
	buf = append(buf, cloveID...)

	// Expiration (8 bytes) - 1 hour from now in milliseconds
	expiration := make([]byte, 8)
	expirationMs := time.Now().Add(1 * time.Hour).UnixMilli()
	binary.BigEndian.PutUint64(expiration, uint64(expirationMs))
	buf = append(buf, expiration...)

	// Certificate (3 bytes - null certificate)
	certificate := []byte{0x00, 0x00, 0x00}
	buf = append(buf, certificate...)

	return buf
}

// buildI2NPHeader creates a valid I2NP NTCP header (16 bytes) with the specified message size.
func buildI2NPHeader(messageSize int, checksum byte) []byte {
	header := make([]byte, 16)

	// Type (1 byte) - use Data message type (20)
	header[0] = 20

	// Message ID (4 bytes) - random value
	binary.BigEndian.PutUint32(header[1:5], 12345)

	// Expiration (8 bytes) - 10 seconds from now in milliseconds
	expirationMs := time.Now().Add(10 * time.Second).UnixMilli()
	binary.BigEndian.PutUint64(header[5:13], uint64(expirationMs))

	// Size (2 bytes) - the actual message data size
	binary.BigEndian.PutUint16(header[13:15], uint16(messageSize))

	// Checksum (1 byte) - first byte of SHA-256 of message data
	header[15] = checksum

	return header
}

// BenchmarkDeserializeGarlicClove_SmallMessage benchmarks small message parsing
func BenchmarkDeserializeGarlicClove_SmallMessage(b *testing.B) {
	cloveData := buildTestGarlicCloveData(64)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = deserializeGarlicClove(cloveData, 0)
	}
}

// BenchmarkDeserializeGarlicClove_LargeMessage benchmarks large message parsing
func BenchmarkDeserializeGarlicClove_LargeMessage(b *testing.B) {
	cloveData := buildTestGarlicCloveData(8192)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = deserializeGarlicClove(cloveData, 0)
	}
}
