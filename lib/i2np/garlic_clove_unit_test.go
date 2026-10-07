package i2np

import (
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
				// Spec-compliant: delivery instructions (1 byte for LOCAL flag) +
				//                 9-byte short I2NP header +
				//                 I2NP data (messageSize bytes)
				//                 (no legacy 15-byte clove trailer)
				expectedBytes := 1 + 9 + tt.messageSize
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

	// Add partial short I2NP header (only 4 bytes after flag = 5 total, less than 9 needed)
	partialHeader := make([]byte, 4)
	cloveData = append(cloveData, partialHeader...)

	assertDeserializeCloveError(t, cloveData, "insufficient data for short I2NP header")
}

// TestDeserializeGarlicClove_InsufficientDataForMessage tests error handling
// when the I2NP header specifies a size larger than available data.
func TestDeserializeGarlicClove_InsufficientDataForMessage(t *testing.T) {
	// Build delivery instructions (LOCAL)
	cloveData := []byte{0x00}

	// Build 9-byte short I2NP header claiming 500 bytes of data
	shortHeader := make([]byte, 9)
	shortHeader[0] = 20
	binary.BigEndian.PutUint32(shortHeader[1:5], 12345)
	binary.BigEndian.PutUint32(shortHeader[5:9], 500)
	cloveData = append(cloveData, shortHeader...)

	// But provide zero bytes of actual data (less than claimed 500)
	messageData := make([]byte, 0)
	cloveData = append(cloveData, messageData...)

	// Spec-compliant format: body consumes all remaining bytes (0 bytes is valid)
	clove, _, err := deserializeGarlicClove(cloveData, 0)
	require.NoError(t, err, "Zero-byte body should be valid in spec-compliant format")
	require.NotNil(t, clove)
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

	// Verify clove was parsed correctly (spec-compliant: no separate clove ID/trailer)
	assert.NotNil(t, clove.DeliveryInstructions)
	assert.Equal(t, byte(0x00), clove.DeliveryInstructions.Flag, "Expected LOCAL delivery flag")
	assert.Equal(t, 12345, clove.CloveID, "Expected clove ID from 9-byte header msgID")

	// Verify expiration is set (spec-compliant uses Unix seconds, may be in past relative to now)
	assert.NotZero(t, clove.Expiration.Unix(), "Clove expiration should be set")

	// Verify bytes consumed (spec-compliant 9-byte short header, no trailer)
	expectedBytes := 1 + 9 + messageSize
	assert.Equal(t, expectedBytes, bytesRead)
}

// TestDeserializeGarlicClove_ExactBufferSize tests that deserialization works
// when buffer size exactly matches requirements (no extra bytes).
func TestDeserializeGarlicClove_ExactBufferSize(t *testing.T) {
	messageSize := 128
	cloveData := buildTestGarlicCloveData(messageSize)

	// Verify data is exactly the size needed (spec-compliant 9-byte header, no trailer)
	expectedSize := 1 + 9 + messageSize
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

	// Verify all bytes were consumed (spec-compliant: body consumes remaining data)
	expectedBytes := 1 + 9 + messageSize + 4 // includes extra data as body
	assert.Equal(t, expectedBytes, bytesRead)
	assert.Equal(t, len(cloveData), bytesRead, "Should consume all data including extra bytes as body")
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

			expectedBytes := 1 + 9 + size
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

	// 2. 9-byte short I2NP header (spec-compliant): type(1) + msgID(4) + exp(4)
	shortHeader := make([]byte, 9)
	shortHeader[0] = 20 // Data message type
	binary.BigEndian.PutUint32(shortHeader[1:5], 12345)
	expirationMs := time.Now().Add(10 * time.Second).Unix()
	binary.BigEndian.PutUint32(shortHeader[5:9], uint32(expirationMs))
	buf = append(buf, shortHeader...)

	// 3. Message body (payload without standard 16-byte header)
	buf = append(buf, messageData...)

	return buf
}
