package i2np

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseECIESGarlicClove_MessageLengthParsing tests that the spec-compliant
// clove format (DI + 9-byte short header + body-to-end) parses correctly for
// various body sizes.
func TestParseECIESGarlicClove_MessageLengthParsing(t *testing.T) {
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

			// Parse the spec-compliant single clove
			garlic, err := ParseECIESGarlicClove(cloveData)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorSubstring != "" {
					assert.Contains(t, err.Error(), tt.errorSubstring)
				}
			} else {
				require.NoError(t, err, "Failed to parse clove with message size %d", tt.messageSize)
				require.NotNil(t, garlic)
				require.Len(t, garlic.Cloves, 1)

				clove := garlic.Cloves[0]

				// Verify clove was parsed correctly
				assert.Equal(t, byte(0x00), clove.DeliveryInstructions.Flag, "Expected LOCAL delivery flag")
				carrier, ok := clove.Message.(DataCarrier)
				require.True(t, ok, "clove message must carry data")
				assert.Equal(t, tt.messageSize, len(carrier.GetData()), "body must extend to end of buffer")
			}
		})
	}
}

// TestParseECIESGarlicClove_InsufficientDataForHeader tests error handling
// when there's not enough data for the I2NP message header.
func TestParseECIESGarlicClove_InsufficientDataForHeader(t *testing.T) {
	// Create clove data with delivery instructions but incomplete I2NP header
	cloveData := []byte{0x00} // LOCAL delivery flag only

	// Add partial short I2NP header (only 4 bytes after flag = 5 total, less than 9 needed)
	partialHeader := make([]byte, 4)
	cloveData = append(cloveData, partialHeader...)

	_, err := ParseECIESGarlicClove(cloveData)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

// TestParseECIESGarlicClove_ZeroByteBody tests that a clove with a 9-byte
// header and zero body bytes is valid (body extends to end = empty).
func TestParseECIESGarlicClove_ZeroByteBody(t *testing.T) {
	// Build delivery instructions (LOCAL)
	cloveData := []byte{0x00}

	// Build 9-byte short I2NP header
	shortHeader := make([]byte, 9)
	shortHeader[0] = 20
	binary.BigEndian.PutUint32(shortHeader[1:5], 12345)
	binary.BigEndian.PutUint32(shortHeader[5:9], uint32(time.Now().Add(10*time.Second).Unix()))
	cloveData = append(cloveData, shortHeader...)

	// Spec-compliant format: body consumes all remaining bytes (0 bytes is valid)
	garlic, err := ParseECIESGarlicClove(cloveData)
	require.NoError(t, err, "Zero-byte body should be valid in spec-compliant format")
	require.NotNil(t, garlic)
	require.Len(t, garlic.Cloves, 1)
	carrier, ok := garlic.Cloves[0].Message.(DataCarrier)
	require.True(t, ok, "clove message must carry data")
	assert.Empty(t, carrier.GetData())
}

// TestParseECIESGarlicClove_ValidCloveStructure tests a complete valid clove
// with all components properly sized.
func TestParseECIESGarlicClove_ValidCloveStructure(t *testing.T) {
	messageSize := 256
	cloveData := buildTestGarlicCloveData(messageSize)

	garlic, err := ParseECIESGarlicClove(cloveData)

	require.NoError(t, err)
	require.NotNil(t, garlic)
	require.Len(t, garlic.Cloves, 1)

	clove := garlic.Cloves[0]

	// Verify all clove components
	assert.Equal(t, byte(0x00), clove.DeliveryInstructions.Flag, "Expected LOCAL delivery flag")
	assert.Equal(t, 12345, clove.Message.MessageID(), "Expected message ID from 9-byte header")
	assert.Equal(t, I2NPMessageTypeData, clove.Message.Type(), "Expected Data message type")

	// Verify expiration is set (spec-compliant uses Unix seconds)
	assert.NotZero(t, clove.Message.Expiration().Unix(), "Message expiration should be set")

	// Verify body extends to end of buffer
	carrier, ok := clove.Message.(DataCarrier)
	require.True(t, ok, "clove message must carry data")
	assert.Equal(t, messageSize, len(carrier.GetData()))
}

// TestParseECIESGarlicClove_EmptyInput tests that empty input is rejected.
func TestParseECIESGarlicClove_EmptyInput(t *testing.T) {
	_, err := ParseECIESGarlicClove(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty")

	_, err = ParseECIESGarlicClove([]byte{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

// TestParseECIESGarlicClove_DifferentMessageSizes tests various message sizes
// to ensure the body-to-end parsing works correctly for edge cases.
func TestParseECIESGarlicClove_DifferentMessageSizes(t *testing.T) {
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

			garlic, err := ParseECIESGarlicClove(cloveData)

			require.NoError(t, err, "Failed with message size %d", size)
			require.NotNil(t, garlic)
			require.Len(t, garlic.Cloves, 1)

			carrier, ok := garlic.Cloves[0].Message.(DataCarrier)
			require.True(t, ok, "clove message must carry data")
			assert.Equal(t, size, len(carrier.GetData()),
				"Incorrect body size for message size %d", size)
		})
	}
}

// buildTestGarlicCloveData creates a properly formatted garlic clove byte sequence
// in the spec-compliant ECIES format:
// DeliveryInstructions (LOCAL = 1 byte) + 9-byte short I2NP header + body.
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
	expirationSecs := time.Now().Add(10 * time.Second).Unix()
	binary.BigEndian.PutUint32(shortHeader[5:9], uint32(expirationSecs))
	buf = append(buf, shortHeader...)

	// 3. Message body (payload without standard 16-byte header)
	buf = append(buf, messageData...)

	return buf
}
