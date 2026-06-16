package i2np

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestDataMessageRoundTrip tests that DataMessages can be successfully marshaled and unmarshaled
// across various payload sizes, including boundary cases and the max allowed size.
// This test also serves as a regression test for HIGH-1: the fix ensures that the code
// checks payload sizes against MaxI2NPMessageSize before converting to int, preventing
// integer overflow on 32-bit platforms.
func TestDataMessageRoundTrip(t *testing.T) {
	testSizes := []int{
		0,                  // Empty
		1,                  // Single byte
		255,                // Boundary: 8-bit max
		256,                // One past 8-bit
		1024,               // 1 KB
		32767,              // Just under 32 KB
		MaxI2NPMessageSize, // Max size (32 KB)
	}

	for _, size := range testSizes {
		t.Run("size_"+string(rune('0'+(byte(size/1000)%10))), func(t *testing.T) {
			payload := make([]byte, size)
			// Fill with test data
			for i := 0; i < len(payload); i++ {
				payload[i] = byte((i * 17) % 256)
			}

			// Create and marshal original message
			original := NewDataMessage(payload)
			require.NotNil(t, original)
			marshaledFull, err := original.MarshalBinary()
			require.NoError(t, err)

			// Deserialize using full I2NP unmarshaling
			decoded := &DataMessage{
				BaseI2NPMessage: &BaseI2NPMessage{},
			}
			err = decoded.UnmarshalBinary(marshaledFull)
			require.NoError(t, err)
			require.Equal(t, len(payload), decoded.PayloadLength)
			require.Equal(t, payload, decoded.Payload)
		})
	}
}
