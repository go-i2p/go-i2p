package i2np

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGenerateRandomMessageID_AlwaysPositive verifies that generateRandomMessageID
// always returns a non-negative value. This is critical for 32-bit platforms where
// int(uint32(x)) with the high bit set wraps to a negative number.
func TestGenerateRandomMessageID_AlwaysPositive(t *testing.T) {
	// Generate many IDs and verify all are positive
	for i := 0; i < 1000; i++ {
		id := generateRandomMessageID()
		assert.GreaterOrEqual(t, id, 0, "message ID must be non-negative (iteration %d)", i)
		// Also verify it fits in 31 bits
		assert.LessOrEqual(t, id, 0x7FFFFFFF, "message ID must fit in 31 bits (iteration %d)", i)
	}
}

// TestGenerateRandomMessageID_NeverZero verifies that generateRandomMessageID
// does not silently return 0. With 31 bits of randomness, the probability of
// a legitimate 0 is 1 in 2^31 (~2 billion), so getting 0 in 100 attempts
// strongly suggests a fallback-to-0 bug rather than genuine randomness.
func TestGenerateRandomMessageID_NeverZero(t *testing.T) {
	for i := 0; i < 100; i++ {
		id := generateRandomMessageID()
		// While technically possible, getting 0 from 31 random bits is
		// ~1 in 2 billion. If we see it in 100 tries, something is wrong.
		if id == 0 {
			t.Fatal("generateRandomMessageID returned 0, likely a silent fallback bug")
		}
	}
}

// TestGenerateRandomMessageID_Uniqueness verifies basic uniqueness of generated IDs.
func TestGenerateRandomMessageID_Uniqueness(t *testing.T) {
	ids := make(map[int]bool)
	for i := 0; i < 100; i++ {
		id := generateRandomMessageID()
		ids[id] = true
	}
	// With 31 bits of randomness, 100 IDs should all be unique
	assert.Equal(t, 100, len(ids), "100 generated message IDs should be unique with 31 bits of entropy")
}

// TestUnmarshalBinary_MessageIDAlwaysPositive verifies that UnmarshalBinary
// produces a positive messageID even when the serialized bytes have the high bit set.
func TestUnmarshalBinary_MessageIDAlwaysPositive(t *testing.T) {
	tests := []struct {
		name    string
		idBytes [4]byte
		wantID  int
	}{
		{
			name:    "high bit set (0x80000000)",
			idBytes: [4]byte{0x80, 0x00, 0x00, 0x00},
			wantID:  0x00000000, // masked: 0x80000000 & 0x7FFFFFFF = 0
		},
		{
			name:    "all bits set (0xFFFFFFFF)",
			idBytes: [4]byte{0xFF, 0xFF, 0xFF, 0xFF},
			wantID:  0x7FFFFFFF, // masked: 0xFFFFFFFF & 0x7FFFFFFF = 0x7FFFFFFF
		},
		{
			name:    "normal positive value",
			idBytes: [4]byte{0x00, 0x30, 0x39, 0x00},
			wantID:  0x00303900,
		},
		{
			name:    "maximum 31-bit value",
			idBytes: [4]byte{0x7F, 0xFF, 0xFF, 0xFF},
			wantID:  0x7FFFFFFF,
		},
		{
			name:    "zero",
			idBytes: [4]byte{0x00, 0x00, 0x00, 0x00},
			wantID:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build a minimal valid I2NP message: type(1) + msgID(4) + expiration(8) + size(2) + checksum(1) = 16
			msg := make([]byte, 16)
			msg[0] = 0x01 // type
			copy(msg[1:5], tt.idBytes[:])
			// Zero expiration, zero size, checksum of empty data
			// SHA256 of empty data = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
			msg[15] = 0xe3

			base := &BaseI2NPMessage{}
			err := base.UnmarshalBinary(msg)
			require.NoError(t, err)
			assert.Equal(t, tt.wantID, base.MessageID(), "messageID should match expected masked value")
			assert.GreaterOrEqual(t, base.MessageID(), 0, "messageID must be non-negative")
		})
	}
}

// TestMarshalUnmarshalBinary_RoundTrip verifies that marshal/unmarshal preserves messageID.
func TestMarshalUnmarshalBinary_RoundTrip(t *testing.T) {
	original := NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_DATA)
	originalID := original.MessageID()

	// Verify the generated ID is positive
	assert.GreaterOrEqual(t, originalID, 0)

	data, err := original.MarshalBinary()
	require.NoError(t, err)

	restored := &BaseI2NPMessage{}
	err = restored.UnmarshalBinary(data)
	require.NoError(t, err)

	assert.Equal(t, originalID, restored.MessageID(),
		"messageID should survive marshal/unmarshal round-trip")
}

// TestMarshalBinary_HighBitMessageID verifies that MarshalBinary correctly
// serializes a messageID as 4 bytes, even with the full 31-bit range.
func TestMarshalBinary_HighBitMessageID(t *testing.T) {
	msg := NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_DATA)
	msg.SetMessageID(0x7FFFFFFF) // maximum 31-bit value

	data, err := msg.MarshalBinary()
	require.NoError(t, err)

	// Verify the serialized messageID bytes
	serializedID := binary.BigEndian.Uint32(data[1:5])
	assert.Equal(t, uint32(0x7FFFFFFF), serializedID,
		"max 31-bit ID should serialize correctly")

	// Verify round-trip
	restored := &BaseI2NPMessage{}
	err = restored.UnmarshalBinary(data)
	require.NoError(t, err)
	assert.Equal(t, 0x7FFFFFFF, restored.MessageID())
}

// TestNewBaseI2NPMessage_MessageIDPositive verifies that newly created messages
// always have positive message IDs.
func TestNewBaseI2NPMessage_MessageIDPositive(t *testing.T) {
	for i := 0; i < 100; i++ {
		msg := NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_DATA)
		assert.GreaterOrEqual(t, msg.MessageID(), 0,
			"newly created message should have non-negative ID (iteration %d)", i)
	}
}
