package i2np

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBuildMessageFactory_OversizedPayload tests that CreateShortTunnelBuildMessage
// returns an error when the payload exceeds I2NP size limits.
func TestBuildMessageFactory_OversizedPayload_Short(t *testing.T) {
	factory := NewBuildMessageFactory()

	// I2NP messages have a 16-bit length field, so max is 65535 bytes.
	// The message header is 16 bytes, so max data is 65535 - 16 = 65519 bytes.
	// Create an oversized payload: 1 byte count + many huge records
	oversizedRecords := make([][]byte, 250)
	for i := range oversizedRecords {
		oversizedRecords[i] = make([]byte, 300) // 250 * 300 = 75000 bytes > 65519
	}

	serialized, err := factory.CreateShortTunnelBuildMessage(oversizedRecords, 12345)

	// Should fail because payload is too large for I2NP 16-bit size field
	assert.Error(t, err, "expected error for oversized payload")
	assert.Nil(t, serialized, "expected nil result on error")
	if err != nil {
		assert.Contains(t, err.Error(), "marshal", "error should mention marshaling")
	}
}

// TestBuildMessageFactory_OversizedPayload_Variable tests that CreateVariableTunnelBuildMessage
// returns an error when the payload exceeds I2NP size limits.
func TestBuildMessageFactory_OversizedPayload_Variable(t *testing.T) {
	factory := NewBuildMessageFactory()

	// Create an oversized payload: 1 byte count + many huge records
	oversizedRecords := make([][]byte, 150)
	for i := range oversizedRecords {
		oversizedRecords[i] = make([]byte, 500) // 150 * 500 = 75000 bytes > 65519
	}

	serialized, err := factory.CreateVariableTunnelBuildMessage(oversizedRecords, 67890)

	// Should fail because payload is too large for I2NP 16-bit size field
	assert.Error(t, err, "expected error for oversized payload")
	assert.Nil(t, serialized, "expected nil result on error")
	if err != nil {
		assert.Contains(t, err.Error(), "marshal", "error should mention marshaling")
	}
}

// TestBuildMessageFactory_OversizedPayload_Tunnel tests that CreateTunnelBuildMessage
// returns an error when the payload exceeds I2NP size limits.
func TestBuildMessageFactory_OversizedPayload_Tunnel(t *testing.T) {
	factory := NewBuildMessageFactory()

	// I2NP messages have a 16-bit length field, so max is 65535 bytes.
	// Create valid-sized records but too many of them: 125 * 528 = 66000 bytes > 65535
	oversizedRecords := make([][]byte, 125)
	for i := range oversizedRecords {
		oversizedRecords[i] = make([]byte, 528) // Valid size but too many records
		for j := range oversizedRecords[i] {
			oversizedRecords[i][j] = byte(i + j)
		}
	}

	serialized, err := factory.CreateTunnelBuildMessage(oversizedRecords, 11111)

	// Should fail because payload is too large for I2NP 16-bit size field
	assert.Error(t, err, "expected error for oversized payload")
	assert.Nil(t, serialized, "expected nil result on error")
	if err != nil {
		assert.Contains(t, err.Error(), "marshal", "error should mention marshaling")
	}
}

// TestBuildMessageFactory_ValidPayload_Short tests normal operation with valid payload.
func TestBuildMessageFactory_ValidPayload_Short(t *testing.T) {
	factory := NewBuildMessageFactory()

	// Create valid STBM records (218 bytes each, typical for 3-hop tunnel)
	validRecords := make([][]byte, 3)
	for i := range validRecords {
		validRecords[i] = make([]byte, 218)
		for j := range validRecords[i] {
			validRecords[i][j] = byte(i + j) // Fill with test data
		}
	}

	serialized, err := factory.CreateShortTunnelBuildMessage(validRecords, 54321)

	require.NoError(t, err, "expected no error for valid payload")
	require.NotNil(t, serialized, "expected non-nil result")

	// Verify message header structure (16-byte header + data)
	require.Greater(t, len(serialized), 16, "message should have header + data")

	// Parse back to verify it's valid
	msg := &BaseI2NPMessage{}
	err = msg.UnmarshalBinary(serialized)
	require.NoError(t, err, "serialized message should be parseable")
	assert.Equal(t, I2NPMessageTypeShortTunnelBuild, msg.Type())
	assert.Equal(t, 54321, msg.MessageID())
}

// TestBuildMessageFactory_ValidPayload_Variable tests normal operation with valid payload.
func TestBuildMessageFactory_ValidPayload_Variable(t *testing.T) {
	factory := NewBuildMessageFactory()

	// Create valid VTB records (528 bytes each, typical for 4-hop tunnel)
	validRecords := make([][]byte, 4)
	for i := range validRecords {
		validRecords[i] = make([]byte, 528)
		for j := range validRecords[i] {
			validRecords[i][j] = byte(i * j) // Fill with test data
		}
	}

	serialized, err := factory.CreateVariableTunnelBuildMessage(validRecords, 98765)

	require.NoError(t, err, "expected no error for valid payload")
	require.NotNil(t, serialized, "expected non-nil result")

	// Verify message header structure (16-byte header + data)
	require.Greater(t, len(serialized), 16, "message should have header + data")

	// Parse back to verify it's valid
	msg := &BaseI2NPMessage{}
	err = msg.UnmarshalBinary(serialized)
	require.NoError(t, err, "serialized message should be parseable")
	assert.Equal(t, I2NPMessageTypeVariableTunnelBuild, msg.Type())
	assert.Equal(t, 98765, msg.MessageID())
}

// TestBuildMessageFactory_ValidPayload_Tunnel tests normal operation with valid payload.
func TestBuildMessageFactory_ValidPayload_Tunnel(t *testing.T) {
	factory := NewBuildMessageFactory()

	// Create valid type-21 records (8 records of 528 bytes each, no count prefix)
	validRecords := make([][]byte, 8)
	for i := range validRecords {
		validRecords[i] = make([]byte, 528)
		for j := range validRecords[i] {
			validRecords[i][j] = byte((i * j) % 256) // Fill with test data
		}
	}

	serialized, err := factory.CreateTunnelBuildMessage(validRecords, 11223)

	require.NoError(t, err, "expected no error for valid payload")
	require.NotNil(t, serialized, "expected non-nil result")

	// Verify message header structure (16-byte header + data)
	require.Greater(t, len(serialized), 16, "message should have header + data")

	// Parse back to verify it's valid
	msg := &BaseI2NPMessage{}
	err = msg.UnmarshalBinary(serialized)
	require.NoError(t, err, "serialized message should be parseable")
	assert.Equal(t, I2NPMessageTypeTunnelBuild, msg.Type())
	assert.Equal(t, 11223, msg.MessageID())
}
