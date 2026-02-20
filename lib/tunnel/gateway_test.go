package tunnel

import (
	"github.com/go-i2p/crypto/types"
	"testing"

	"github.com/go-i2p/crypto/tunnel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewGateway tests the gateway constructor
func TestNewGateway(t *testing.T) {
	// Create a mock encryptor for testing
	mockEncryptor := &tunnel.AESEncryptor{}

	tests := []struct {
		name        string
		tunnelID    TunnelID
		encryption  tunnel.TunnelEncryptor
		nextHopID   TunnelID
		expectError bool
		errorType   error
	}{
		{
			name:        "valid gateway creation",
			tunnelID:    TunnelID(12345),
			encryption:  mockEncryptor,
			nextHopID:   TunnelID(67890),
			expectError: false,
		},
		{
			name:        "nil encryption",
			tunnelID:    TunnelID(12345),
			encryption:  nil,
			nextHopID:   TunnelID(67890),
			expectError: true,
			errorType:   ErrNilEncryption,
		},
		{
			name:        "zero tunnel IDs",
			tunnelID:    TunnelID(0),
			encryption:  mockEncryptor,
			nextHopID:   TunnelID(0),
			expectError: false, // Zero IDs are technically valid
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gw, err := NewGateway(tt.tunnelID, tt.encryption, tt.nextHopID)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, gw)
				if tt.errorType != nil {
					assert.ErrorIs(t, err, tt.errorType)
				}
			} else {
				assert.NoError(t, err)
				require.NotNil(t, gw)
				assert.Equal(t, tt.tunnelID, gw.TunnelID())
				assert.Equal(t, tt.nextHopID, gw.NextHopID())
			}
		})
	}
}

// TestGatewaySend tests the Send method with various message sizes
func TestGatewaySend(t *testing.T) {
	// Note: We test the building logic without actual encryption
	// since encryption requires proper key setup

	tests := []struct {
		name        string
		msgBytes    []byte
		expectError bool
		errorType   error
	}{
		{
			name:        "message too large",
			msgBytes:    make([]byte, maxTunnelPayload+100),
			expectError: true,
			errorType:   ErrMessageTooLarge,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create gateway without encryption for error path testing
			gw := &Gateway{
				tunnelID:  TunnelID(12345),
				nextHopID: TunnelID(67890),
			}

			// Test delivery instruction creation which will fail for invalid inputs
			_, err := gw.createDeliveryInstructions(tt.msgBytes)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorType != nil {
					assert.ErrorIs(t, err, tt.errorType)
				}
			}
		})
	}
}

// TestCreateDeliveryInstructions tests delivery instruction creation
func TestCreateDeliveryInstructions(t *testing.T) {
	gw := &Gateway{
		tunnelID:  TunnelID(12345),
		nextHopID: TunnelID(67890),
	}

	tests := []struct {
		name        string
		msgBytes    []byte
		expectError bool
	}{
		{
			name:        "small message",
			msgBytes:    []byte("test"),
			expectError: false,
		},
		{
			name:        "empty message",
			msgBytes:    []byte{},
			expectError: false,
		},
		{
			name:        "max size message",
			msgBytes:    make([]byte, maxTunnelPayload-3),
			expectError: false,
		},
		{
			name:        "oversized message",
			msgBytes:    make([]byte, maxTunnelPayload),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			instructions, err := gw.createDeliveryInstructions(tt.msgBytes)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, instructions)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, instructions)
				assert.Equal(t, 3, len(instructions))
				// First byte should be DT_LOCAL (0)
				assert.Equal(t, byte(DT_LOCAL), instructions[0])
			}
		})
	}
}

// TestBuildTunnelMessage tests tunnel message construction
func TestBuildTunnelMessage(t *testing.T) {
	gw := &Gateway{
		tunnelID:  TunnelID(12345),
		nextHopID: TunnelID(67890),
	}

	tests := []struct {
		name         string
		instructions []byte
		msgBytes     []byte
		expectError  bool
	}{
		{
			name:         "valid message",
			instructions: []byte{0x00, 0x00, 0x04},
			msgBytes:     []byte("test"),
			expectError:  false,
		},
		{
			name:         "empty message",
			instructions: []byte{0x00, 0x00, 0x00},
			msgBytes:     []byte{},
			expectError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := gw.buildTunnelMessage(tt.instructions, tt.msgBytes)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, result)
				assert.Equal(t, 1028, len(result))

				// Verify tunnel ID is correct
				tunnelID := TunnelID(uint32(result[0])<<24 | uint32(result[1])<<16 | uint32(result[2])<<8 | uint32(result[3]))
				assert.Equal(t, gw.nextHopID, tunnelID)

				// Verify there's a zero byte separator somewhere in the message
				foundZero := false
				for i := 24; i < len(result); i++ {
					if result[i] == 0x00 {
						foundZero = true
						break
					}
				}
				assert.True(t, foundZero, "Should have zero byte separator")
			}
		})
	}
}

// TestGatewayIVIsWritten verifies that buildTunnelMessage writes a non-zero
// random IV at bytes 4-19, fixing CRITICAL BUG #5.
func TestGatewayIVIsWritten(t *testing.T) {
	gw := &Gateway{
		tunnelID:  TunnelID(12345),
		nextHopID: TunnelID(67890),
	}

	testMsg := []byte("test")
	instructions, err := gw.createDeliveryInstructions(testMsg)
	require.NoError(t, err)

	tunnelMsg, err := gw.buildTunnelMessage(instructions, testMsg)
	require.NoError(t, err)
	assert.Equal(t, 1028, len(tunnelMsg))

	// Verify IV (bytes 4-19) is not all zeros
	iv := tunnelMsg[4:20]
	allZero := true
	for _, b := range iv {
		if b != 0 {
			allZero = false
			break
		}
	}
	assert.False(t, allZero, "IV bytes 4-19 should not be all zeros")
}

// TestGatewayIVIsRandom verifies that the IV differs between calls.
func TestGatewayIVIsRandom(t *testing.T) {
	gw := &Gateway{
		tunnelID:  TunnelID(12345),
		nextHopID: TunnelID(67890),
	}

	testMsg := []byte("test")
	instructions, err := gw.createDeliveryInstructions(testMsg)
	require.NoError(t, err)

	msg1, err := gw.buildTunnelMessage(instructions, testMsg)
	require.NoError(t, err)

	msg2, err := gw.buildTunnelMessage(instructions, testMsg)
	require.NoError(t, err)

	iv1 := msg1[4:20]
	iv2 := msg2[4:20]

	different := false
	for i := range iv1 {
		if iv1[i] != iv2[i] {
			different = true
			break
		}
	}
	assert.True(t, different, "IVs should differ between calls (random)")
}

// TestGatewayChecksumIncludesIV verifies the checksum is calculated using the IV.
func TestGatewayChecksumIncludesIV(t *testing.T) {
	gw := &Gateway{
		tunnelID:  TunnelID(12345),
		nextHopID: TunnelID(67890),
	}

	testMsg := []byte("test")
	instructions, err := gw.createDeliveryInstructions(testMsg)
	require.NoError(t, err)

	tunnelMsg, err := gw.buildTunnelMessage(instructions, testMsg)
	require.NoError(t, err)

	// Verify checksum: first 4 bytes of SHA256(data_after_zero_byte + IV)
	// Per I2P spec: "The checksum does NOT cover the padding or the zero byte."
	iv := tunnelMsg[4:20]
	// Find zero byte separator
	var zeroPos int
	for i := 24; i < len(tunnelMsg); i++ {
		if tunnelMsg[i] == 0x00 {
			zeroPos = i
			break
		}
	}
	require.Greater(t, zeroPos, 23, "zero byte separator must exist")
	dataAfterZero := tunnelMsg[zeroPos+1:]
	checksumData := append(dataAfterZero, iv...)
	hash := types.SHA256(checksumData)
	expectedChecksum := hash[:4]

	actualChecksum := tunnelMsg[20:24]
	assert.Equal(t, expectedChecksum, actualChecksum, "Checksum should be calculated from data + IV")
}

// mockPassthroughEncryptor implements TunnelEncryptor by returning data as-is.
type mockPassthroughEncryptor struct{}

func (m *mockPassthroughEncryptor) Encrypt(data []byte) ([]byte, error) {
	result := make([]byte, len(data))
	copy(result, data)
	return result, nil
}

func (m *mockPassthroughEncryptor) Decrypt(data []byte) ([]byte, error) {
	result := make([]byte, len(data))
	copy(result, data)
	return result, nil
}

func (m *mockPassthroughEncryptor) Type() tunnel.TunnelEncryptionType {
	return tunnel.TunnelEncryptionAES
}

// TestEndpointAccepts1028Bytes verifies the Endpoint accepts 1028-byte messages,
// fixing FUNCTIONAL MISMATCH #1.
func TestEndpointAccepts1028Bytes(t *testing.T) {
	handler := func(msg []byte) error { return nil }
	mockEnc := &mockPassthroughEncryptor{}

	ep, err := NewEndpoint(TunnelID(12345), mockEnc, handler)
	require.NoError(t, err)
	defer ep.Stop()

	// 1028 bytes should not be rejected by the size check
	// (may fail at checksum validation, but NOT at size validation)
	testData := make([]byte, 1028)
	err = ep.Receive(testData)
	// The error should NOT be ErrInvalidTunnelData (size check)
	if err != nil {
		assert.NotErrorIs(t, err, ErrInvalidTunnelData,
			"1028-byte messages should pass size validation")
	}
}

// TestEndpointRejectsWrongSizes verifies the Endpoint still rejects non-1028 sizes.
func TestEndpointRejectsWrongSizes(t *testing.T) {
	handler := func(msg []byte) error { return nil }
	mockEnc := &mockPassthroughEncryptor{}

	ep, err := NewEndpoint(TunnelID(12345), mockEnc, handler)
	require.NoError(t, err)
	defer ep.Stop()

	wrongSizes := []int{0, 100, 1024, 1027, 1029, 2000}
	for _, size := range wrongSizes {
		err := ep.Receive(make([]byte, size))
		assert.ErrorIs(t, err, ErrInvalidTunnelData,
			"size %d should be rejected", size)
	}
}

// TestGatewayGetters tests the getter methods
func TestGatewayGetters(t *testing.T) {
	tunnelID := TunnelID(12345)
	nextHopID := TunnelID(67890)
	mockEncryptor := &tunnel.AESEncryptor{}

	gw, err := NewGateway(tunnelID, mockEncryptor, nextHopID)
	require.NoError(t, err)
	require.NotNil(t, gw)

	assert.Equal(t, tunnelID, gw.TunnelID())
	assert.Equal(t, nextHopID, gw.NextHopID())
}

// TestGatewayMessageBuilding tests the message building pipeline
func TestGatewayMessageBuilding(t *testing.T) {
	// This test verifies that the gateway can build valid tunnel messages
	// without requiring full encryption setup
	gw := &Gateway{
		tunnelID:  TunnelID(12345),
		nextHopID: TunnelID(67890),
	}

	testMsg := []byte("Integration test message")

	// Test building delivery instructions
	instructions, err := gw.createDeliveryInstructions(testMsg)
	require.NoError(t, err)
	assert.Equal(t, 3, len(instructions))

	// Test building full tunnel message
	tunnelMsg, err := gw.buildTunnelMessage(instructions, testMsg)
	require.NoError(t, err)
	assert.Equal(t, 1028, len(tunnelMsg))

	// Verify tunnel ID is set correctly
	tunnelID := TunnelID(uint32(tunnelMsg[0])<<24 | uint32(tunnelMsg[1])<<16 | uint32(tunnelMsg[2])<<8 | uint32(tunnelMsg[3]))
	assert.Equal(t, TunnelID(67890), tunnelID)
}

// TestGatewayPaddingIsRandom tests that padding bytes are random and non-zero
func TestGatewayPaddingIsRandom(t *testing.T) {
	gw := &Gateway{
		tunnelID:  TunnelID(12345),
		nextHopID: TunnelID(67890),
	}

	// Use a small message to maximize padding
	testMsg := []byte("Hi")
	instructions, err := gw.createDeliveryInstructions(testMsg)
	require.NoError(t, err)

	// Build multiple messages and verify padding varies
	var paddingBytes1, paddingBytes2 []byte

	tunnelMsg1, err := gw.buildTunnelMessage(instructions, testMsg)
	require.NoError(t, err)

	tunnelMsg2, err := gw.buildTunnelMessage(instructions, testMsg)
	require.NoError(t, err)

	// Find the zero separator to locate padding
	for i := 24; i < len(tunnelMsg1); i++ {
		if tunnelMsg1[i] == 0x00 {
			paddingBytes1 = tunnelMsg1[24:i]
			break
		}
	}
	for i := 24; i < len(tunnelMsg2); i++ {
		if tunnelMsg2[i] == 0x00 {
			paddingBytes2 = tunnelMsg2[24:i]
			break
		}
	}

	require.NotEmpty(t, paddingBytes1, "Should have padding bytes")
	require.Equal(t, len(paddingBytes1), len(paddingBytes2), "Padding lengths should match")

	// Verify no zero bytes in padding (I2P spec requires non-zero)
	for i, b := range paddingBytes1 {
		assert.NotZero(t, b, "Padding byte %d should be non-zero", i)
	}

	// Verify padding is different between calls (random)
	different := false
	for i := range paddingBytes1 {
		if paddingBytes1[i] != paddingBytes2[i] {
			different = true
			break
		}
	}
	assert.True(t, different, "Padding should be random between calls")
}
