package tunnel

import (
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
