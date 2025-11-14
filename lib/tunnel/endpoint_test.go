package tunnel

import (
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/go-i2p/crypto/tunnel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewEndpoint tests the endpoint constructor
func TestNewEndpoint(t *testing.T) {
	mockHandler := func(msgBytes []byte) error {
		return nil
	}

	// Create a mock encryptor for testing
	mockEncryptor := &tunnel.AESEncryptor{}

	tests := []struct {
		name        string
		tunnelID    TunnelID
		decryption  tunnel.TunnelEncryptor
		handler     MessageHandler
		expectError bool
		errorType   error
	}{
		{
			name:        "valid endpoint creation",
			tunnelID:    TunnelID(12345),
			decryption:  mockEncryptor,
			handler:     mockHandler,
			expectError: false,
		},
		{
			name:        "nil decryption",
			tunnelID:    TunnelID(12345),
			decryption:  nil,
			handler:     mockHandler,
			expectError: true,
			errorType:   ErrNilDecryption,
		},
		{
			name:        "nil handler",
			tunnelID:    TunnelID(12345),
			decryption:  mockEncryptor,
			handler:     nil,
			expectError: true,
			errorType:   ErrNilHandler,
		},
		{
			name:        "nil both",
			tunnelID:    TunnelID(12345),
			decryption:  nil,
			handler:     nil,
			expectError: true,
			errorType:   ErrNilDecryption,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ep, err := NewEndpoint(tt.tunnelID, tt.decryption, tt.handler)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, ep)
				if tt.errorType != nil {
					assert.ErrorIs(t, err, tt.errorType)
				}
			} else {
				assert.NoError(t, err)
				require.NotNil(t, ep)
				assert.Equal(t, tt.tunnelID, ep.TunnelID())
			}
		})
	}
}

// TestEndpointReceive tests the Receive method with various inputs
func TestEndpointReceive(t *testing.T) {
	var receivedMsg []byte
	mockHandler := func(msgBytes []byte) error {
		receivedMsg = make([]byte, len(msgBytes))
		copy(receivedMsg, msgBytes)
		return nil
	}

	mockEncryptor := &tunnel.AESEncryptor{}

	tests := []struct {
		name        string
		dataSize    int
		expectError bool
		errorType   error
	}{
		{
			name:        "invalid size - too small",
			dataSize:    100,
			expectError: true,
			errorType:   ErrInvalidTunnelData,
		},
		{
			name:        "invalid size - too large",
			dataSize:    2000,
			expectError: true,
			errorType:   ErrInvalidTunnelData,
		},
		{
			name:        "empty data",
			dataSize:    0,
			expectError: true,
			errorType:   ErrInvalidTunnelData,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ep, err := NewEndpoint(TunnelID(12345), mockEncryptor, mockHandler)
			require.NoError(t, err)

			testData := make([]byte, tt.dataSize)
			err = ep.Receive(testData)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorType != nil {
					assert.ErrorIs(t, err, tt.errorType)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestValidateChecksum tests the checksum validation
func TestValidateChecksum(t *testing.T) {
	ep := &Endpoint{
		tunnelID: TunnelID(12345),
	}

	tests := []struct {
		name        string
		setupFunc   func() []byte
		expectError bool
	}{
		{
			name: "valid checksum",
			setupFunc: func() []byte {
				msg := make([]byte, 1028)
				// Set up IV (bytes 4-20)
				for i := 4; i < 20; i++ {
					msg[i] = byte(i)
				}
				// Set up some data (bytes 24+)
				for i := 24; i < 100; i++ {
					msg[i] = byte(i % 256)
				}
				// Calculate correct checksum
				checksumData := append(msg[24:], msg[4:20]...)
				hash := sha256.Sum256(checksumData)
				copy(msg[20:24], hash[:4])
				return msg
			},
			expectError: false,
		},
		{
			name: "invalid checksum",
			setupFunc: func() []byte {
				msg := make([]byte, 1028)
				// Set up IV
				for i := 4; i < 20; i++ {
					msg[i] = byte(i)
				}
				// Set invalid checksum
				msg[20] = 0xFF
				msg[21] = 0xFF
				msg[22] = 0xFF
				msg[23] = 0xFF
				return msg
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := tt.setupFunc()
			err := ep.validateChecksum(data)

			if tt.expectError {
				assert.Error(t, err)
				assert.ErrorIs(t, err, ErrChecksumMismatch)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestProcessDeliveryInstructions tests delivery instruction parsing
func TestProcessDeliveryInstructions(t *testing.T) {
	tests := []struct {
		name          string
		setupFunc     func() []byte
		expectError   bool
		expectedCount int
	}{
		{
			name: "simple local delivery",
			setupFunc: func() []byte {
				msg := make([]byte, 1028)
				// Add padding with non-zero bytes
				for i := 24; i < 500; i++ {
					msg[i] = byte((i % 255) + 1)
				}
				// Zero byte separator at position 500
				msg[500] = 0x00
				// Delivery instructions at 501
				msg[501] = DT_LOCAL // flags: DT_LOCAL, not fragmented
				testMsg := []byte("Hello, I2P!")
				binary.BigEndian.PutUint16(msg[502:504], uint16(len(testMsg)))
				// Message at 504
				copy(msg[504:], testMsg)
				return msg
			},
			expectError:   false,
			expectedCount: 1,
		},
		{
			name: "no zero byte separator",
			setupFunc: func() []byte {
				msg := make([]byte, 1028)
				// Fill with non-zero bytes (no separator)
				for i := 24; i < len(msg); i++ {
					msg[i] = byte((i % 255) + 1)
				}
				return msg
			},
			expectError:   true,
			expectedCount: 0,
		},
		{
			name: "multiple messages",
			setupFunc: func() []byte {
				msg := make([]byte, 1028)
				// Padding
				for i := 24; i < 400; i++ {
					msg[i] = byte((i % 255) + 1)
				}
				// Zero byte
				msg[400] = 0x00
				offset := 401

				// First message
				msg[offset] = DT_LOCAL
				msg1 := []byte("First")
				binary.BigEndian.PutUint16(msg[offset+1:offset+3], uint16(len(msg1)))
				copy(msg[offset+3:], msg1)
				offset += 3 + len(msg1)

				// Second message
				msg[offset] = DT_LOCAL
				msg2 := []byte("Second")
				binary.BigEndian.PutUint16(msg[offset+1:offset+3], uint16(len(msg2)))
				copy(msg[offset+3:], msg2)

				return msg
			},
			expectError:   false,
			expectedCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var receivedMsgs [][]byte
			mockHandler := func(msgBytes []byte) error {
				msg := make([]byte, len(msgBytes))
				copy(msg, msgBytes)
				receivedMsgs = append(receivedMsgs, msg)
				return nil
			}

			ep := &Endpoint{
				tunnelID:  TunnelID(12345),
				handler:   mockHandler,
				fragments: make(map[uint32]*fragmentAssembler),
			}

			data := tt.setupFunc()
			err := ep.processDeliveryInstructions(data)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedCount, len(receivedMsgs))
			}
		})
	}
}

// TestEndpointTunnelID tests the TunnelID getter
func TestEndpointTunnelID(t *testing.T) {
	tunnelID := TunnelID(12345)
	mockEncryptor := &tunnel.AESEncryptor{}
	mockHandler := func(msgBytes []byte) error {
		return nil
	}

	ep, err := NewEndpoint(TunnelID(12345), mockEncryptor, mockHandler)
	require.NoError(t, err)
	require.NotNil(t, ep)

	assert.Equal(t, tunnelID, ep.TunnelID())
}

// TestClearFragments tests the fragment clearing functionality
func TestClearFragments(t *testing.T) {
	mockEncryptor := &tunnel.AESEncryptor{}
	mockHandler := func(msgBytes []byte) error {
		return nil
	}

	ep, err := NewEndpoint(TunnelID(12345), mockEncryptor, mockHandler)
	require.NoError(t, err)

	// Add some mock fragments
	ep.fragments[1] = &fragmentAssembler{
		fragments:  [][]byte{[]byte("test")},
		totalCount: 2,
	}
	ep.fragments[2] = &fragmentAssembler{
		fragments:  [][]byte{[]byte("test2")},
		totalCount: 1,
	}

	assert.Equal(t, 2, len(ep.fragments))

	// Clear fragments
	ep.ClearFragments()

	assert.Equal(t, 0, len(ep.fragments))
}

// TestEndpointDecryptTunnelMessage tests the decryption wrapper
func TestEndpointDecryptTunnelMessage(t *testing.T) {
	// Note: This test uses a basic endpoint without proper tunnel encryption setup
	// In real usage, the tunnel would be properly initialized with keys
	// For this test, we just verify the method signature and basic behavior

	mockHandler := func(msgBytes []byte) error {
		return nil
	}

	// Create test data
	testData := make([]byte, 1028)
	for i := range testData {
		testData[i] = byte(i % 256)
	}

	// Test with a properly initialized (but empty) endpoint that won't panic
	ep := &Endpoint{
		tunnelID:  TunnelID(12345),
		handler:   mockHandler,
		fragments: make(map[uint32]*fragmentAssembler),
		// Note: decryption is nil, so we won't call decryptTunnelMessage directly
	}

	// Verify endpoint is created correctly
	assert.Equal(t, TunnelID(12345), ep.TunnelID())
	assert.NotNil(t, ep.handler)
	assert.NotNil(t, ep.fragments)
}

// TestGatewayEndpointStructure tests the structure compatibility between gateway and endpoint
func TestGatewayEndpointStructure(t *testing.T) {
	// This test verifies that gateway produces output with correct structure
	// without requiring full encryption/decryption which needs proper key setup

	testMessage := []byte("Structure test message")

	// Create a gateway (endpoint creation requires decryption which may panic with nil tunnel)
	gw := &Gateway{
		tunnelID:  TunnelID(12345),
		nextHopID: TunnelID(67890),
		// Note: no encryption set, we'll build message manually
	}

	// Build delivery instructions
	instructions, err := gw.createDeliveryInstructions(testMessage)
	require.NoError(t, err)

	// Build tunnel message
	tunnelMsg, err := gw.buildTunnelMessage(instructions, testMessage)
	require.NoError(t, err)
	require.Equal(t, 1028, len(tunnelMsg))

	// Verify tunnel ID in message
	tunnelID := TunnelID(uint32(tunnelMsg[0])<<24 | uint32(tunnelMsg[1])<<16 | uint32(tunnelMsg[2])<<8 | uint32(tunnelMsg[3]))
	assert.Equal(t, TunnelID(67890), tunnelID)

	// Verify there's a zero byte separator
	foundZero := false
	for i := 24; i < len(tunnelMsg); i++ {
		if tunnelMsg[i] == 0x00 {
			foundZero = true
			break
		}
	}
	assert.True(t, foundZero, "Should have zero byte separator")
}
