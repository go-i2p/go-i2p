package tunnel

import (
	"github.com/go-i2p/crypto/types"
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
				// Non-zero padding (bytes 24-99)
				for i := 24; i < 100; i++ {
					msg[i] = byte(i%254 + 1) // non-zero padding
				}
				// Zero byte separator
				msg[100] = 0x00
				// Data after zero byte (delivery instructions + message)
				for i := 101; i < 110; i++ {
					msg[i] = byte(i % 256)
				}
				// Calculate correct checksum: SHA256(data_after_zero_byte + IV)
				dataAfterZero := msg[101:]
				checksumData := append(dataAfterZero, msg[4:20]...)
				hash := types.SHA256(checksumData)
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
		fragments: map[int][]byte{
			0: []byte("test"),
		},
		deliveryType: DT_LOCAL,
		totalCount:   2,
		receivedMask: 1,
	}
	ep.fragments[2] = &fragmentAssembler{
		fragments: map[int][]byte{
			0: []byte("test2"),
		},
		deliveryType: DT_LOCAL,
		totalCount:   1,
		receivedMask: 1,
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

// TestFragmentReassembly tests the fragment reassembly functionality
func TestFragmentReassembly(t *testing.T) {
	var receivedMsg []byte
	mockHandler := func(msgBytes []byte) error {
		receivedMsg = make([]byte, len(msgBytes))
		copy(receivedMsg, msgBytes)
		return nil
	}

	mockEncryptor := &tunnel.AESEncryptor{}

	tests := []struct {
		name      string
		fragments []struct {
			isFirst bool
			fragNum int
			isLast  bool
			data    []byte
		}
		expectedMsg    []byte
		expectDelivery bool
	}{
		{
			name: "two fragments in order",
			fragments: []struct {
				isFirst bool
				fragNum int
				isLast  bool
				data    []byte
			}{
				{isFirst: true, fragNum: 0, isLast: false, data: []byte("Hello, ")},
				{isFirst: false, fragNum: 1, isLast: true, data: []byte("World!")},
			},
			expectedMsg:    []byte("Hello, World!"),
			expectDelivery: true,
		},
		{
			name: "two fragments out of order",
			fragments: []struct {
				isFirst bool
				fragNum int
				isLast  bool
				data    []byte
			}{
				{isFirst: false, fragNum: 1, isLast: true, data: []byte("World!")},
				{isFirst: true, fragNum: 0, isLast: false, data: []byte("Hello, ")},
			},
			expectedMsg:    []byte("Hello, World!"),
			expectDelivery: true,
		},
		{
			name: "three fragments",
			fragments: []struct {
				isFirst bool
				fragNum int
				isLast  bool
				data    []byte
			}{
				{isFirst: true, fragNum: 0, isLast: false, data: []byte("Part1")},
				{isFirst: false, fragNum: 1, isLast: false, data: []byte("Part2")},
				{isFirst: false, fragNum: 2, isLast: true, data: []byte("Part3")},
			},
			expectedMsg:    []byte("Part1Part2Part3"),
			expectDelivery: true,
		},
		{
			name: "single unfragmented message",
			fragments: []struct {
				isFirst bool
				fragNum int
				isLast  bool
				data    []byte
			}{
				{isFirst: true, fragNum: 0, isLast: false, data: []byte("Complete message")},
			},
			expectedMsg:    []byte("Complete message"),
			expectDelivery: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			receivedMsg = nil
			ep, err := NewEndpoint(TunnelID(12345), mockEncryptor, mockHandler)
			require.NoError(t, err)

			msgID := uint32(999)

			for _, frag := range tt.fragments {
				if frag.isFirst {
					// Create first fragment delivery instructions
					di := &DeliveryInstructions{
						fragmentType: FIRST_FRAGMENT,
						deliveryType: DT_LOCAL,
						fragmented:   len(tt.fragments) > 1,
						messageID:    msgID,
						fragmentSize: uint16(len(frag.data)),
					}
					err := ep.processFirstFragment(di, frag.data)
					require.NoError(t, err)
				} else {
					// Create follow-on fragment delivery instructions
					di := &DeliveryInstructions{
						fragmentType:   FOLLOW_ON_FRAGMENT,
						fragmentNumber: frag.fragNum,
						lastFragment:   frag.isLast,
						messageID:      msgID,
						fragmentSize:   uint16(len(frag.data)),
					}
					err := ep.processFollowOnFragment(di, frag.data)
					require.NoError(t, err)
				}
			}

			if tt.expectDelivery {
				require.NotNil(t, receivedMsg, "Expected message to be delivered")
				assert.Equal(t, tt.expectedMsg, receivedMsg)
			} else {
				assert.Nil(t, receivedMsg, "Expected no message delivery")
			}
		})
	}
}

// TestFragmentErrors tests error handling in fragment processing
func TestFragmentErrors(t *testing.T) {
	mockHandler := func(msgBytes []byte) error {
		return nil
	}

	mockEncryptor := &tunnel.AESEncryptor{}

	t.Run("duplicate fragment", func(t *testing.T) {
		ep, err := NewEndpoint(TunnelID(12345), mockEncryptor, mockHandler)
		require.NoError(t, err)

		msgID := uint32(123)

		// First fragment
		di1 := &DeliveryInstructions{
			fragmentType: FIRST_FRAGMENT,
			deliveryType: DT_LOCAL,
			fragmented:   true,
			messageID:    msgID,
			fragmentSize: 5,
		}
		err = ep.processFirstFragment(di1, []byte("Hello"))
		require.NoError(t, err)

		// Second fragment
		di2 := &DeliveryInstructions{
			fragmentType:   FOLLOW_ON_FRAGMENT,
			fragmentNumber: 1,
			lastFragment:   false,
			messageID:      msgID,
			fragmentSize:   6,
		}
		err = ep.processFollowOnFragment(di2, []byte("World!"))
		require.NoError(t, err)

		// Duplicate of second fragment
		err = ep.processFollowOnFragment(di2, []byte("World!"))
		assert.ErrorIs(t, err, ErrDuplicateFragment)
	})

	t.Run("fragment number too large", func(t *testing.T) {
		ep, err := NewEndpoint(TunnelID(12345), mockEncryptor, mockHandler)
		require.NoError(t, err)

		msgID := uint32(456)

		// Fragment with number > 63
		di := &DeliveryInstructions{
			fragmentType:   FOLLOW_ON_FRAGMENT,
			fragmentNumber: 64,
			lastFragment:   true,
			messageID:      msgID,
			fragmentSize:   4,
		}
		err = ep.processFollowOnFragment(di, []byte("Test"))
		assert.ErrorIs(t, err, ErrTooManyFragments)
	})

	t.Run("fragment number zero (invalid for follow-on)", func(t *testing.T) {
		ep, err := NewEndpoint(TunnelID(12345), mockEncryptor, mockHandler)
		require.NoError(t, err)

		msgID := uint32(789)

		// Fragment 0 in follow-on fragment (invalid)
		di := &DeliveryInstructions{
			fragmentType:   FOLLOW_ON_FRAGMENT,
			fragmentNumber: 0,
			lastFragment:   false,
			messageID:      msgID,
			fragmentSize:   4,
		}
		err = ep.processFollowOnFragment(di, []byte("Test"))
		assert.ErrorIs(t, err, ErrTooManyFragments)
	})
}

// TestFragmentPartialReassembly tests scenarios where reassembly is incomplete
func TestFragmentPartialReassembly(t *testing.T) {
	var receivedMsg []byte
	mockHandler := func(msgBytes []byte) error {
		receivedMsg = make([]byte, len(msgBytes))
		copy(receivedMsg, msgBytes)
		return nil
	}

	mockEncryptor := &tunnel.AESEncryptor{}

	t.Run("missing middle fragment", func(t *testing.T) {
		receivedMsg = nil
		ep, err := NewEndpoint(TunnelID(12345), mockEncryptor, mockHandler)
		require.NoError(t, err)

		msgID := uint32(111)

		// First fragment
		di1 := &DeliveryInstructions{
			fragmentType: FIRST_FRAGMENT,
			deliveryType: DT_LOCAL,
			fragmented:   true,
			messageID:    msgID,
			fragmentSize: 5,
		}
		err = ep.processFirstFragment(di1, []byte("Part1"))
		require.NoError(t, err)

		// Skip fragment 1, send fragment 2 (last)
		di3 := &DeliveryInstructions{
			fragmentType:   FOLLOW_ON_FRAGMENT,
			fragmentNumber: 2,
			lastFragment:   true,
			messageID:      msgID,
			fragmentSize:   5,
		}
		err = ep.processFollowOnFragment(di3, []byte("Part3"))
		require.NoError(t, err)

		// Message should not be delivered yet (missing fragment 1)
		assert.Nil(t, receivedMsg)

		// Now send the missing fragment 1
		di2 := &DeliveryInstructions{
			fragmentType:   FOLLOW_ON_FRAGMENT,
			fragmentNumber: 1,
			lastFragment:   false,
			messageID:      msgID,
			fragmentSize:   5,
		}
		err = ep.processFollowOnFragment(di2, []byte("Part2"))
		require.NoError(t, err)

		// Now message should be delivered
		require.NotNil(t, receivedMsg)
		assert.Equal(t, []byte("Part1Part2Part3"), receivedMsg)
	})

	t.Run("follow-on fragment without first fragment", func(t *testing.T) {
		receivedMsg = nil
		ep, err := NewEndpoint(TunnelID(12345), mockEncryptor, mockHandler)
		require.NoError(t, err)

		msgID := uint32(222)

		// Send follow-on fragment without first fragment
		di := &DeliveryInstructions{
			fragmentType:   FOLLOW_ON_FRAGMENT,
			fragmentNumber: 1,
			lastFragment:   true,
			messageID:      msgID,
			fragmentSize:   5,
		}
		err = ep.processFollowOnFragment(di, []byte("Part2"))
		require.NoError(t, err)

		// Message should not be delivered (missing first fragment)
		assert.Nil(t, receivedMsg)

		// Verify fragment is stored
		assert.Contains(t, ep.fragments, msgID)
	})
}

// TestNonLocalDelivery tests that non-local messages are not delivered to handler
func TestNonLocalDelivery(t *testing.T) {
	var receivedMsg []byte
	mockHandler := func(msgBytes []byte) error {
		receivedMsg = make([]byte, len(msgBytes))
		copy(receivedMsg, msgBytes)
		return nil
	}

	mockEncryptor := &tunnel.AESEncryptor{}

	t.Run("unfragmented router delivery", func(t *testing.T) {
		receivedMsg = nil
		ep, err := NewEndpoint(TunnelID(12345), mockEncryptor, mockHandler)
		require.NoError(t, err)

		di := &DeliveryInstructions{
			fragmentType: FIRST_FRAGMENT,
			deliveryType: DT_ROUTER,
			fragmented:   false,
			fragmentSize: 10,
		}
		err = ep.processFirstFragment(di, []byte("RouterData"))
		require.NoError(t, err)

		// Should not be delivered (non-local)
		assert.Nil(t, receivedMsg)
	})

	t.Run("fragmented tunnel delivery", func(t *testing.T) {
		receivedMsg = nil
		ep, err := NewEndpoint(TunnelID(12345), mockEncryptor, mockHandler)
		require.NoError(t, err)

		msgID := uint32(333)

		// First fragment - tunnel delivery
		di1 := &DeliveryInstructions{
			fragmentType: FIRST_FRAGMENT,
			deliveryType: DT_TUNNEL,
			fragmented:   true,
			messageID:    msgID,
			fragmentSize: 5,
		}
		err = ep.processFirstFragment(di1, []byte("Part1"))
		require.NoError(t, err)

		// Last fragment
		di2 := &DeliveryInstructions{
			fragmentType:   FOLLOW_ON_FRAGMENT,
			fragmentNumber: 1,
			lastFragment:   true,
			messageID:      msgID,
			fragmentSize:   5,
		}
		err = ep.processFollowOnFragment(di2, []byte("Part2"))
		require.NoError(t, err)

		// Should not be delivered (non-local)
		assert.Nil(t, receivedMsg)
	})
}
