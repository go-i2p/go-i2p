package router

import (
	"github.com/go-i2p/crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"testing"
	"time"

	"github.com/go-i2p/crypto/tunnel"
	"github.com/go-i2p/go-i2p/lib/i2cp"
	"github.com/go-i2p/go-i2p/lib/i2np"
	tunnelpkg "github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewInboundMessageHandler tests handler creation
func TestNewInboundMessageHandler(t *testing.T) {
	sessionManager := i2cp.NewSessionManager()
	handler := NewInboundMessageHandler(sessionManager)

	assert.NotNil(t, handler)
	assert.NotNil(t, handler.tunnelSessions)
	assert.NotNil(t, handler.sessionManager)
	assert.Equal(t, 0, handler.GetTunnelCount())
}

// TestRegisterTunnel tests tunnel registration
func TestRegisterTunnel(t *testing.T) {
	sessionManager := i2cp.NewSessionManager()
	handler := NewInboundMessageHandler(sessionManager)

	// Create a mock endpoint with a simple handler
	mockDecryptor := &mockTunnelEncryptor{}
	endpoint, err := tunnelpkg.NewEndpoint(123, mockDecryptor, func(msgBytes []byte) error {
		return nil
	})
	require.NoError(t, err)

	// Register tunnel
	tunnelID := tunnelpkg.TunnelID(12345)
	sessionID := uint16(1)

	err = handler.RegisterTunnel(tunnelID, sessionID, endpoint)
	assert.NoError(t, err)
	assert.Equal(t, 1, handler.GetTunnelCount())

	// Verify registration
	retrievedSessionID, exists := handler.GetTunnelSession(tunnelID)
	assert.True(t, exists)
	assert.Equal(t, sessionID, retrievedSessionID)
}

// TestRegisterTunnelDuplicate tests duplicate tunnel registration
func TestRegisterTunnelDuplicate(t *testing.T) {
	sessionManager := i2cp.NewSessionManager()
	handler := NewInboundMessageHandler(sessionManager)

	mockDecryptor := &mockTunnelEncryptor{}
	endpoint, err := tunnelpkg.NewEndpoint(123, mockDecryptor, func(msgBytes []byte) error {
		return nil
	})
	require.NoError(t, err)

	tunnelID := tunnelpkg.TunnelID(12345)
	sessionID := uint16(1)

	// Register once
	err = handler.RegisterTunnel(tunnelID, sessionID, endpoint)
	require.NoError(t, err)

	// Try to register again
	err = handler.RegisterTunnel(tunnelID, sessionID, endpoint)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already registered")
}

// TestUnregisterTunnel tests tunnel unregistration
func TestUnregisterTunnel(t *testing.T) {
	sessionManager := i2cp.NewSessionManager()
	handler := NewInboundMessageHandler(sessionManager)

	mockDecryptor := &mockTunnelEncryptor{}
	endpoint, err := tunnelpkg.NewEndpoint(123, mockDecryptor, func(msgBytes []byte) error {
		return nil
	})
	require.NoError(t, err)

	tunnelID := tunnelpkg.TunnelID(12345)
	sessionID := uint16(1)

	// Register and then unregister
	err = handler.RegisterTunnel(tunnelID, sessionID, endpoint)
	require.NoError(t, err)
	assert.Equal(t, 1, handler.GetTunnelCount())

	handler.UnregisterTunnel(tunnelID)
	assert.Equal(t, 0, handler.GetTunnelCount())

	_, exists := handler.GetTunnelSession(tunnelID)
	assert.False(t, exists)
}

// TestHandleTunnelDataUnregistered tests handling messages for unregistered tunnels
func TestHandleTunnelDataUnregistered(t *testing.T) {
	sessionManager := i2cp.NewSessionManager()
	handler := NewInboundMessageHandler(sessionManager)

	// Create a TunnelData message for an unregistered tunnel
	tunnelData := createMockTunnelDataMessage(99999)

	// Should not error, just log and return
	err := handler.HandleTunnelData(tunnelData)
	assert.NoError(t, err)
}

// TestHandleTunnelDataInvalidMessage tests handling invalid messages
func TestHandleTunnelDataInvalidMessage(t *testing.T) {
	sessionManager := i2cp.NewSessionManager()
	handler := NewInboundMessageHandler(sessionManager)

	// Create a non-TunnelCarrier message
	dataMsg := createMockDataMessage()

	err := handler.HandleTunnelData(dataMsg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "TunnelCarrier")
}

// TestHandleTunnelDataSuccess tests successful message handling
func TestHandleTunnelDataSuccess(t *testing.T) {
	sessionManager := i2cp.NewSessionManager()
	handler := NewInboundMessageHandler(sessionManager)

	// Create an I2CP session
	session, err := sessionManager.CreateSession(nil, i2cp.DefaultSessionConfig())
	require.NoError(t, err)

	sessionID := session.ID()
	tunnelID := tunnelpkg.TunnelID(12345)

	// Track whether message handler was called
	handlerCalled := false
	messageReceived := make(chan []byte, 10) // Buffered to handle multiple delivery instructions

	mockDecryptor := &mockTunnelEncryptor{
		decryptFunc: func(data []byte) ([]byte, error) {
			// Return a valid decrypted tunnel message
			// Format: [tunnel ID (4)][IV (16)][checksum (4)][data with zero separator and delivery instructions]
			// Important: Only return the exact size needed to avoid spurious zero-byte delivery instructions
			decrypted := make([]byte, 38) // Exactly enough for: tunnel_id(4) + IV(16) + checksum(4) + zero(1) + flags(1) + size(2) + message(10)

			// Tunnel ID (first 4 bytes)
			binary.BigEndian.PutUint32(decrypted[0:4], uint32(tunnelID))

			// IV (bytes 4-20) - use random for realism
			rand.Read(decrypted[4:20])
			iv := decrypted[4:20]

			// Set zero byte separator at position 24
			decrypted[24] = 0x00

			// Add delivery instruction (local delivery, message size 10 bytes)
			decrypted[25] = 0x00                             // Flags: local delivery (0x00)
			binary.BigEndian.PutUint16(decrypted[26:28], 10) // Message size

			// Add 10 bytes of message data
			copy(decrypted[28:38], []byte("testmessage")[:10])

			// Calculate checksum: first 4 bytes of SHA256(data_after_checksum + IV)
			dataAfterChecksum := decrypted[24:]
			checksumData := append(dataAfterChecksum, iv...)
			hash := sha256.Sum256(checksumData)
			copy(decrypted[20:24], hash[:4])

			return decrypted, nil
		},
	}

	endpoint, err := tunnelpkg.NewEndpoint(tunnelID, mockDecryptor, func(msgBytes []byte) error {
		handlerCalled = true
		messageReceived <- msgBytes
		// Queue to session
		return session.QueueIncomingMessage(msgBytes)
	})
	require.NoError(t, err)

	// Register tunnel
	err = handler.RegisterTunnel(tunnelID, sessionID, endpoint)
	require.NoError(t, err)

	// Create TunnelData message
	tunnelData := createMockTunnelDataMessage(tunnelID)

	// Process message
	err = handler.HandleTunnelData(tunnelData)
	assert.NoError(t, err)

	// Verify message handler was called
	select {
	case msg := <-messageReceived:
		assert.True(t, handlerCalled)
		assert.NotNil(t, msg)
		assert.Equal(t, 10, len(msg))
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Message handler was not called")
	}

	// Verify message was queued to session
	receivedMsg, err := session.ReceiveMessage()
	assert.NoError(t, err)
	assert.NotNil(t, receivedMsg)
	assert.Equal(t, 10, len(receivedMsg.Payload))
}

// TestCreateMessageHandler tests message handler creation
func TestCreateMessageHandler(t *testing.T) {
	sessionManager := i2cp.NewSessionManager()
	handler := NewInboundMessageHandler(sessionManager)

	// Create session
	session, err := sessionManager.CreateSession(nil, i2cp.DefaultSessionConfig())
	require.NoError(t, err)

	// Create handler
	msgHandler := handler.createMessageHandler(session.ID())
	assert.NotNil(t, msgHandler)

	// Test handler with message
	testMsg := []byte("test message payload")
	err = msgHandler(testMsg)
	assert.NoError(t, err)

	// Verify message was queued
	receivedMsg, err := session.ReceiveMessage()
	assert.NoError(t, err)
	assert.NotNil(t, receivedMsg)
	assert.Equal(t, testMsg, receivedMsg.Payload)
}

// TestCreateMessageHandlerInvalidSession tests handler with invalid session
func TestCreateMessageHandlerInvalidSession(t *testing.T) {
	sessionManager := i2cp.NewSessionManager()
	handler := NewInboundMessageHandler(sessionManager)

	// Create handler for non-existent session
	msgHandler := handler.createMessageHandler(9999)

	// Should error
	err := msgHandler([]byte("test"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestConcurrentTunnelRegistration tests concurrent tunnel operations
func TestConcurrentTunnelRegistration(t *testing.T) {
	sessionManager := i2cp.NewSessionManager()
	handler := NewInboundMessageHandler(sessionManager)

	// Create 10 tunnels concurrently
	const numTunnels = 10
	done := make(chan bool, numTunnels)

	for i := 0; i < numTunnels; i++ {
		go func(id int) {
			mockDecryptor := &mockTunnelEncryptor{}
			endpoint, err := tunnelpkg.NewEndpoint(tunnelpkg.TunnelID(id), mockDecryptor, func(msgBytes []byte) error {
				return nil
			})
			if err != nil {
				t.Errorf("Failed to create endpoint: %v", err)
				done <- false
				return
			}

			err = handler.RegisterTunnel(tunnelpkg.TunnelID(id), uint16(id), endpoint)
			if err != nil {
				t.Errorf("Failed to register tunnel: %v", err)
				done <- false
				return
			}
			done <- true
		}(i)
	}

	// Wait for all registrations
	for i := 0; i < numTunnels; i++ {
		success := <-done
		assert.True(t, success)
	}

	assert.Equal(t, numTunnels, handler.GetTunnelCount())
}

// Helper functions and mocks

// mockTunnelEncryptor is a mock implementation of tunnel.TunnelEncryptor
type mockTunnelEncryptor struct {
	decryptFunc func([]byte) ([]byte, error)
}

func (m *mockTunnelEncryptor) Encrypt(data []byte) ([]byte, error) {
	return data, nil
}

func (m *mockTunnelEncryptor) Decrypt(data []byte) ([]byte, error) {
	if m.decryptFunc != nil {
		return m.decryptFunc(data)
	}
	return data, nil
}

func (m *mockTunnelEncryptor) Type() tunnel.TunnelEncryptionType {
	return tunnel.TunnelEncryptionAES // Return AES type for tests
}

// createMockTunnelDataMessage creates a mock TunnelData I2NP message
func createMockTunnelDataMessage(tunnelID tunnelpkg.TunnelID) i2np.I2NPMessage {
	var data [1024]byte

	// Set tunnel ID
	binary.BigEndian.PutUint32(data[0:4], uint32(tunnelID))

	// Fill with random encrypted data
	rand.Read(data[4:])

	// Create TunnelData message
	msg := i2np.NewTunnelDataMessage(data)
	return msg
}

// createMockDataMessage creates a mock Data I2NP message (not TunnelCarrier)
func createMockDataMessage() i2np.I2NPMessage {
	payload := []byte("test payload data")
	return i2np.NewDataMessage(payload)
}
