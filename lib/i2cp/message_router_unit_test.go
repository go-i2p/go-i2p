package i2cp

import (
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/stretchr/testify/assert"
)

// TestNewMessageRouter verifies message router creation
func TestNewMessageRouter(t *testing.T) {
	// Create mock garlic encryptor
	garlicMgr := newMockGarlicEncryptor()

	// Create transport send function
	sentMessages := make(map[string]i2np.I2NPMessage)
	transportSend := func(peerHash common.Hash, msg i2np.I2NPMessage) error {
		key := string(peerHash[:])
		sentMessages[key] = msg
		return nil
	}
	_ = sentMessages

	// Create message router
	router := NewMessageRouter(garlicMgr, transportSend)
	assert.NotNil(t, router)
	assert.NotNil(t, router.garlicSessions)
	assert.NotNil(t, router.transportSend)
}

// TestRouteOutboundMessageSuccess verifies successful message routing
func TestRouteOutboundMessageSuccess(t *testing.T) {
	// Setup
	session, garlicMgr, transportSend, sentMessages := setupMessageRouterTest(t)
	router := NewMessageRouter(garlicMgr, transportSend)

	// Create destination
	destHash, destPubKey := createTestDestAndPubKey()

	// Test payload
	payload := []byte("test message payload")

	// Route message
	err := router.RouteOutboundMessage(RouteRequest{
		Session: session, MessageID: 0, DestinationHash: destHash, DestinationPubKey: destPubKey,
		Payload: payload, ExpirationMs: 0, StatusCallback: nil,
	})
	assert.NoError(t, err)

	// Verify message was sent to gateway
	assert.Len(t, sentMessages, 1, "should send one message to gateway")

	// Verify sent message is a Garlic message
	for _, msg := range sentMessages {
		assert.Equal(t, i2np.I2NPMessageTypeGarlic, msg.Type())
	}
}

// TestRouteOutboundMessageErrors verifies error cases for message routing
func TestRouteOutboundMessageErrors(t *testing.T) {
	tests := []struct {
		name        string
		makeSession func(t *testing.T) *Session
		wantErr     string
	}{
		{
			name:        "NoPool",
			makeSession: createTestSessionWithoutPools,
			wantErr:     "outbound tunnel pool required",
		},
		{
			name:        "NoActiveTunnels",
			makeSession: createTestSessionWithEmptyPools,
			wantErr:     "insufficient active outbound tunnels",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := tt.makeSession(t)
			garlicMgr := newMockGarlicEncryptor()

			sentMessages := make(map[string]i2np.I2NPMessage)
			transportSend := func(peerHash common.Hash, msg i2np.I2NPMessage) error {
				sentMessages[string(peerHash[:])] = msg
				return nil
			}

			router := NewMessageRouter(garlicMgr, transportSend)

			destHash := createTestHash()
			var destPubKey [32]byte
			payload := []byte("test")

			err := router.RouteOutboundMessage(RouteRequest{
				Session: session, MessageID: 0, DestinationHash: destHash, DestinationPubKey: destPubKey,
				Payload: payload, ExpirationMs: 0, StatusCallback: nil,
			})
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

// TestSendThroughTunnel verifies sending through a specific tunnel
func TestSendThroughTunnel(t *testing.T) {
	// Setup with mock garlic encryptor
	garlicMgr := newMockGarlicEncryptor()

	sentMessages := make(map[string]i2np.I2NPMessage)
	transportSend := func(peerHash common.Hash, msg i2np.I2NPMessage) error {
		sentMessages[string(peerHash[:])] = msg
		return nil
	}

	router := NewMessageRouter(garlicMgr, transportSend)

	// Create tunnel with hops
	tunnel := &tunnel.TunnelState{
		ID:    tunnel.TunnelID(12345),
		Hops:  []common.Hash{createTestHash(), createTestHash()},
		State: tunnel.TunnelReady,
	}

	// Create test message
	msg := i2np.NewDataMessage([]byte("test"))

	// Send through tunnel
	err := router.SendThroughTunnel(tunnel, msg)
	assert.NoError(t, err)

	// Verify message was sent
	assert.Len(t, sentMessages, 1)
}

// TestSendThroughTunnelNoHops verifies error when tunnel has no hops
func TestSendThroughTunnelNoHops(t *testing.T) {
	garlicMgr := newMockGarlicEncryptor()

	transportSend := func(peerHash common.Hash, msg i2np.I2NPMessage) error {
		return nil
	}

	router := NewMessageRouter(garlicMgr, transportSend)

	// Create tunnel with NO hops
	tunnel := &tunnel.TunnelState{
		ID:    tunnel.TunnelID(12345),
		Hops:  []common.Hash{}, // Empty
		State: tunnel.TunnelReady,
	}

	msg := i2np.NewDataMessage([]byte("test"))

	err := router.SendThroughTunnel(tunnel, msg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "tunnel hops required")
}

// TestRouteOutboundMessageZeroHopTunnelRejected verifies that zero-hop tunnels
// are rejected for I2CP client traffic to prevent anonymity compromise.
// This is the fix for the critical bug where zero-hop tunnels sent messages
// directly to the destination hash, bypassing I2P's anonymity model.
func TestRouteOutboundMessageZeroHopTunnelRejected(t *testing.T) {
	// Create a session with only zero-hop tunnels (no hops)
	session := createTestSessionWithZeroHopTunnels(t)

	// Create mock garlic encryptor and router
	garlicMgr := newMockGarlicEncryptor()

	sentMessages := make(map[string]i2np.I2NPMessage)
	transportSend := func(peerHash common.Hash, msg i2np.I2NPMessage) error {
		sentMessages[string(peerHash[:])] = msg
		return nil
	}

	router := NewMessageRouter(garlicMgr, transportSend)

	// Track status callback invocations
	var receivedStatus uint8
	statusCallback := func(messageID uint32, statusCode uint8, messageSize, nonce uint32) {
		receivedStatus = statusCode
	}

	// Attempt to route message through zero-hop tunnel
	destHash, destPubKey := createTestDestAndPubKey()
	payload := []byte("test message payload")

	err := router.RouteOutboundMessage(RouteRequest{
		Session: session, MessageID: 42, DestinationHash: destHash, DestinationPubKey: destPubKey,
		Payload: payload, ExpirationMs: 0, StatusCallback: statusCallback,
	})

	// Verify the message was rejected
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "zero-hop tunnels are not supported")
	assert.Contains(t, err.Error(), "anonymity requires at least one hop")

	// Verify no messages were sent through transport (critical: no IP leak)
	assert.Empty(t, sentMessages, "no messages should be sent through transport for zero-hop tunnels")

	// Verify status callback reported no tunnels
	assert.Equal(t, uint8(MessageStatusNoTunnels), receivedStatus,
		"status callback should report MessageStatusNoTunnels for zero-hop tunnel rejection")
}

// TestValidateAndSelectTunnelZeroHopRejection tests the validateAndSelectTunnel
// method directly to ensure zero-hop tunnels are consistently rejected.
func TestValidateAndSelectTunnelZeroHopRejection(t *testing.T) {
	garlicMgr := newMockGarlicEncryptor()

	transportSend := func(peerHash common.Hash, msg i2np.I2NPMessage) error {
		return nil
	}

	router := NewMessageRouter(garlicMgr, transportSend)

	// Create session with zero-hop tunnel
	session := createTestSessionWithZeroHopTunnels(t)
	destHash := createTestHash()

	// validateAndSelectTunnel should reject the zero-hop tunnel
	selectedTunnel, err := router.validateAndSelectTunnel(session, destHash)
	assert.Error(t, err)
	assert.Nil(t, selectedTunnel)
	assert.Contains(t, err.Error(), "zero-hop tunnels are not supported")
}

// =============================================================================
// MESSAGE ROUTER TESTS
// =============================================================================

// TestMessageRouter_StatusCallbackInvoked verifies status callbacks are called.
func TestMessageRouter_StatusCallbackInvoked(t *testing.T) {
	router := NewMessageRouter(nil, nil)

	// Without tunnel pool, should fail with NoTunnels status
	session, _ := NewSession(1, nil, nil)
	defer session.Stop()

	var receivedStatus uint8
	callback := func(messageID uint32, statusCode uint8, messageSize, nonce uint32) {
		receivedStatus = statusCode
	}

	var destHash common.Hash
	var destKey [32]byte

	err := router.RouteOutboundMessage(RouteRequest{
		Session: session, MessageID: 1, DestinationHash: destHash, DestinationPubKey: destKey,
		Payload: []byte("test"), ExpirationMs: 0, StatusCallback: callback,
	})
	if err == nil {
		t.Error("Expected error without outbound pool")
	}

	if receivedStatus != MessageStatusNoTunnels {
		t.Errorf("Status = %d, want %d (NoTunnels)", receivedStatus, MessageStatusNoTunnels)
	}
}
