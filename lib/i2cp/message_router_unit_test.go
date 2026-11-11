package i2cp

import (
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewMessageRouter verifies message router creation
func TestNewMessageRouter(t *testing.T) {
	// Create mock garlic encryptor
	garlicMgr := newMockGarlicEncryptor()

	// Create transport send function
	sentMessages := make(map[string]i2np.Message)
	transportSend := func(peerHash common.Hash, msg i2np.Message) error {
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

// TestRouteOutboundMessageSuccess verifies that a routed message leaves this
// router as encapsulated tunnel traffic addressed to hop 0, and not as a bare
// garlic I2NP message. That distinction is the I2P-002 defect: a bare message
// handed to a tunnel hop is unreadable by the network and identifies this
// router as the sender.
func TestRouteOutboundMessageSuccess(t *testing.T) {
	// Setup
	session, garlicMgr, transportSend, records, resolver := setupMessageRouterTest(t)
	router := NewMessageRouter(garlicMgr, transportSend)

	// Create destination and give it a lease so the message can be addressed.
	destHash, destPubKey := createTestDestAndPubKey()
	destGateway := createTestHash()
	const destTunnelID uint32 = 0x5EED1234
	resolver.add(destHash, destGateway, destTunnelID)
	router.SetLeaseResolver(resolver)

	// Test payload
	payload := []byte("test message payload")

	// Route message
	err := router.RouteOutboundMessage(RouteRequest{
		Session: session, MessageID: 0, DestinationHash: destHash, DestinationPubKey: destPubKey,
		Payload: payload, ExpirationMs: 0, StatusCallback: nil,
	})
	require.NoError(t, err)

	require.Len(t, *records, 1, "one tunnel record for a small payload")
	rec := (*records)[0]

	// The record went to a tunnel hop, never to the destination hash.
	assert.NotEqual(t, destHash, rec.hop, "must not send to the destination hash directly")

	// The TunnelData envelope is addressed to hop 0's receive tunnel ID, which
	// is the first hop's ID in the selected tunnel, not the destination's.
	assert.NotEqual(t, destTunnelID, rec.headerID,
		"envelope must address our hop 0, not the destination tunnel")

	// The lease resolver was consulted for the destination.
	assert.Equal(t, []common.Hash{destHash}, resolver.calls)

	// The record is a full 1028-byte layered tunnel message.
	assert.Len(t, rec.record, tunnel.TunnelMessageSize)
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

			sentMessages := make(map[string]i2np.Message)
			transportSend := func(peerHash common.Hash, msg i2np.Message) error {
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

// TestSendThroughTunnel verifies encapsulation through an explicitly selected
// tunnel: the message must leave as TunnelData records to hop 0.
func TestSendThroughTunnel(t *testing.T) {
	garlicMgr := newMockGarlicEncryptor()
	transportSend, records := captureTransport(t)
	router := NewMessageRouter(garlicMgr, transportSend)

	hopZero := createTestHash()
	state := &tunnel.TunnelState{
		ID:    tunnel.TunnelID(12345),
		Hops:  []common.Hash{hopZero, createTestHash()},
		State: tunnel.TunnelReady,
	}
	addRetainedLayers(t, state, tunnel.TunnelID(70000))

	msg := i2np.NewDataMessage([]byte("test"))
	target := LeaseTarget{GatewayHash: createTestHash(), TunnelID: 0xABC}

	err := router.SendThroughTunnel(state, msg, target)
	require.NoError(t, err)

	require.Len(t, *records, 1)
	assert.Equal(t, hopZero, (*records)[0].hop, "record must go to hop 0")
	assert.Equal(t, uint32(70000), (*records)[0].headerID, "envelope addresses hop 0's receive ID")
}

// TestSendThroughTunnelNoHops verifies error when tunnel has no hops
func TestSendThroughTunnelNoHops(t *testing.T) {
	garlicMgr := newMockGarlicEncryptor()
	transportSend, _ := captureTransport(t)
	router := NewMessageRouter(garlicMgr, transportSend)

	// Create tunnel with NO hops
	state := &tunnel.TunnelState{
		ID:    tunnel.TunnelID(12345),
		Hops:  []common.Hash{}, // Empty
		State: tunnel.TunnelReady,
	}

	msg := i2np.NewDataMessage([]byte("test"))

	err := router.SendThroughTunnel(state, msg, LeaseTarget{GatewayHash: createTestHash(), TunnelID: 1})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "tunnel hops required")
}

// TestSendThroughTunnelWithoutLayerKeys pins the fail-closed behaviour: a
// tunnel that never retained its build keys must not be able to send, rather
// than silently emitting something the network will discard.
func TestSendThroughTunnelWithoutLayerKeys(t *testing.T) {
	garlicMgr := newMockGarlicEncryptor()
	transportSend, records := captureTransport(t)
	router := NewMessageRouter(garlicMgr, transportSend)

	state := &tunnel.TunnelState{
		ID:    tunnel.TunnelID(12345),
		Hops:  []common.Hash{createTestHash()},
		State: tunnel.TunnelReady,
	}

	err := router.SendThroughTunnel(state, i2np.NewDataMessage([]byte("test")),
		LeaseTarget{GatewayHash: createTestHash(), TunnelID: 1})
	require.Error(t, err)
	assert.Empty(t, *records, "nothing may be sent when the tunnel cannot encrypt")
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

	sentMessages := make(map[string]i2np.Message)
	transportSend := func(peerHash common.Hash, msg i2np.Message) error {
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

	transportSend := func(peerHash common.Hash, msg i2np.Message) error {
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
