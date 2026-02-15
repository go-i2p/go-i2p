package i2cp

import (
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewMessageRouter verifies message router creation
func TestNewMessageRouter(t *testing.T) {
	// Create garlic session manager
	var privKey [32]byte
	copy(privKey[:], "test-private-key-32-bytes-pad")

	garlicMgr, err := i2np.NewGarlicSessionManager(privKey)
	require.NoError(t, err)

	// Create transport send function
	sentMessages := make(map[string]i2np.I2NPMessage)
	transportSend := func(peerHash common.Hash, msg i2np.I2NPMessage) error {
		key := string(peerHash[:])
		sentMessages[key] = msg
		return nil
	}

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
	destHash := createTestHash()
	var destPubKey [32]byte
	copy(destPubKey[:], "dest-public-key-32-bytes-pads")

	// Test payload
	payload := []byte("test message payload")

	// Route message
	err := router.RouteOutboundMessage(session, 0, destHash, destPubKey, payload, 0, nil)
	require.NoError(t, err)

	// Verify message was sent to gateway
	assert.Len(t, sentMessages, 1, "should send one message to gateway")

	// Verify sent message is a Garlic message
	for _, msg := range sentMessages {
		assert.Equal(t, i2np.I2NP_MESSAGE_TYPE_GARLIC, msg.Type())
	}
}

// TestRouteOutboundMessageNoPool verifies error when no outbound pool exists
func TestRouteOutboundMessageNoPool(t *testing.T) {
	// Setup session WITHOUT outbound pool
	session := createTestSessionWithoutPools(t)

	// Create garlic manager and router
	var privKey [32]byte
	garlicMgr, err := i2np.NewGarlicSessionManager(privKey)
	require.NoError(t, err)

	sentMessages := make(map[string]i2np.I2NPMessage)
	transportSend := func(peerHash common.Hash, msg i2np.I2NPMessage) error {
		sentMessages[string(peerHash[:])] = msg
		return nil
	}

	router := NewMessageRouter(garlicMgr, transportSend)

	// Attempt to route message
	destHash := createTestHash()
	var destPubKey [32]byte
	payload := []byte("test")

	err = router.RouteOutboundMessage(session, 0, destHash, destPubKey, payload, 0, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "outbound tunnel pool required")
}

// TestRouteOutboundMessageNoActiveTunnels verifies error when no active tunnels
func TestRouteOutboundMessageNoActiveTunnels(t *testing.T) {
	// Setup session with empty pool (no active tunnels)
	session := createTestSessionWithEmptyPools(t)

	// Create garlic manager and router
	var privKey [32]byte
	garlicMgr, err := i2np.NewGarlicSessionManager(privKey)
	require.NoError(t, err)

	sentMessages := make(map[string]i2np.I2NPMessage)
	transportSend := func(peerHash common.Hash, msg i2np.I2NPMessage) error {
		sentMessages[string(peerHash[:])] = msg
		return nil
	}

	router := NewMessageRouter(garlicMgr, transportSend)

	// Attempt to route message
	destHash := createTestHash()
	var destPubKey [32]byte
	payload := []byte("test")

	err = router.RouteOutboundMessage(session, 0, destHash, destPubKey, payload, 0, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "insufficient active outbound tunnels")
}

// TestSendThroughTunnel verifies sending through a specific tunnel
func TestSendThroughTunnel(t *testing.T) {
	// Setup
	var privKey [32]byte
	garlicMgr, err := i2np.NewGarlicSessionManager(privKey)
	require.NoError(t, err)

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
	err = router.SendThroughTunnel(tunnel, msg)
	require.NoError(t, err)

	// Verify message was sent
	assert.Len(t, sentMessages, 1)
}

// TestSendThroughTunnelNoHops verifies error when tunnel has no hops
func TestSendThroughTunnelNoHops(t *testing.T) {
	var privKey [32]byte
	garlicMgr, err := i2np.NewGarlicSessionManager(privKey)
	require.NoError(t, err)

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

	err = router.SendThroughTunnel(tunnel, msg)
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

	// Create garlic manager and router
	var privKey [32]byte
	copy(privKey[:], "test-private-key-32-bytes-pad")
	garlicMgr, err := i2np.NewGarlicSessionManager(privKey)
	require.NoError(t, err)

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
	destHash := createTestHash()
	var destPubKey [32]byte
	copy(destPubKey[:], "dest-public-key-32-bytes-pads")
	payload := []byte("test message payload")

	err = router.RouteOutboundMessage(session, 42, destHash, destPubKey, payload, 0, statusCallback)

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
	var privKey [32]byte
	garlicMgr, err := i2np.NewGarlicSessionManager(privKey)
	require.NoError(t, err)

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

func createTestSessionWithZeroHopTunnels(t *testing.T) *Session {
	config := DefaultSessionConfig()
	session := &Session{
		id:        1,
		config:    config,
		active:    true,
		createdAt: time.Now(),
	}

	selector := &mockPeerSelector{}
	session.outboundPool = tunnel.NewTunnelPool(selector)
	session.inboundPool = tunnel.NewTunnelPool(selector)

	// Add a zero-hop tunnel (no hops — this is the dangerous case)
	zeroHopTunnel := &tunnel.TunnelState{
		ID:        tunnel.TunnelID(9999),
		Hops:      []common.Hash{}, // Zero hops
		State:     tunnel.TunnelReady,
		CreatedAt: time.Now(),
	}
	session.outboundPool.AddTunnel(zeroHopTunnel)

	return session
}

// Helper functions

func setupMessageRouterTest(t *testing.T) (*Session, *i2np.GarlicSessionManager, TransportSendFunc, map[string]i2np.I2NPMessage) {
	// Create session with active tunnels using existing test helper
	server, session, _, outboundPool, cleanup := setupTestEnvironment(t)
	t.Cleanup(cleanup)

	// Ensure server is available (though we don't use it directly)
	_ = server

	// Add outbound tunnels to the pool (setupTestEnvironment only adds inbound tunnels)
	for i := 0; i < 2; i++ {
		tunnelID := tunnel.TunnelID(2000 + i)
		var gateway common.Hash
		copy(gateway[:], []byte("mock-outbound-gateway-hash-12345678901234567890"))
		gateway[31] = byte(i) // Make each gateway unique

		tunnelState := &tunnel.TunnelState{
			ID:        tunnelID,
			Hops:      []common.Hash{gateway},
			State:     tunnel.TunnelReady,
			CreatedAt: time.Now(),
		}
		outboundPool.AddTunnel(tunnelState)
	}

	// Create garlic session manager
	var privKey [32]byte
	copy(privKey[:], "test-private-key-32-bytes-pad")
	garlicMgr, err := i2np.NewGarlicSessionManager(privKey)
	require.NoError(t, err)

	// Create transport send function that records sent messages
	sentMessages := make(map[string]i2np.I2NPMessage)
	transportSend := func(peerHash common.Hash, msg i2np.I2NPMessage) error {
		key := string(peerHash[:])
		sentMessages[key] = msg
		return nil
	}

	return session, garlicMgr, transportSend, sentMessages
}

func createTestSessionWithoutPools(t *testing.T) *Session {
	// Create a minimal session without pools
	config := DefaultSessionConfig()
	session := &Session{
		id:        1,
		config:    config,
		active:    true,
		createdAt: time.Now(),
		// No pools set
	}
	return session
}

func createTestSessionWithEmptyPools(t *testing.T) *Session {
	// Create minimal session with empty pools
	config := DefaultSessionConfig()
	session := &Session{
		id:        1,
		config:    config,
		active:    true,
		createdAt: time.Now(),
	}

	// Create empty pools (no tunnels)
	selector := &mockPeerSelector{}
	session.outboundPool = tunnel.NewTunnelPool(selector)
	session.inboundPool = tunnel.NewTunnelPool(selector)

	return session
}

func createTestHash() common.Hash {
	var hash common.Hash
	for i := range hash {
		hash[i] = byte(i)
	}
	return hash
}
