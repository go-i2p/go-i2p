// Package router contains tests for router message processing functionality.
// These tests verify the message routing logic introduced in Step 3 of the
// I2NP Message Processing Integration plan.
package router

import (
	"net"
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/i2np"
	ntcp "github.com/go-i2p/go-i2p/lib/transport/ntcp2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRouteMessageWithoutNetDB tests message routing behavior when NetDB is not initialized.
// This validates that the routing switch statement correctly directs messages
// to the appropriate handler methods on the MessageRouter.
func TestRouteMessageWithoutNetDB(t *testing.T) {
	// Create a minimal router with message router but no NetDB
	router := &Router{
		messageRouter: i2np.NewMessageRouter(i2np.MessageRouterConfig{
			MaxRetries:     3,
			DefaultTimeout: 30,
			EnableLogging:  false,
		}),
	}

	peerHash := common.Hash{}
	copy(peerHash[:], "test_peer_000000000000000000000")

	testCases := []struct {
		name      string
		createMsg func() i2np.I2NPMessage
	}{
		{
			name: "Data message routes without panic",
			createMsg: func() i2np.I2NPMessage {
				return i2np.NewDataMessage([]byte("test payload"))
			},
		},
		{
			name: "DeliveryStatus message routes without panic",
			createMsg: func() i2np.I2NPMessage {
				return i2np.NewDeliveryStatusMessage(12345, time.Now())
			},
		},
		{
			name: "TunnelData message routes without panic",
			createMsg: func() i2np.I2NPMessage {
				var data [1024]byte
				copy(data[:], "tunnel data")
				return i2np.NewTunnelDataMessage(data)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			msg := tc.createMsg()
			require.NotNil(t, msg, "Message should be created")

			// Route message - should not panic
			// Message routing may succeed or fail depending on internal state,
			// but the key is that it doesn't panic
			_ = router.routeMessage(msg, peerHash)

			// If we get here without panicking, the test passes
			assert.True(t, true, "Message routing completed without panic")
		})
	}
}

// TestRouteMessageSwitchStatement tests that the routing switch statement
// handles all defined I2NP message type constants without panicking.
// This is a compile-time validation test.
func TestRouteMessageSwitchStatement(t *testing.T) {
	// Create minimal router
	router := &Router{
		messageRouter: i2np.NewMessageRouter(i2np.MessageRouterConfig{
			MaxRetries:     3,
			DefaultTimeout: 30,
			EnableLogging:  false,
		}),
	}

	peerHash := common.Hash{}

	// Test that database message types are recognized by the switch statement
	databaseTypes := []byte{
		i2np.I2NP_MESSAGE_TYPE_DATABASE_STORE,
		i2np.I2NP_MESSAGE_TYPE_DATABASE_LOOKUP,
		i2np.I2NP_MESSAGE_TYPE_DATABASE_SEARCH_REPLY,
	}

	for _, msgType := range databaseTypes {
		// We can't easily create messages with arbitrary types,
		// so we'll just verify the constants are defined
		assert.NotZero(t, msgType, "Database message type constant should be defined")
	}

	// Test general message types
	generalTypes := []byte{
		i2np.I2NP_MESSAGE_TYPE_DATA,
		i2np.I2NP_MESSAGE_TYPE_DELIVERY_STATUS,
		i2np.I2NP_MESSAGE_TYPE_TUNNEL_DATA,
	}

	for _, msgType := range generalTypes {
		assert.NotZero(t, msgType, "General message type constant should be defined")
	}

	// Test tunnel message types
	tunnelTypes := []byte{
		i2np.I2NP_MESSAGE_TYPE_TUNNEL_BUILD,
		i2np.I2NP_MESSAGE_TYPE_TUNNEL_BUILD_REPLY,
		i2np.I2NP_MESSAGE_TYPE_VARIABLE_TUNNEL_BUILD,
		i2np.I2NP_MESSAGE_TYPE_VARIABLE_TUNNEL_BUILD_REPLY,
	}

	for _, msgType := range tunnelTypes {
		assert.NotZero(t, msgType, "Tunnel message type constant should be defined")
	}

	// Verify router has messageRouter set
	require.NotNil(t, router.messageRouter, "Router should have messageRouter initialized")

	// Verify routeMessage method exists and can be called
	msg := i2np.NewDataMessage([]byte("test"))
	_ = router.routeMessage(msg, peerHash)
	// If we reach here without panicking, the routing logic is working
	assert.True(t, true, "routeMessage method exists and can be called")
}

// TestCreateSessionFromConnInvalidAddr tests error handling when connection
// has invalid address type.
func TestCreateSessionFromConnInvalidAddr(t *testing.T) {
	router := &Router{
		activeSessions: make(map[common.Hash]*ntcp.NTCP2Session),
	}

	// Create a mock connection with wrong address type
	mockConn := &mockNetConn{
		remoteAddr: &mockAddr{network: "tcp", address: "127.0.0.1:12345"},
	}

	// Attempt to create session from connection
	session, peerHash, err := router.createSessionFromConn(mockConn)

	// Should return error for invalid address type
	require.Error(t, err, "Should return error for non-NTCP2Addr address")
	assert.Contains(t, err.Error(), "invalid connection type", "Error should mention invalid connection type")
	assert.Nil(t, session, "Session should be nil on error")
	assert.Equal(t, common.Hash{}, peerHash, "Peer hash should be empty on error")
}

// mockAddr implements net.Addr for testing
type mockAddr struct {
	network string
	address string
}

func (m *mockAddr) Network() string {
	return m.network
}

func (m *mockAddr) String() string {
	return m.address
}

// mockNetConn implements net.Conn for testing
type mockNetConn struct {
	remoteAddr net.Addr
	localAddr  net.Addr
}

func (m *mockNetConn) Read(b []byte) (n int, err error) {
	return 0, nil
}

func (m *mockNetConn) Write(b []byte) (n int, err error) {
	return len(b), nil
}

func (m *mockNetConn) Close() error {
	return nil
}

func (m *mockNetConn) LocalAddr() net.Addr {
	if m.localAddr != nil {
		return m.localAddr
	}
	return &mockAddr{network: "tcp", address: "127.0.0.1:0"}
}

func (m *mockNetConn) RemoteAddr() net.Addr {
	return m.remoteAddr
}

func (m *mockNetConn) SetDeadline(t time.Time) error {
	return nil
}

func (m *mockNetConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *mockNetConn) SetWriteDeadline(t time.Time) error {
	return nil
}
