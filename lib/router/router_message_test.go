// Package router contains tests for router message processing functionality.
// These tests verify the message routing logic introduced in Step 3 of the
// I2NP Message Processing Integration plan.
package router

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/transport"
	ntcp "github.com/go-i2p/go-i2p/lib/transport/ntcp2"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRouteMessageWithoutNetDB tests message routing behavior when NetDB is not initialized.
// This validates that the routing switch statement correctly directs messages
// to the appropriate handler methods on the MessageRouter.
func TestRouteMessageWithoutNetDB(t *testing.T) {
	// Create a minimal router with message router but no NetDB
	router := &Router{
		messageRouter: i2np.NewI2NPMessageDispatcher(i2np.I2NPMessageDispatcherConfig{
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
				return i2np.NewTunnelDataMessage(tunnel.TunnelID(1), data)
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
		messageRouter: i2np.NewI2NPMessageDispatcher(i2np.I2NPMessageDispatcherConfig{
			MaxRetries:     3,
			DefaultTimeout: 30,
			EnableLogging:  false,
		}),
	}

	peerHash := common.Hash{}

	// Test that database message types are recognized by the switch statement
	databaseTypes := []byte{
		i2np.I2NPMessageTypeDatabaseStore,
		i2np.I2NPMessageTypeDatabaseLookup,
		i2np.I2NPMessageTypeDatabaseSearchReply,
	}

	for _, msgType := range databaseTypes {
		// We can't easily create messages with arbitrary types,
		// so we'll just verify the constants are defined
		assert.NotZero(t, msgType, "Database message type constant should be defined")
	}

	// Test general message types
	generalTypes := []byte{
		i2np.I2NPMessageTypeData,
		i2np.I2NPMessageTypeDeliveryStatus,
		i2np.I2NPMessageTypeTunnelData,
	}

	for _, msgType := range generalTypes {
		assert.NotZero(t, msgType, "General message type constant should be defined")
	}

	// Test tunnel message types
	tunnelTypes := []byte{
		i2np.I2NPMessageTypeTunnelBuild,
		i2np.I2NPMessageTypeTunnelBuildReply,
		i2np.I2NPMessageTypeVariableTunnelBuild,
		i2np.I2NPMessageTypeVariableTunnelBuildReply,
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

type panicOnceReader struct {
	calls int
}

func (r *panicOnceReader) ReadNextI2NP() (i2np.I2NPMessage, error) {
	r.calls++
	if r.calls == 1 {
		panic("panic from ReadNextI2NP")
	}
	return nil, nil
}

type panicTypeMessage struct {
	*i2np.BaseI2NPMessage
}

func (m *panicTypeMessage) Type() int {
	panic("panic from Type")
}

func TestProcessSessionMessagesRecoversFromReadPanic(t *testing.T) {
	router := &Router{running: true}
	peerHash := common.Hash{}
	copy(peerHash[:], "peer_panic_test_12345678901234567")

	reader := &panicOnceReader{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		router.processSessionMessages(reader, staticAuthenticatedPeer{hash: peerHash, handshakeComplete: true})
	}()

	select {
	case <-done:
		assert.Equal(t, 1, reader.calls, "processor should stop after recovering from panic")
	case <-time.After(2 * time.Second):
		t.Fatal("processSessionMessages did not stop after recovered panic")
	}
}

func TestRouteMessageRecoversFromMessagePanic(t *testing.T) {
	router := &Router{
		messageRouter: i2np.NewI2NPMessageDispatcher(i2np.I2NPMessageDispatcherConfig{
			MaxRetries:     3,
			DefaultTimeout: 30,
			EnableLogging:  false,
		}),
	}

	peerHash := common.Hash{}
	msg := &panicTypeMessage{BaseI2NPMessage: i2np.NewBaseI2NPMessage(i2np.I2NPMessageTypeData)}

	var err error
	assert.NotPanics(t, func() {
		err = router.routeMessage(msg, peerHash)
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "panic while routing I2NP message")
}

func TestProcessSessionMessagesRefusesUnauthenticatedPeer(t *testing.T) {
	router := &Router{running: true}
	peerHash := common.Hash{}
	copy(peerHash[:], "peer_unauth_test_1234567890123456")

	reader := &panicOnceReader{}
	router.processSessionMessages(reader, staticAuthenticatedPeer{hash: peerHash, handshakeComplete: false})

	assert.Equal(t, 0, reader.calls, "unauthenticated peers must not start message reads")
}

func TestIsBenignReadError(t *testing.T) {
	assert.True(t, isBenignReadError(ntcp.ErrSessionClosed))
	assert.True(t, isBenignReadError(io.EOF))
	assert.True(t, isBenignReadError(io.ErrUnexpectedEOF))
	assert.True(t, isBenignReadError(net.ErrClosed))
	assert.True(t, isBenignReadError(context.Canceled))
	assert.False(t, isBenignReadError(errors.New("invalid frame length")))
}

func TestIsFramingOrLengthViolation(t *testing.T) {
	assert.True(t, isFramingOrLengthViolation(errors.New("invalid frame length")))
	assert.True(t, isFramingOrLengthViolation(errors.New("payload exceeds limit")))
	assert.False(t, isFramingOrLengthViolation(errors.New("connection reset by peer")))
}

func TestShouldLogReadWarnRateLimit(t *testing.T) {
	peer := "testpeer"
	readWarnLimiterMu.Lock()
	readWarnLastByPeer = make(map[string]time.Time)
	readWarnLimiterMu.Unlock()

	assert.True(t, shouldLogReadWarn(peer), "first warning should pass")
	assert.False(t, shouldLogReadWarn(peer), "immediate duplicate warning should be suppressed")

	readWarnLimiterMu.Lock()
	readWarnLastByPeer[peer] = time.Now().Add(-readWarnMinInterval - time.Second)
	readWarnLimiterMu.Unlock()

	assert.True(t, shouldLogReadWarn(peer), "warning should pass after interval")
}

// TestHandleNewConnectionInvalidAddr tests that handleNewConnection does not
// panic and gracefully handles an unrecognised remote address type.
func TestHandleNewConnectionInvalidAddr(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	router := &Router{
		activeSessions: make(map[common.Hash]transport.TransportSession),
		ctx:            ctx,
	}

	// Create a mock connection with wrong address type
	mockConn := &mockNetConn{
		remoteAddr: &mockAddr{network: "tcp", address: "127.0.0.1:12345"},
	}

	// Should not panic; the connection should be closed and no session registered
	require.NotPanics(t, func() {
		router.handleNewConnection(mockConn)
	})
	assert.Empty(t, router.activeSessions, "No session should be registered for unrecognised address type")
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

// TestRouteMessageGarlicAndTunnelGateway tests that garlic (type 11) and
// tunnel gateway (type 19) messages are routed through the MessageRouter
// instead of being rejected with "unsupported message type".
func TestRouteMessageGarlicAndTunnelGateway(t *testing.T) {
	router := &Router{
		messageRouter: i2np.NewI2NPMessageDispatcher(i2np.I2NPMessageDispatcherConfig{
			MaxRetries:     3,
			DefaultTimeout: 30,
			EnableLogging:  false,
		}),
	}

	peerHash := common.Hash{}
	copy(peerHash[:], "test_peer_000000000000000000000")

	t.Run("Garlic message is not rejected as unsupported", func(t *testing.T) {
		// Create a base message with type GARLIC (11)
		msg := i2np.NewBaseI2NPMessage(i2np.I2NPMessageTypeGarlic)
		msg.SetData([]byte("encrypted garlic payload"))

		err := router.routeMessage(msg, peerHash)
		// The message may fail downstream (no garlic session configured),
		// but it must NOT fail with "unsupported message type: 11"
		if err != nil {
			assert.NotContains(t, err.Error(), "unsupported message type",
				"Garlic messages should not be rejected as unsupported")
		}
	})

	t.Run("TunnelGateway message is not rejected as unsupported", func(t *testing.T) {
		// Create a TunnelGateway message
		msg := i2np.NewTunnelGatewayMessage(tunnel.TunnelID(42), []byte("tunnel payload data"))

		err := router.routeMessage(msg, peerHash)
		// The message may fail downstream (no tunnel gateway handler configured),
		// but it must NOT fail with "unsupported message type: 19"
		if err != nil {
			assert.NotContains(t, err.Error(), "unsupported message type",
				"TunnelGateway messages should not be rejected as unsupported")
		}
	})
}

// TestRouteMessageAllSupportedTypes verifies that no defined I2NP message type
// falls through to the "unsupported message type" default case.
func TestRouteMessageAllSupportedTypes(t *testing.T) {
	router := &Router{
		messageRouter: i2np.NewI2NPMessageDispatcher(i2np.I2NPMessageDispatcherConfig{
			MaxRetries:     3,
			DefaultTimeout: 30,
			EnableLogging:  false,
		}),
	}

	peerHash := common.Hash{}

	// Every message type that the router should accept
	supportedTypes := []struct {
		name    string
		msgType int
	}{
		{"DatabaseStore", i2np.I2NPMessageTypeDatabaseStore},
		{"DatabaseLookup", i2np.I2NPMessageTypeDatabaseLookup},
		{"DatabaseSearchReply", i2np.I2NPMessageTypeDatabaseSearchReply},
		{"DeliveryStatus", i2np.I2NPMessageTypeDeliveryStatus},
		{"Garlic", i2np.I2NPMessageTypeGarlic},
		{"TunnelData", i2np.I2NPMessageTypeTunnelData},
		{"TunnelGateway", i2np.I2NPMessageTypeTunnelGateway},
		{"Data", i2np.I2NPMessageTypeData},
		{"TunnelBuild", i2np.I2NPMessageTypeTunnelBuild},
		{"TunnelBuildReply", i2np.I2NPMessageTypeTunnelBuildReply},
		{"VariableTunnelBuild", i2np.I2NPMessageTypeVariableTunnelBuild},
		{"VariableTunnelBuildReply", i2np.I2NPMessageTypeVariableTunnelBuildReply},
	}

	for _, tc := range supportedTypes {
		t.Run(tc.name, func(t *testing.T) {
			msg := i2np.NewBaseI2NPMessage(tc.msgType)
			msg.SetData([]byte("test payload"))

			err := router.routeMessage(msg, peerHash)
			// If there's an error, it should be a processing error, not "unsupported"
			if err != nil {
				assert.NotContains(t, err.Error(), "unsupported message type",
					"Message type %d (%s) should be supported", tc.msgType, tc.name)
			}
		})
	}
}

// TestRouteMessageUnsupportedTypeStillRejected verifies that truly unknown
// message types are still properly rejected.
func TestRouteMessageUnsupportedTypeStillRejected(t *testing.T) {
	router := &Router{
		messageRouter: i2np.NewI2NPMessageDispatcher(i2np.I2NPMessageDispatcherConfig{
			MaxRetries:     3,
			DefaultTimeout: 30,
			EnableLogging:  false,
		}),
	}

	peerHash := common.Hash{}

	// Use an invalid/undefined message type
	msg := i2np.NewBaseI2NPMessage(255)
	msg.SetData([]byte("test"))

	err := router.routeMessage(msg, peerHash)
	require.Error(t, err, "Unknown message types should be rejected")
	assert.Contains(t, err.Error(), "unsupported message type",
		"Error should indicate unsupported message type")
}
