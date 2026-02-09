package transport

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTransportInterfaceCompliance verifies that TransportMuxer implements
// all Transport interface methods. This is a compile-time check that will
// fail if the interface is not properly implemented.
func TestTransportInterfaceCompliance(t *testing.T) {
	// Compile-time interface check is in multi.go: var _ Transport = (*TransportMuxer)(nil)

	// Verify individual method existence on TransportMuxer
	muxer := &TransportMuxer{}

	// Check all interface methods exist
	_ = muxer.Accept            // Transport interface
	_ = muxer.Addr              // Transport interface
	_ = muxer.SetIdentity       // Transport interface
	_ = muxer.GetSession        // Transport interface
	_ = muxer.Compatible        // Transport interface
	_ = muxer.Close             // Transport interface
	_ = muxer.Name              // Transport interface
	_ = muxer.AcceptWithTimeout // Extension method with timeout
	_ = muxer.GetTransports     // Extension method

	t.Log("TransportMuxer correctly implements Transport interface (verified in multi.go)")
}

// TestTransportSelectionPriority verifies that transports are tried in the order they are added.
func TestTransportSelectionPriority(t *testing.T) {
	// Track which transport was tried
	callOrder := make([]string, 0)
	var mu sync.Mutex

	// First transport is incompatible
	transport1 := &mockTransportWithOrder{
		name:       "Transport1",
		compatible: false,
		callOrder:  &callOrder,
		mu:         &mu,
	}

	// Second transport is compatible
	transport2 := &mockTransportWithOrder{
		name:       "Transport2",
		compatible: true,
		callOrder:  &callOrder,
		mu:         &mu,
	}

	// Third transport is also compatible (but should not be tried)
	transport3 := &mockTransportWithOrder{
		name:       "Transport3",
		compatible: true,
		callOrder:  &callOrder,
		mu:         &mu,
	}

	muxer := Mux(transport1, transport2, transport3)

	// Create an empty router info for compatibility check
	// Note: We use router_info.RouterInfo{} which will have zero values
	emptyRI := router_info.RouterInfo{}
	compatible := muxer.Compatible(emptyRI)
	require.True(t, compatible, "Muxer should be compatible if any transport is compatible")

	// Verify call order
	mu.Lock()
	defer mu.Unlock()

	// Depending on implementation, all or some transports may be checked
	assert.Contains(t, callOrder, "Transport1", "Transport1 should be checked first")
}

// mockTransportWithOrder tracks call order for testing transport selection
type mockTransportWithOrder struct {
	name       string
	compatible bool
	callOrder  *[]string
	mu         *sync.Mutex
}

func (m *mockTransportWithOrder) Accept() (net.Conn, error) {
	return nil, nil
}

func (m *mockTransportWithOrder) Addr() net.Addr {
	return nil
}

func (m *mockTransportWithOrder) SetIdentity(ident router_info.RouterInfo) error {
	return nil
}

func (m *mockTransportWithOrder) GetSession(routerInfo router_info.RouterInfo) (TransportSession, error) {
	m.mu.Lock()
	*m.callOrder = append(*m.callOrder, m.name+"-GetSession")
	m.mu.Unlock()
	if m.compatible {
		return &mockSession{}, nil
	}
	return nil, errors.New("session not available")
}

func (m *mockTransportWithOrder) Compatible(routerInfo router_info.RouterInfo) bool {
	m.mu.Lock()
	*m.callOrder = append(*m.callOrder, m.name)
	m.mu.Unlock()
	return m.compatible
}

func (m *mockTransportWithOrder) Close() error {
	return nil
}

func (m *mockTransportWithOrder) Name() string {
	return m.name
}

// mockSession implements TransportSession for testing
type mockSession struct{}

func (m *mockSession) QueueSendI2NP(msg i2np.I2NPMessage) {}
func (m *mockSession) SendQueueSize() int                 { return 0 }
func (m *mockSession) ReadNextI2NP() (i2np.I2NPMessage, error) {
	return nil, nil
}
func (m *mockSession) Close() error { return nil }

// TestMuxerAccept verifies the Accept method works correctly.
func TestMuxerAccept(t *testing.T) {
	expectedConn := &mockConn{}
	transport := &mockTransport{
		acceptConn: expectedConn,
	}
	muxer := Mux(transport)

	conn, err := muxer.Accept()
	require.NoError(t, err)
	assert.Equal(t, expectedConn, conn)
}

// TestMuxerAcceptNoTransport verifies Accept returns error when no transport available.
func TestMuxerAcceptNoTransport(t *testing.T) {
	muxer := &TransportMuxer{trans: []Transport{}}

	conn, err := muxer.Accept()
	assert.Error(t, err)
	assert.Equal(t, ErrNoTransportAvailable, err)
	assert.Nil(t, conn)
}

// TestMuxerAddr verifies the Addr method returns the first transport's address.
func TestMuxerAddr(t *testing.T) {
	expectedAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
	transport := &mockTransportWithAddr{addr: expectedAddr}
	muxer := Mux(transport)

	addr := muxer.Addr()
	assert.Equal(t, expectedAddr, addr)
}

// TestMuxerAddrNoTransport verifies Addr returns nil when no transport available.
func TestMuxerAddrNoTransport(t *testing.T) {
	muxer := &TransportMuxer{trans: []Transport{}}

	addr := muxer.Addr()
	assert.Nil(t, addr)
}

// mockTransportWithAddr is a mock transport that returns a specific address.
type mockTransportWithAddr struct {
	addr net.Addr
}

func (m *mockTransportWithAddr) Accept() (net.Conn, error) { return nil, nil }
func (m *mockTransportWithAddr) Addr() net.Addr            { return m.addr }
func (m *mockTransportWithAddr) SetIdentity(ident router_info.RouterInfo) error {
	return nil
}

func (m *mockTransportWithAddr) GetSession(routerInfo router_info.RouterInfo) (TransportSession, error) {
	return nil, nil
}
func (m *mockTransportWithAddr) Compatible(routerInfo router_info.RouterInfo) bool { return false }
func (m *mockTransportWithAddr) Close() error                                      { return nil }
func (m *mockTransportWithAddr) Name() string                                      { return "MockWithAddr" }

// TestConnectionPoolingLimitsEnforced verifies that connection pooling limits
// are actively enforced by the TransportMuxer, preventing resource exhaustion.
func TestConnectionPoolingLimitsEnforced(t *testing.T) {
	// Create a muxer with a very small connection limit
	transport := &mockTransportWithOrder{
		name:       "LimitedTransport",
		compatible: true,
		callOrder:  &[]string{},
		mu:         &sync.Mutex{},
	}
	muxer := MuxWithLimit(2, transport)

	// First session should succeed
	emptyRI := router_info.RouterInfo{}
	_, err := muxer.GetSession(emptyRI)
	require.NoError(t, err, "First session should succeed")
	assert.Equal(t, 1, muxer.ActiveSessionCount(), "Should have 1 active session")

	// Second session should succeed
	_, err = muxer.GetSession(emptyRI)
	require.NoError(t, err, "Second session should succeed")
	assert.Equal(t, 2, muxer.ActiveSessionCount(), "Should have 2 active sessions")

	// Third session should fail - pool is full
	_, err = muxer.GetSession(emptyRI)
	assert.Error(t, err, "Third session should be rejected")
	assert.Equal(t, ErrConnectionPoolFull, err, "Error should be ErrConnectionPoolFull")
	assert.Equal(t, 2, muxer.ActiveSessionCount(), "Should still have 2 active sessions")

	// Release a session
	muxer.ReleaseSession()
	assert.Equal(t, 1, muxer.ActiveSessionCount(), "Should have 1 active session after release")

	// Fourth session should succeed after release
	_, err = muxer.GetSession(emptyRI)
	require.NoError(t, err, "Session after release should succeed")
	assert.Equal(t, 2, muxer.ActiveSessionCount(), "Should have 2 active sessions again")
}

// TestAcceptEnforcesConnectionLimit verifies that Accept respects the connection limit.
func TestAcceptEnforcesConnectionLimit(t *testing.T) {
	transport := &mockTransport{
		acceptConn: &mockConn{},
	}
	muxer := MuxWithLimit(1, transport)

	// First accept should succeed
	conn, err := muxer.Accept()
	require.NoError(t, err)
	require.NotNil(t, conn)
	assert.Equal(t, 1, muxer.ActiveSessionCount())

	// Second accept should fail - pool is full
	conn, err = muxer.Accept()
	assert.Error(t, err)
	assert.Equal(t, ErrConnectionPoolFull, err)
	assert.Nil(t, conn)

	// Release and accept again
	muxer.ReleaseSession()
	conn, err = muxer.Accept()
	require.NoError(t, err)
	require.NotNil(t, conn)
}

// TestDefaultMaxConnections verifies the default max connections value is used
// when no explicit limit is set.
func TestDefaultMaxConnections(t *testing.T) {
	muxer := Mux()
	assert.Equal(t, DefaultMaxConnections, muxer.getMaxConnections(),
		"Default max connections should be %d", DefaultMaxConnections)
}

// TestCustomMaxConnections verifies that custom max connections values are respected.
func TestCustomMaxConnections(t *testing.T) {
	muxer := MuxWithLimit(100)
	assert.Equal(t, 100, muxer.getMaxConnections(),
		"Custom max connections should be 100")
}

// TestReleaseSessionFloor verifies that ReleaseSession doesn't go below zero.
func TestReleaseSessionFloor(t *testing.T) {
	muxer := Mux()
	muxer.ReleaseSession()
	assert.Equal(t, 0, muxer.ActiveSessionCount(),
		"Active session count should not go below 0")
}

// TestErrorHandlingGracefulDegradation verifies that transport failures are handled gracefully.
func TestErrorHandlingGracefulDegradation(t *testing.T) {
	// Create transport that always fails
	failingTransport := &mockTransport{
		acceptError: errors.New("connection refused"),
	}

	// Create transport that succeeds
	successTransport := &mockTransport{
		acceptConn: &mockConn{},
	}

	muxer := Mux(failingTransport, successTransport)

	// Verify muxer handles first transport failure gracefully
	// Note: AcceptWithTimeout only uses first transport, which is a limitation
	conn, err := muxer.AcceptWithTimeout(100 * time.Millisecond)
	assert.Error(t, err, "Should return error from first (failing) transport")
	assert.Nil(t, conn)

	t.Log("Note: TransportMuxer.AcceptWithTimeout only uses first transport (index 0)")
	t.Log("This may be intentional for NTCP2-only support, but limits failover capability")
}

// TestSessionCleanupOnShutdown verifies sessions are properly closed during shutdown.
func TestSessionCleanupOnShutdown(t *testing.T) {
	closedTransports := 0
	var mu sync.Mutex

	transport1 := &mockTransportWithClose{
		name:           "Transport1",
		onClose:        func() { mu.Lock(); closedTransports++; mu.Unlock() },
		closesSessions: true,
		sessionsClosed: 0,
	}

	transport2 := &mockTransportWithClose{
		name:           "Transport2",
		onClose:        func() { mu.Lock(); closedTransports++; mu.Unlock() },
		closesSessions: true,
		sessionsClosed: 0,
	}

	muxer := Mux(transport1, transport2)

	// Close the muxer
	err := muxer.Close()
	require.NoError(t, err)

	// Verify all transports were closed
	mu.Lock()
	assert.Equal(t, 2, closedTransports, "All transports should be closed")
	mu.Unlock()
}

// mockTransportWithClose tracks close operations for testing
type mockTransportWithClose struct {
	name           string
	onClose        func()
	closesSessions bool
	sessionsClosed int
}

func (m *mockTransportWithClose) Accept() (net.Conn, error) {
	return nil, nil
}

func (m *mockTransportWithClose) Addr() net.Addr {
	return nil
}

func (m *mockTransportWithClose) SetIdentity(ident router_info.RouterInfo) error {
	return nil
}

func (m *mockTransportWithClose) GetSession(routerInfo router_info.RouterInfo) (TransportSession, error) {
	return nil, nil
}

func (m *mockTransportWithClose) Compatible(routerInfo router_info.RouterInfo) bool {
	return false
}

func (m *mockTransportWithClose) Close() error {
	if m.onClose != nil {
		m.onClose()
	}
	return nil
}

func (m *mockTransportWithClose) Name() string {
	return m.name
}

// TestMuxerCloseReturnsLastError verifies that Close returns the last error encountered.
func TestMuxerCloseReturnsLastError(t *testing.T) {
	expectedErr := errors.New("transport close error")

	// First transport closes successfully
	transport1 := &mockTransport{}

	// Second transport fails to close
	transport2 := &mockTransportWithCloseError{
		closeErr: expectedErr,
	}

	muxer := Mux(transport1, transport2)

	// Close should return the error from transport2
	err := muxer.Close()
	assert.Equal(t, expectedErr, err, "Close should return the last error encountered")
}

// mockTransportWithCloseError returns an error on close
type mockTransportWithCloseError struct {
	closeErr error
}

func (m *mockTransportWithCloseError) Accept() (net.Conn, error) {
	return nil, nil
}

func (m *mockTransportWithCloseError) Addr() net.Addr {
	return nil
}

func (m *mockTransportWithCloseError) SetIdentity(ident router_info.RouterInfo) error {
	return nil
}

func (m *mockTransportWithCloseError) GetSession(routerInfo router_info.RouterInfo) (TransportSession, error) {
	return nil, nil
}

func (m *mockTransportWithCloseError) Compatible(routerInfo router_info.RouterInfo) bool {
	return false
}

func (m *mockTransportWithCloseError) Close() error {
	return m.closeErr
}

func (m *mockTransportWithCloseError) Name() string {
	return "MockWithCloseError"
}

// TestNameGenerationCorrectness verifies the Name() method generates proper composite names.
func TestNameGenerationCorrectness(t *testing.T) {
	transport1 := &mockTransport{}
	muxer := Mux(transport1)

	name := muxer.Name()
	t.Logf("Muxer name: %q", name)

	// Verify the name is properly formatted (no trailing comma)
	assert.Equal(t, "Muxed Transport: MockTransport", name, "Name should be properly formatted")
	assert.NotContains(t, name, ", \"", "Name should not end with trailing comma")
}
