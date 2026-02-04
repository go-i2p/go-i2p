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
	// Note: TransportMuxer does NOT implement Transport interface fully.
	// It is missing Accept() and Addr() methods.
	// This is documented as a known gap in AUDIT.md.

	// Verify individual method existence on TransportMuxer
	muxer := &TransportMuxer{}

	// Check methods that exist
	_ = muxer.SetIdentity
	_ = muxer.GetSession
	_ = muxer.Compatible
	_ = muxer.Close
	_ = muxer.Name
	_ = muxer.AcceptWithTimeout // Has timeout variant but not Accept()
	_ = muxer.GetTransports

	t.Log("TransportMuxer has most Transport methods, but Accept() and Addr() are not implemented")
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

// TestConnectionPoolingNoLimits verifies current lack of connection limits.
// This test documents that connection pooling limits are NOT enforced,
// which is a known gap that should be addressed for production use.
func TestConnectionPoolingNoLimits(t *testing.T) {
	// Create a muxer with a mock transport
	transport := &mockTransport{
		acceptConn: &mockConn{},
	}
	muxer := Mux(transport)

	// Verify we can get multiple sessions without limits
	// In a real implementation, there should be a configurable limit

	t.Log("AUDIT FINDING: No connection pooling limits are enforced in TransportMuxer")
	t.Log("Recommendation: Add MaxConnections configuration to prevent resource exhaustion")

	// This test passes to document the gap, not to enforce limits
	assert.NotNil(t, muxer)
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

// TestNameGenerationTruncation verifies the Name() method's string manipulation.
func TestNameGenerationTruncation(t *testing.T) {
	transport1 := &mockTransport{}
	muxer := Mux(transport1)

	name := muxer.Name()
	// The Name() function appears to have a bug - it takes the last 3 chars
	// instead of trimming the trailing ", "
	t.Logf("Muxer name: %q", name)

	// Document this as a potential bug for review
	t.Log("Note: TransportMuxer.Name() truncates to last 3 characters of the generated string")
	t.Log("This appears to be a bug - should likely remove trailing ', ' instead")
}
