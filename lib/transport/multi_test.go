package transport

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/go-i2p/common/router_info"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockTransport implements Transport interface for testing
type mockTransport struct {
	acceptDelay time.Duration
	acceptError error
	acceptConn  net.Conn
}

func (m *mockTransport) Accept() (net.Conn, error) {
	if m.acceptDelay > 0 {
		time.Sleep(m.acceptDelay)
	}
	if m.acceptError != nil {
		return nil, m.acceptError
	}
	return m.acceptConn, nil
}

func (m *mockTransport) Addr() net.Addr {
	return nil
}

func (m *mockTransport) SetIdentity(ident router_info.RouterInfo) error {
	return nil
}

func (m *mockTransport) GetSession(routerInfo router_info.RouterInfo) (TransportSession, error) {
	return nil, nil
}

func (m *mockTransport) Compatible(routerInfo router_info.RouterInfo) bool {
	return true
}

func (m *mockTransport) Close() error {
	return nil
}

func (m *mockTransport) Name() string {
	return "MockTransport"
}

// mockConn implements net.Conn for testing
type mockConn struct {
	closed bool
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	return 0, nil
}

func (m *mockConn) Write(b []byte) (n int, err error) {
	return len(b), nil
}

func (m *mockConn) Close() error {
	m.closed = true
	return nil
}

func (m *mockConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
}

func (m *mockConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 54321}
}

func (m *mockConn) SetDeadline(t time.Time) error {
	return nil
}

func (m *mockConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *mockConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// TestAcceptWithTimeoutSuccess tests successful connection acceptance before timeout
func TestAcceptWithTimeoutSuccess(t *testing.T) {
	// Create mock connection
	mockConn := &mockConn{}

	// Create mock transport that accepts immediately
	transport := &mockTransport{
		acceptDelay: 50 * time.Millisecond,
		acceptConn:  mockConn,
	}

	// Create muxer with mock transport
	muxer := Mux(transport)

	// Accept with timeout longer than delay
	conn, err := muxer.AcceptWithTimeout(200 * time.Millisecond)

	// Verify success
	require.NoError(t, err, "AcceptWithTimeout should succeed when connection arrives before timeout")
	require.NotNil(t, conn, "Should return valid connection")
	assert.Equal(t, mockConn, conn.(*trackedConn).Conn, "Should return the mock connection")
}

// TestAcceptWithTimeoutExpires tests timeout behavior when no connection arrives
func TestAcceptWithTimeoutExpires(t *testing.T) {
	// Create mock transport with long delay (longer than timeout)
	transport := &mockTransport{
		acceptDelay: 500 * time.Millisecond,
		acceptConn:  &mockConn{},
	}

	// Create muxer with mock transport
	muxer := Mux(transport)

	// Accept with short timeout
	start := time.Now()
	conn, err := muxer.AcceptWithTimeout(100 * time.Millisecond)
	duration := time.Since(start)

	// Verify timeout occurred
	require.Error(t, err, "AcceptWithTimeout should return error on timeout")
	assert.ErrorIs(t, err, context.DeadlineExceeded, "Error should be context.DeadlineExceeded")
	assert.Nil(t, conn, "Should return nil connection on timeout")

	// Verify timeout duration is approximately correct (within 50ms tolerance)
	assert.InDelta(t, 100, duration.Milliseconds(), 50,
		"Timeout should occur at approximately the specified duration")
}

// TestAcceptWithTimeoutTransportError tests error propagation from underlying transport
func TestAcceptWithTimeoutTransportError(t *testing.T) {
	// Create mock transport that returns error
	expectedError := ErrNoTransportAvailable
	transport := &mockTransport{
		acceptDelay: 0,
		acceptError: expectedError,
	}

	// Create muxer with mock transport
	muxer := Mux(transport)

	// Accept with timeout
	conn, err := muxer.AcceptWithTimeout(1 * time.Second)

	// Verify error is propagated
	require.Error(t, err, "AcceptWithTimeout should propagate transport errors")
	assert.Equal(t, expectedError, err, "Should return exact error from transport")
	assert.Nil(t, conn, "Should return nil connection on error")
}

// TestAcceptWithTimeoutNoTransport tests behavior when no transport is available
func TestAcceptWithTimeoutNoTransport(t *testing.T) {
	// Create empty muxer with no transports
	muxer := &TransportMuxer{
		trans: []Transport{},
	}

	// Accept with timeout
	conn, err := muxer.AcceptWithTimeout(100 * time.Millisecond)

	// Verify appropriate error
	require.Error(t, err, "AcceptWithTimeout should error when no transport available")
	assert.Equal(t, ErrNoTransportAvailable, err, "Should return ErrNoTransportAvailable")
	assert.Nil(t, conn, "Should return nil connection on error")
}

// TestAcceptWithTimeoutZeroTimeout tests behavior with zero timeout
func TestAcceptWithTimeoutZeroTimeout(t *testing.T) {
	// Create mock transport with immediate accept
	transport := &mockTransport{
		acceptDelay: 0,
		acceptConn:  &mockConn{},
	}

	// Create muxer with mock transport
	muxer := Mux(transport)

	// Accept with zero timeout (should timeout immediately)
	conn, err := muxer.AcceptWithTimeout(0)

	// Zero timeout should result in immediate timeout in most cases
	// However, due to goroutine scheduling, it might succeed
	if err != nil {
		assert.ErrorIs(t, err, context.DeadlineExceeded, "Zero timeout should cause deadline exceeded")
		assert.Nil(t, conn, "Should return nil connection on timeout")
	} else {
		// If it succeeded due to race condition, verify valid connection
		require.NotNil(t, conn, "If accept succeeded, connection should be valid")
	}
}

// TestAcceptWithTimeoutConcurrent tests multiple concurrent accept calls
func TestAcceptWithTimeoutConcurrent(t *testing.T) {
	// Create mock transport that accepts after short delay
	transport := &mockTransport{
		acceptDelay: 50 * time.Millisecond,
		acceptConn:  &mockConn{},
	}

	// Create muxer with mock transport
	muxer := Mux(transport)

	numConcurrent := 5
	done := make(chan bool, numConcurrent)

	// Launch concurrent accept operations
	for i := 0; i < numConcurrent; i++ {
		go func(id int) {
			defer func() { done <- true }()

			// Each goroutine attempts accept with timeout
			conn, err := muxer.AcceptWithTimeout(200 * time.Millisecond)
			// Note: With this mock, all will succeed since each call creates
			// a new goroutine that doesn't block others
			if err != nil {
				assert.ErrorIs(t, err, context.DeadlineExceeded,
					"Error should be timeout if it occurs")
			}

			// If successful, connection should be valid
			if conn != nil {
				assert.NotNil(t, conn, "Connection should be valid if no error")
			}
		}(i)
	}

	// Wait for all goroutines with timeout
	timeout := time.After(2 * time.Second)
	for i := 0; i < numConcurrent; i++ {
		select {
		case <-done:
			// Goroutine completed
		case <-timeout:
			t.Fatal("Test timed out waiting for concurrent accepts")
		}
	}
}

// BenchmarkAcceptWithTimeout measures performance of AcceptWithTimeout
func BenchmarkAcceptWithTimeout(b *testing.B) {
	// Create mock transport with minimal delay
	transport := &mockTransport{
		acceptDelay: 1 * time.Millisecond,
		acceptConn:  &mockConn{},
	}

	muxer := Mux(transport)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn, err := muxer.AcceptWithTimeout(100 * time.Millisecond)
		if err != nil {
			b.Fatalf("Unexpected error: %v", err)
		}
		if conn == nil {
			b.Fatal("Expected connection, got nil")
		}
	}
}

// BenchmarkAcceptWithTimeoutTimeout measures performance when timeouts occur
func BenchmarkAcceptWithTimeoutTimeout(b *testing.B) {
	// Create mock transport with long delay to force timeouts
	transport := &mockTransport{
		acceptDelay: 500 * time.Millisecond,
		acceptConn:  &mockConn{},
	}

	muxer := Mux(transport)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn, err := muxer.AcceptWithTimeout(10 * time.Millisecond)
		if !assert.ErrorIs(b, err, context.DeadlineExceeded) {
			b.Fatalf("Expected timeout error, got: %v", err)
		}
		if conn != nil {
			b.Fatal("Expected nil connection on timeout")
		}
	}
}

// trackingMockConn tracks when Close() is called
type trackingMockConn struct {
	mockConn
	closeChan chan struct{}
}

func newTrackingMockConn() *trackingMockConn {
	return &trackingMockConn{
		closeChan: make(chan struct{}, 1),
	}
}

func (t *trackingMockConn) Close() error {
	t.closed = true
	select {
	case t.closeChan <- struct{}{}:
	default:
	}
	return nil
}

// slowAcceptTransport simulates a transport that takes a long time to accept
type slowAcceptTransport struct {
	delay     time.Duration
	conn      net.Conn
	cancelled chan struct{}
}

func newSlowAcceptTransport(delay time.Duration, conn net.Conn) *slowAcceptTransport {
	return &slowAcceptTransport{
		delay:     delay,
		conn:      conn,
		cancelled: make(chan struct{}),
	}
}

func (s *slowAcceptTransport) Accept() (net.Conn, error) {
	time.Sleep(s.delay)
	return s.conn, nil
}

func (s *slowAcceptTransport) Addr() net.Addr                                 { return nil }
func (s *slowAcceptTransport) SetIdentity(ident router_info.RouterInfo) error { return nil }
func (s *slowAcceptTransport) GetSession(routerInfo router_info.RouterInfo) (TransportSession, error) {
	return nil, nil
}
func (s *slowAcceptTransport) Compatible(routerInfo router_info.RouterInfo) bool { return true }
func (s *slowAcceptTransport) Close() error                                      { return nil }
func (s *slowAcceptTransport) Name() string                                      { return "SlowAcceptTransport" }

// TestAcceptMultipleTransportsFirstWins tests that Accept returns connection from the first transport to complete
func TestAcceptMultipleTransportsFirstWins(t *testing.T) {
	// Create two transports with different delays
	fastConn := &mockConn{}
	slowConn := &mockConn{}

	fastTransport := &mockTransport{
		acceptDelay: 10 * time.Millisecond,
		acceptConn:  fastConn,
	}
	slowTransport := &mockTransport{
		acceptDelay: 200 * time.Millisecond,
		acceptConn:  slowConn,
	}

	// Mux with slow transport first, fast transport second
	muxer := Mux(slowTransport, fastTransport)

	start := time.Now()
	conn, err := muxer.AcceptWithTimeout(500 * time.Millisecond)
	duration := time.Since(start)

	require.NoError(t, err, "Should succeed with multi-transport accept")
	require.NotNil(t, conn, "Should return a connection")

	// Should return within the fast transport's time, not the slow one
	assert.Less(t, duration, 100*time.Millisecond, "Should return quickly when fast transport succeeds")

	// The returned connection should be from the fast transport
	assert.Equal(t, fastConn, conn.(*trackedConn).Conn, "Should return the fast transport's connection")
}

// TestAcceptWithTimeoutClosesLeakedConnections tests that connections accepted after timeout are closed
func TestAcceptWithTimeoutClosesLeakedConnections(t *testing.T) {
	// Create a tracking connection that notifies when closed
	trackedConn := newTrackingMockConn()

	// Create transport that accepts AFTER the timeout
	slowTransport := newSlowAcceptTransport(200*time.Millisecond, trackedConn)

	muxer := Mux(slowTransport)

	// Timeout before accept completes
	conn, err := muxer.AcceptWithTimeout(50 * time.Millisecond)

	require.Error(t, err, "Should timeout")
	assert.ErrorIs(t, err, context.DeadlineExceeded, "Error should be deadline exceeded")
	assert.Nil(t, conn, "Should return nil connection on timeout")

	// Wait for the slow transport to complete and verify the connection was closed
	select {
	case <-trackedConn.closeChan:
		// Success: connection was closed after timeout
		assert.True(t, trackedConn.closed, "Leaked connection should be closed")
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Timed out waiting for leaked connection to be closed")
	}
}

// TestAcceptSecondTransportWinsWhenFirstFails tests fallback to second transport when first fails
func TestAcceptSecondTransportWinsWhenFirstFails(t *testing.T) {
	expectedConn := &mockConn{}

	// First transport fails
	failingTransport := &mockTransport{
		acceptDelay: 10 * time.Millisecond,
		acceptError: ErrNoTransportAvailable,
	}
	// Second transport succeeds
	successTransport := &mockTransport{
		acceptDelay: 20 * time.Millisecond,
		acceptConn:  expectedConn,
	}

	muxer := Mux(failingTransport, successTransport)

	conn, err := muxer.AcceptWithTimeout(500 * time.Millisecond)

	require.NoError(t, err, "Should succeed with second transport")
	require.NotNil(t, conn, "Should return a connection")
	assert.Equal(t, expectedConn, conn.(*trackedConn).Conn, "Should return the second transport's connection")
}

// TestAcceptAllTransportsFail tests that proper error is returned when all transports fail
func TestAcceptAllTransportsFail(t *testing.T) {
	failTransport1 := &mockTransport{
		acceptDelay: 10 * time.Millisecond,
		acceptError: ErrNoTransportAvailable,
	}
	failTransport2 := &mockTransport{
		acceptDelay: 20 * time.Millisecond,
		acceptError: ErrNoTransportAvailable,
	}

	muxer := Mux(failTransport1, failTransport2)

	conn, err := muxer.AcceptWithTimeout(500 * time.Millisecond)

	require.Error(t, err, "Should return error when all transports fail")
	assert.Equal(t, ErrNoTransportAvailable, err, "Should return the last error")
	assert.Nil(t, conn, "Should return nil connection")
}

// TestAcceptClosesLateConnectionsAfterSuccess tests that connections arriving after success are closed
func TestAcceptClosesLateConnectionsAfterSuccess(t *testing.T) {
	// First transport returns quickly
	fastConn := &mockConn{}
	fastTransport := &mockTransport{
		acceptDelay: 10 * time.Millisecond,
		acceptConn:  fastConn,
	}

	// Second transport returns slowly with a tracked connection
	slowConn := newTrackingMockConn()
	slowTransport := newSlowAcceptTransport(200*time.Millisecond, slowConn)

	muxer := Mux(fastTransport, slowTransport)

	conn, err := muxer.AcceptWithTimeout(500 * time.Millisecond)

	require.NoError(t, err, "Should succeed with fast transport")
	require.NotNil(t, conn, "Should return a connection")
	assert.Equal(t, fastConn, conn.(*trackedConn).Conn, "Should return fast transport's connection")

	// Wait for slow transport to complete and verify its connection was closed
	select {
	case <-slowConn.closeChan:
		// Success: late connection was closed
		assert.True(t, slowConn.closed, "Late connection should be closed")
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Timed out waiting for late connection to be closed")
	}
}

// TestAcceptBasicMultiTransport tests basic Accept() with multiple transports
func TestAcceptBasicMultiTransport(t *testing.T) {
	// Create two transports with different delays
	fastConn := &mockConn{}
	slowConn := &mockConn{}

	fastTransport := &mockTransport{
		acceptDelay: 10 * time.Millisecond,
		acceptConn:  fastConn,
	}
	slowTransport := &mockTransport{
		acceptDelay: 500 * time.Millisecond,
		acceptConn:  slowConn,
	}

	// Mux with slow transport first
	muxer := Mux(slowTransport, fastTransport)

	// Use a goroutine with channel to avoid blocking indefinitely
	type result struct {
		conn net.Conn
		err  error
	}
	resChan := make(chan result, 1)

	go func() {
		conn, err := muxer.Accept()
		resChan <- result{conn, err}
	}()

	select {
	case res := <-resChan:
		require.NoError(t, res.err, "Accept should succeed")
		require.NotNil(t, res.conn, "Should return a connection")
		// Should return the fast connection
		assert.Equal(t, fastConn, res.conn.(*trackedConn).Conn, "Should return fast transport's connection")
	case <-time.After(200 * time.Millisecond):
		t.Fatal("Accept took too long - should return fast connection quickly")
	}
}
