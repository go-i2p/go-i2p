package ntcp2

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/crypto/types"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNTCP2Session_Basic(t *testing.T) {
	// Test NTCP2Session basic functionality
	conn := &mockConn{data: []byte{}}
	ctx := context.Background()
	logger := logger.WithField("test", "session")

	session := NewNTCP2Session(conn, ctx, logger)
	require.NotNil(t, session)
	defer session.Close()

	// Test initial state
	assert.Equal(t, 0, session.SendQueueSize())

	// Test that Close works
	err := session.Close()
	assert.NoError(t, err)
}

func TestNTCP2Session_QueueMessage(t *testing.T) {
	// Test queuing messages
	conn := &mockConn{data: []byte{}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logger := logger.WithField("test", "queue")

	session := NewNTCP2Session(conn, ctx, logger)
	defer session.Close()

	// Queue a message
	msg := i2np.NewDataMessage([]byte("test message"))
	session.QueueSendI2NP(msg)

	// Give workers time to process
	time.Sleep(10 * time.Millisecond)

	// Queue size behavior depends on worker processing speed
	// Just verify the method works without panic
}

func TestConfig_Validation(t *testing.T) {
	// Test config creation and validation
	config, err := NewConfig(":8080")
	require.NoError(t, err)
	require.NotNil(t, config)

	// Test validation passes for valid address
	err = config.Validate()
	assert.NoError(t, err)
	assert.Equal(t, ":8080", config.ListenerAddress)

	// Test validation fails for empty address
	invalidConfig, err := NewConfig("")
	require.NoError(t, err)
	err = invalidConfig.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid listener address")
}

func TestSupportsNTCP2_Nil(t *testing.T) {
	// Test nil RouterInfo
	assert.False(t, SupportsNTCP2(nil))
}

func TestFramingIntegration(t *testing.T) {
	// Test that block framing produces non-empty output
	msg := i2np.NewDataMessage([]byte("integration test"))
	msg.SetMessageID(42)

	framedData, err := FrameI2NPMessageAsBlock(msg)
	require.NoError(t, err)
	assert.True(t, len(framedData) > 0, "Block-framed data must be non-empty")
}

// Mock connection for testing
type mockConn struct {
	data   []byte
	offset int
}

func (c *mockConn) Read(p []byte) (n int, err error) {
	if c.offset >= len(c.data) {
		return 0, bytes.ErrTooLarge // EOF
	}

	n = copy(p, c.data[c.offset:])
	c.offset += n
	return n, nil
}

func (c *mockConn) Write(p []byte) (n int, err error) {
	return len(p), nil
}

func (c *mockConn) Close() error {
	return nil
}

func (c *mockConn) LocalAddr() net.Addr {
	return &mockAddr{"mock-local"}
}

func (c *mockConn) RemoteAddr() net.Addr {
	return &mockAddr{"mock-remote"}
}

func (c *mockConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *mockConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *mockConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// Mock address for testing
type mockAddr struct {
	address string
}

func (a *mockAddr) Network() string {
	return "mock"
}

func (a *mockAddr) String() string {
	return a.address
}

// TestBuildTransportInstanceStoresKeystore verifies that buildTransportInstance
// stores the keystore reference, which is required for SetIdentity to
// reinitialize crypto keys.
func TestBuildTransportInstanceStoresKeystore(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mockKs := &mockKeystore{}
	config := &Config{
		ListenerAddress: "127.0.0.1:0",
		WorkingDir:      t.TempDir(),
	}

	logger := logger.WithField("component", "test")

	var identity router_info.RouterInfo // nil interface value
	transport := buildTransportInstance(config, identity, mockKs, ctx, cancel, logger)

	assert.NotNil(t, transport, "Transport should be created")
	assert.NotNil(t, transport.keystore, "Keystore should be stored in transport")
	assert.Same(t, mockKs, transport.keystore, "Keystore should be the same instance")
}

// mockKeystore implements KeystoreProvider for testing
type mockKeystore struct{}

func (m *mockKeystore) GetEncryptionPrivateKey() types.PrivateEncryptionKey {
	return nil
}

// E-5: Test that NetDB storage failures are observable (not silently ignored)
func TestVerifyMapIntegrity(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	config := &Config{
		ListenerAddress: "127.0.0.1:0",
		WorkingDir:      t.TempDir(),
	}
	mockKs := &mockKeystore{}
	logger := logger.WithField("component", "test")

	var identity router_info.RouterInfo
	transport := buildTransportInstance(config, identity, mockKs, ctx, cancel, logger)

	// CRITICAL-5.1: Test map integrity with valid entries
	// Empty map should have zero invalid entries
	invalidCount := transport.verifyMapIntegrity()
	assert.Equal(t, 0, invalidCount, "Empty map should have zero invalid entries")

	// Note: Proper testing would require real data.Hash keys from router_info.RouterInfo
	// For now, we verify the function doesn't panic and can be called
	// The actual integrity checks would be tested with real router hashes in integration tests
}

func TestStoreRouterInfoInNetDB_ErrorObservability(t *testing.T) {
	tests := []struct {
		name          string
		storer        interface{}
		expectError   bool
		expectLogWarn bool
	}{
		{
			name:          "nil storer returns no error",
			storer:        nil,
			expectError:   false,
			expectLogWarn: false,
		},
		{
			name:          "error-returning storer surfaces error",
			storer:        &mockStorerWithErrors{shouldFail: true},
			expectError:   true,
			expectLogWarn: false,
		},
		{
			name:          "error-returning storer succeeds",
			storer:        &mockStorerWithErrors{shouldFail: false},
			expectError:   false,
			expectLogWarn: false,
		},
		{
			name:          "void storer never returns error",
			storer:        &mockVoidStorer{},
			expectError:   false,
			expectLogWarn: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			config := &Config{
				ListenerAddress: "127.0.0.1:0",
			}

			logger := logger.WithField("test", tt.name)
			var identity router_info.RouterInfo // nil interface value
			transport := buildTransportInstance(config, identity, &mockKeystore{}, ctx, cancel, logger)

			// Inject the mock storer using SetRouterInfoStorer
			if tt.storer != nil {
				if s, ok := tt.storer.(interface {
					StoreRouterInfo(ri router_info.RouterInfo)
				}); ok {
					transport.SetRouterInfoStorer(s)
				}
			}

			// Create a minimal RouterInfo for testing
			mockRI := createMockRouterInfo(t)
			mockConn := &mockConn{data: []byte{}}

			// Call storeRouterInfoInNetDB and check if error is returned
			err := transport.storeRouterInfoInNetDB(mockRI, mockConn)

			if tt.expectError {
				assert.Error(t, err, "Expected storage error to be observable")
			} else {
				assert.NoError(t, err, "Expected no error")
			}
		})
	}
}

// mockStorerWithErrors implements RouterInfoStorerWithErrors for E-5 testing
type mockStorerWithErrors struct {
	shouldFail bool
}

func (m *mockStorerWithErrors) StoreRouterInfo(ri router_info.RouterInfo) {
	// Void method - never returns error
}

func (m *mockStorerWithErrors) StoreRouterInfoWithError(ri router_info.RouterInfo) error {
	if m.shouldFail {
		return assert.AnError
	}
	return nil
}

// mockVoidStorer implements only the void StoreRouterInfo method
type mockVoidStorer struct{}

func (m *mockVoidStorer) StoreRouterInfo(ri router_info.RouterInfo) {
	// Void method - storage happens silently
}

// createMockRouterInfo creates a minimal RouterInfo for testing
func createMockRouterInfo(t *testing.T) router_info.RouterInfo {
	t.Helper()
	// Return a nil interface value for simplicity - the test focuses on error propagation,
	// not RouterInfo parsing
	var ri router_info.RouterInfo
	return ri
}
