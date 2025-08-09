package ntcp2

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNTCP2Session_Basic(t *testing.T) {
	// Test NTCP2Session basic functionality
	conn := &mockConn{data: []byte{}}
	ctx := context.Background()
	logger := logrus.WithField("test", "session")

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
	logger := logrus.WithField("test", "queue")

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
	// Test that framing and session work together
	// Create a data message
	msg := i2np.NewDataMessage([]byte("integration test"))
	msg.SetMessageID(42)

	// Frame it
	framedData, err := FrameI2NPMessage(msg)
	require.NoError(t, err)
	assert.True(t, len(framedData) > 4) // Has length prefix

	// Create a mock connection with the framed data
	conn := &mockConn{data: framedData}

	// Unframe it
	unframedMsg, err := UnframeI2NPMessage(conn)
	require.NoError(t, err)
	assert.Equal(t, i2np.I2NP_MESSAGE_TYPE_DATA, unframedMsg.Type())
	assert.Equal(t, 42, unframedMsg.MessageID())
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
