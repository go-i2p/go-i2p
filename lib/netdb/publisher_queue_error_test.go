package netdb

import (
	"fmt"
	"sync"
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// failingTransportSession is a mock that returns an error from QueueSendI2NP.
// Used to verify that sendMessageThroughGateway propagates send errors.
type failingTransportSession struct {
	mu      sync.Mutex
	sendErr error
}

func (s *failingTransportSession) QueueSendI2NP(msg i2np.I2NPMessage) error {
	return s.sendErr
}

// failingTransportManager returns a failingTransportSession for any router.
type failingTransportManager struct {
	session *failingTransportSession
}

func (m *failingTransportManager) GetSession(routerInfo router_info.RouterInfo) (TransportSession, error) {
	return m.session, nil
}

// setupGatewayTest creates a mock NetDB with a valid gateway RouterInfo and returns
// the db, gateway hash, and a test I2NP message. Reduces boilerplate in gateway tests.
func setupGatewayTest(t *testing.T) (*mockNetDB, common.Hash, i2np.I2NPMessage) {
	t.Helper()
	db := newMockNetDB()
	gatewayRI := createValidRouterInfo(t)
	gatewayHash, err := gatewayRI.IdentHash()
	require.NoError(t, err)
	db.StoreRouterInfo(gatewayRI)
	msg := i2np.NewBaseI2NPMessage(i2np.I2NP_MESSAGE_TYPE_DATABASE_STORE)
	msg.SetData([]byte("test data"))
	return db, gatewayHash, msg
}

// TestSendMessageThroughGatewayQueueError verifies that sendMessageThroughGateway
// propagates errors from QueueSendI2NP instead of silently discarding them.
// This covers CRITICAL BUG: QueueSendI2NP Error Silently Discarded in publisher.go.
func TestSendMessageThroughGatewayQueueError(t *testing.T) {
	db, gatewayHash, msg := setupGatewayTest(t)

	// Create a transport that returns an error on QueueSendI2NP
	sendErr := fmt.Errorf("send queue full: 256/256 messages pending")
	transport := &failingTransportManager{
		session: &failingTransportSession{sendErr: sendErr},
	}

	publisher := NewPublisher(db, nil, transport, nil, DefaultPublisherConfig())

	// Call sendMessageThroughGateway — should propagate the error
	err := publisher.sendMessageThroughGateway(gatewayHash, msg)

	assert.Error(t, err, "Expected error from QueueSendI2NP failure")
	assert.Contains(t, err.Error(), "failed to queue message",
		"Error should describe the queue failure")
}

// TestSendMessageThroughGatewaySuccess verifies the happy path where
// QueueSendI2NP succeeds and no error is returned.
func TestSendMessageThroughGatewaySuccess(t *testing.T) {
	db, gatewayHash, msg := setupGatewayTest(t)
	transport := newMockTransportManager()

	publisher := NewPublisher(db, nil, transport, nil, DefaultPublisherConfig())

	// Should succeed
	err := publisher.sendMessageThroughGateway(gatewayHash, msg)
	assert.NoError(t, err)

	// Verify message was sent
	sentMsgs := transport.GetSentMessages(gatewayHash)
	assert.Len(t, sentMsgs, 1, "Expected one sent message")
}

// TestSendMessageThroughGatewayNoTransport verifies the error when
// the transport manager is nil. The function first retrieves the gateway
// RouterInfo, then checks transport, so we need a valid gateway in the DB.
func TestSendMessageThroughGatewayNoTransport(t *testing.T) {
	db, gatewayHash, msg := setupGatewayTest(t)

	// Create publisher with nil transport
	publisher := NewPublisher(db, nil, nil, nil, DefaultPublisherConfig())

	err := publisher.sendMessageThroughGateway(gatewayHash, msg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "transport manager not available")
}
