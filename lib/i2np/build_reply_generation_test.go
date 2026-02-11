package i2np

import (
	"errors"
	"sync"
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/session_key"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockBuildReplyForwarder implements BuildReplyForwarder for testing
type mockBuildReplyForwarder struct {
	mu                 sync.Mutex
	routerCalls        []routerForwardCall
	tunnelCalls        []tunnelForwardCall
	forwardToRouterErr error
	forwardToTunnelErr error
}

type routerForwardCall struct {
	routerHash       common.Hash
	messageID        int
	encryptedRecords []byte
	isShortBuild     bool
}

type tunnelForwardCall struct {
	gatewayHash      common.Hash
	tunnelID         tunnel.TunnelID
	messageID        int
	encryptedRecords []byte
	isShortBuild     bool
}

func newMockBuildReplyForwarder() *mockBuildReplyForwarder {
	return &mockBuildReplyForwarder{
		routerCalls: make([]routerForwardCall, 0),
		tunnelCalls: make([]tunnelForwardCall, 0),
	}
}

func (m *mockBuildReplyForwarder) ForwardBuildReplyToRouter(routerHash common.Hash, messageID int, encryptedRecords []byte, isShortBuild bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.routerCalls = append(m.routerCalls, routerForwardCall{
		routerHash:       routerHash,
		messageID:        messageID,
		encryptedRecords: encryptedRecords,
		isShortBuild:     isShortBuild,
	})
	return m.forwardToRouterErr
}

func (m *mockBuildReplyForwarder) ForwardBuildReplyThroughTunnel(gatewayHash common.Hash, tunnelID tunnel.TunnelID, messageID int, encryptedRecords []byte, isShortBuild bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tunnelCalls = append(m.tunnelCalls, tunnelForwardCall{
		gatewayHash:      gatewayHash,
		tunnelID:         tunnelID,
		messageID:        messageID,
		encryptedRecords: encryptedRecords,
		isShortBuild:     isShortBuild,
	})
	return m.forwardToTunnelErr
}

func (m *mockBuildReplyForwarder) getRouterCalls() []routerForwardCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]routerForwardCall, len(m.routerCalls))
	copy(result, m.routerCalls)
	return result
}

func (m *mockBuildReplyForwarder) getTunnelCalls() []tunnelForwardCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]tunnelForwardCall, len(m.tunnelCalls))
	copy(result, m.tunnelCalls)
	return result
}

// mockParticipantManager implements ParticipantManager for testing
type mockParticipantManager struct {
	mu              sync.Mutex
	acceptAll       bool
	rejectCode      byte
	rejectReason    string
	registeredCount int
	registerErr     error
}

func newMockParticipantManager(acceptAll bool) *mockParticipantManager {
	return &mockParticipantManager{
		acceptAll:    acceptAll,
		rejectCode:   TUNNEL_BUILD_REPLY_REJECT,
		rejectReason: "mock rejection",
	}
}

func (m *mockParticipantManager) ProcessBuildRequest(sourceHash common.Hash) (accepted bool, rejectCode byte, reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.acceptAll {
		return true, 0, ""
	}
	return false, m.rejectCode, m.rejectReason
}

func (m *mockParticipantManager) RegisterParticipant(tunnelID tunnel.TunnelID, sourceHash common.Hash, expiry time.Time, layerKey, ivKey session_key.SessionKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.registeredCount++
	return m.registerErr
}

func (m *mockParticipantManager) getRegisteredCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.registeredCount
}

func TestBuildReplyForwarderInterface(t *testing.T) {
	t.Run("interface_compiles", func(t *testing.T) {
		// Verify the interface can be implemented
		var _ BuildReplyForwarder = (*mockBuildReplyForwarder)(nil)
	})
}

func TestProcessSingleBuildRecord_AcceptedRequest(t *testing.T) {
	// Setup
	processor := NewMessageProcessor()
	mockForwarder := newMockBuildReplyForwarder()
	mockParticipant := newMockParticipantManager(true) // Accept all requests

	processor.SetBuildReplyForwarder(mockForwarder)
	processor.SetParticipantManager(mockParticipant)

	record := createTestBuildRequestRecord(t)
	record.NextTunnel = 0 // Force direct router forwarding
	messageID := 1001

	// Execute
	processor.processSingleBuildRecord(messageID, 0, record, false)

	// Verify
	assert.Equal(t, 1, mockParticipant.getRegisteredCount(), "Participant should be registered")

	routerCalls := mockForwarder.getRouterCalls()
	assert.Len(t, routerCalls, 1, "Should have one router forward call")

	if len(routerCalls) > 0 {
		assert.Equal(t, record.NextIdent, routerCalls[0].routerHash, "Router hash should match NextIdent")
		assert.Equal(t, messageID, routerCalls[0].messageID, "Message ID should match")
		assert.NotEmpty(t, routerCalls[0].encryptedRecords, "Encrypted records should not be empty")
		// ChaCha20-Poly1305 produces 544 bytes (528 + 16 auth tag)
		assert.Equal(t, 544, len(routerCalls[0].encryptedRecords), "Encrypted reply should be 544 bytes")
	}
}

func TestProcessSingleBuildRecord_RejectedRequest(t *testing.T) {
	// Setup
	processor := NewMessageProcessor()
	mockForwarder := newMockBuildReplyForwarder()
	mockParticipant := newMockParticipantManager(false) // Reject all requests
	mockParticipant.rejectCode = TUNNEL_BUILD_REPLY_OVERLOAD
	mockParticipant.rejectReason = "router overloaded"

	processor.SetBuildReplyForwarder(mockForwarder)
	processor.SetParticipantManager(mockParticipant)

	record := createTestBuildRequestRecord(t)
	record.NextTunnel = 0 // Force direct router forwarding
	messageID := 1002

	// Execute
	processor.processSingleBuildRecord(messageID, 0, record, false)

	// Verify
	assert.Equal(t, 0, mockParticipant.getRegisteredCount(), "Participant should not be registered when rejected")

	routerCalls := mockForwarder.getRouterCalls()
	assert.Len(t, routerCalls, 1, "Should still forward rejection reply")
}

func TestProcessSingleBuildRecord_TunnelForwarding(t *testing.T) {
	// Setup
	processor := NewMessageProcessor()
	mockForwarder := newMockBuildReplyForwarder()
	mockParticipant := newMockParticipantManager(true)

	processor.SetBuildReplyForwarder(mockForwarder)
	processor.SetParticipantManager(mockParticipant)

	record := createTestBuildRequestRecord(t)
	record.NextTunnel = tunnel.TunnelID(67890) // Non-zero means tunnel forwarding
	messageID := 1003

	// Execute
	processor.processSingleBuildRecord(messageID, 0, record, false)

	// Verify
	tunnelCalls := mockForwarder.getTunnelCalls()
	assert.Len(t, tunnelCalls, 1, "Should have one tunnel forward call")

	if len(tunnelCalls) > 0 {
		assert.Equal(t, record.NextIdent, tunnelCalls[0].gatewayHash, "Gateway hash should match NextIdent")
		assert.Equal(t, record.NextTunnel, tunnelCalls[0].tunnelID, "Tunnel ID should match NextTunnel")
		assert.Equal(t, messageID, tunnelCalls[0].messageID, "Message ID should match")
	}

	routerCalls := mockForwarder.getRouterCalls()
	assert.Len(t, routerCalls, 0, "Should not use router forwarding when tunnel is specified")
}

func TestProcessSingleBuildRecord_NoForwarder(t *testing.T) {
	// Setup - no forwarder set
	processor := NewMessageProcessor()
	mockParticipant := newMockParticipantManager(true)

	processor.SetParticipantManager(mockParticipant)
	// Note: No SetBuildReplyForwarder called

	record := createTestBuildRequestRecord(t)
	messageID := 1004

	// Execute - should not panic, just log warning
	processor.processSingleBuildRecord(messageID, 0, record, false)

	// Verify - participant should still be registered even without forwarder
	assert.Equal(t, 1, mockParticipant.getRegisteredCount(), "Participant should still be registered")
}

func TestGenerateAndSendBuildReply_EncryptionWorks(t *testing.T) {
	// Setup
	processor := NewMessageProcessor()
	mockForwarder := newMockBuildReplyForwarder()
	mockParticipant := newMockParticipantManager(true)

	processor.SetBuildReplyForwarder(mockForwarder)
	processor.SetParticipantManager(mockParticipant)

	record := createTestBuildRequestRecord(t)
	record.NextTunnel = 0 // Force direct router forwarding
	messageID := 1005

	// Execute
	err := processor.generateAndSendBuildReply(messageID, 0, record, TUNNEL_BUILD_REPLY_SUCCESS, false)

	// Verify
	require.NoError(t, err, "Should successfully generate and send reply")

	routerCalls := mockForwarder.getRouterCalls()
	require.Len(t, routerCalls, 1, "Should have one forward call")

	// Verify the encrypted reply can be decrypted
	encryptedReply := routerCalls[0].encryptedRecords
	crypto := NewBuildRecordCrypto()

	decrypted, err := crypto.DecryptReplyRecord(encryptedReply, record.ReplyKey, record.ReplyIV)
	require.NoError(t, err, "Should be able to decrypt the reply")
	assert.Equal(t, byte(TUNNEL_BUILD_REPLY_SUCCESS), decrypted.Reply, "Reply code should be SUCCESS")
}

func TestGenerateAndSendBuildReply_AllReplyCodes(t *testing.T) {
	testCases := []struct {
		name      string
		replyCode byte
	}{
		{"SUCCESS", TUNNEL_BUILD_REPLY_SUCCESS},
		{"REJECT", TUNNEL_BUILD_REPLY_REJECT},
		{"OVERLOAD", TUNNEL_BUILD_REPLY_OVERLOAD},
		{"BANDWIDTH", TUNNEL_BUILD_REPLY_BANDWIDTH},
		{"INVALID", TUNNEL_BUILD_REPLY_INVALID},
		{"EXPIRED", TUNNEL_BUILD_REPLY_EXPIRED},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			processor := NewMessageProcessor()
			mockForwarder := newMockBuildReplyForwarder()
			mockParticipant := newMockParticipantManager(true)

			processor.SetBuildReplyForwarder(mockForwarder)
			processor.SetParticipantManager(mockParticipant)

			record := createTestBuildRequestRecord(t)
			record.NextTunnel = 0 // Force direct router forwarding

			err := processor.generateAndSendBuildReply(1, 0, record, tc.replyCode, false)
			require.NoError(t, err)

			routerCalls := mockForwarder.getRouterCalls()
			require.Len(t, routerCalls, 1)

			// Verify the encrypted reply has correct reply code
			crypto := NewBuildRecordCrypto()
			decrypted, err := crypto.DecryptReplyRecord(routerCalls[0].encryptedRecords, record.ReplyKey, record.ReplyIV)
			require.NoError(t, err)
			assert.Equal(t, tc.replyCode, decrypted.Reply, "Reply code should match")
		})
	}
}

func TestForwardBuildReply_RouterForwardError(t *testing.T) {
	// Setup
	processor := NewMessageProcessor()
	mockForwarder := newMockBuildReplyForwarder()
	mockForwarder.forwardToRouterErr = errors.New("network error")

	processor.SetBuildReplyForwarder(mockForwarder)

	record := createTestBuildRequestRecord(t)
	record.NextTunnel = 0 // Direct router forwarding

	// Execute
	err := processor.forwardBuildReply(1, record, []byte("test-encrypted-data"), false)

	// Verify
	assert.Error(t, err, "Should return error from forwarder")
	assert.Contains(t, err.Error(), "network error")
}

func TestForwardBuildReply_TunnelForwardError(t *testing.T) {
	// Setup
	processor := NewMessageProcessor()
	mockForwarder := newMockBuildReplyForwarder()
	mockForwarder.forwardToTunnelErr = errors.New("tunnel error")

	processor.SetBuildReplyForwarder(mockForwarder)

	record := createTestBuildRequestRecord(t)
	record.NextTunnel = tunnel.TunnelID(12345) // Tunnel forwarding

	// Execute
	err := processor.forwardBuildReply(1, record, []byte("test-encrypted-data"), false)

	// Verify
	assert.Error(t, err, "Should return error from forwarder")
	assert.Contains(t, err.Error(), "tunnel error")
}

func TestMultipleBuildRecords_Processing(t *testing.T) {
	// Setup
	processor := NewMessageProcessor()
	mockForwarder := newMockBuildReplyForwarder()
	mockParticipant := newMockParticipantManager(true)

	processor.SetBuildReplyForwarder(mockForwarder)
	processor.SetParticipantManager(mockParticipant)

	// Create multiple records
	records := make([]BuildRequestRecord, 5)
	for i := 0; i < 5; i++ {
		records[i] = createTestBuildRequestRecord(t)
		if i%2 == 0 {
			records[i].NextTunnel = 0 // Router forwarding
		} else {
			records[i].NextTunnel = tunnel.TunnelID(1000 + i) // Tunnel forwarding
		}
	}

	messageID := 2000

	// Execute
	processor.processAllBuildRecords(messageID, records, false)

	// Verify
	assert.Equal(t, 5, mockParticipant.getRegisteredCount(), "All participants should be registered")

	routerCalls := mockForwarder.getRouterCalls()
	tunnelCalls := mockForwarder.getTunnelCalls()

	// 3 records with NextTunnel=0 (indices 0, 2, 4)
	assert.Len(t, routerCalls, 3, "Should have 3 router forward calls")
	// 2 records with NextTunnel!=0 (indices 1, 3)
	assert.Len(t, tunnelCalls, 2, "Should have 2 tunnel forward calls")
}

func TestSetBuildReplyForwarder(t *testing.T) {
	processor := NewMessageProcessor()
	assert.Nil(t, processor.buildReplyForwarder, "Initially should be nil")

	mockForwarder := newMockBuildReplyForwarder()
	processor.SetBuildReplyForwarder(mockForwarder)

	assert.NotNil(t, processor.buildReplyForwarder, "Should be set after call")
}

func TestBuildRecordCrypto_InitializedInProcessor(t *testing.T) {
	processor := NewMessageProcessor()
	assert.NotNil(t, processor.buildRecordCrypto, "BuildRecordCrypto should be initialized by default")
}
