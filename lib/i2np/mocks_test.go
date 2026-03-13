package i2np

import (
	"fmt"
	"sync"
	"time"

	"github.com/go-i2p/crypto/types"

	common "github.com/go-i2p/common/data"
	router_info "github.com/go-i2p/common/router_info"
	"github.com/go-i2p/common/session_key"
	"github.com/go-i2p/go-i2p/lib/tunnel"
)

// --- MockNetDBRetriever ---

// MockNetDBRetriever implements NetDBRetriever for testing
type MockNetDBRetriever struct {
	data map[common.Hash][]byte
}

func NewMockNetDBRetriever() *MockNetDBRetriever {
	return &MockNetDBRetriever{
		data: make(map[common.Hash][]byte),
	}
}

func (m *MockNetDBRetriever) GetRouterInfoBytes(hash common.Hash) ([]byte, error) {
	if data, exists := m.data[hash]; exists {
		return data, nil
	}
	return nil, fmt.Errorf("RouterInfo not found")
}

func (m *MockNetDBRetriever) GetRouterInfoCount() int {
	return len(m.data)
}

func (m *MockNetDBRetriever) AddRouterInfo(hash common.Hash, data []byte) {
	m.data[hash] = data
}

// --- MockTransportSession ---

// MockTransportSession implements TransportSession for testing
type MockTransportSession struct {
	sentMessages []I2NPMessage
}

func NewMockTransportSession() *MockTransportSession {
	return &MockTransportSession{
		sentMessages: make([]I2NPMessage, 0),
	}
}

func (m *MockTransportSession) QueueSendI2NP(msg I2NPMessage) error {
	m.sentMessages = append(m.sentMessages, msg)
	return nil
}

func (m *MockTransportSession) SendQueueSize() int {
	return len(m.sentMessages)
}

func (m *MockTransportSession) GetSentMessages() []I2NPMessage {
	return m.sentMessages
}

// --- MockSessionProvider ---

// MockSessionProvider implements SessionProvider for testing
type MockSessionProvider struct {
	session *MockTransportSession
}

func NewMockSessionProvider() *MockSessionProvider {
	return &MockSessionProvider{
		session: NewMockTransportSession(),
	}
}

func (m *MockSessionProvider) GetSessionByHash(hash common.Hash) (TransportSession, error) {
	return m.session, nil
}

func (m *MockSessionProvider) GetMockSession() *MockTransportSession {
	return m.session
}

// --- MockPeerSelector ---

// MockPeerSelector implements tunnel.PeerSelector for testing
type MockPeerSelector struct {
	peers []router_info.RouterInfo
}

func (m *MockPeerSelector) SelectPeers(count int, exclude []common.Hash) ([]router_info.RouterInfo, error) {
	if len(m.peers) < count {
		return m.peers, nil // Return what we have
	}
	return m.peers[:count], nil
}

// --- SimpleMockPeerSelector ---

// SimpleMockPeerSelector implements tunnel.PeerSelector without requiring RouterInfo initialization
type SimpleMockPeerSelector struct{}

func (s *SimpleMockPeerSelector) SelectPeers(count int, exclude []common.Hash) ([]router_info.RouterInfo, error) {
	// Return empty slice to simulate sufficient peers without requiring RouterInfo initialization
	// This allows testing the TunnelManager logic without complex RouterInfo setup
	peers := make([]router_info.RouterInfo, count)
	return peers, nil
}

// --- mockBuildReplyForwarder ---

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

// mockBuildReplyForwarder implements BuildReplyForwarder for testing
type mockBuildReplyForwarder struct {
	mu                 sync.Mutex
	routerCalls        []routerForwardCall
	tunnelCalls        []tunnelForwardCall
	forwardToRouterErr error
	forwardToTunnelErr error
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

// --- mockParticipantManager ---

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

// --- Shared helper: createTestBuildRequestRecord ---

// createTestBuildRequestRecord creates a test BuildRequestRecord with randomized data
func createTestBuildRequestRecord(t interface{ Helper() }) BuildRequestRecord {
	t.Helper()

	layerKey, ivKey, replyKey, replyIV, padding, ourIdent, nextIdent := generateRandomBuildKeys()

	return BuildRequestRecord{
		ReceiveTunnel: tunnel.TunnelID(12345),
		OurIdent:      ourIdent,
		NextTunnel:    tunnel.TunnelID(67890),
		NextIdent:     nextIdent,
		LayerKey:      layerKey,
		IVKey:         ivKey,
		ReplyKey:      replyKey,
		ReplyIV:       replyIV,
		Flag:          0,
		RequestTime:   time.Now(),
		SendMessageID: 42,
		Padding:       padding,
	}
}

// --- Shared helpers: tunnel build reply factories ---

// createSuccessfulTunnelBuildReply creates a TunnelBuildReply where all hops accepted
func createSuccessfulTunnelBuildReply() *TunnelBuildReply {
	var reply TunnelBuildReply
	for i := 0; i < 8; i++ {
		reply.Records[i] = createValidResponseRecordWithReply(TUNNEL_BUILD_REPLY_SUCCESS)
	}
	return &reply
}

// createRejectedTunnelBuildReply creates a TunnelBuildReply where all hops rejected
func createRejectedTunnelBuildReply() *TunnelBuildReply {
	var reply TunnelBuildReply
	for i := 0; i < 8; i++ {
		reply.Records[i] = createValidResponseRecordWithReply(TUNNEL_BUILD_REPLY_REJECT)
	}
	return &reply
}

// createMixedTunnelBuildReply creates a TunnelBuildReply with mixed responses
func createMixedTunnelBuildReply() *TunnelBuildReply {
	var reply TunnelBuildReply
	replyCodes := []byte{
		TUNNEL_BUILD_REPLY_SUCCESS,
		TUNNEL_BUILD_REPLY_SUCCESS,
		TUNNEL_BUILD_REPLY_REJECT,
		TUNNEL_BUILD_REPLY_SUCCESS,
		TUNNEL_BUILD_REPLY_OVERLOAD,
		TUNNEL_BUILD_REPLY_SUCCESS,
		TUNNEL_BUILD_REPLY_BANDWIDTH,
		TUNNEL_BUILD_REPLY_SUCCESS,
	}
	for i, replyCode := range replyCodes {
		reply.Records[i] = createValidResponseRecordWithReply(replyCode)
	}
	return &reply
}

// createSingleFailureTunnelBuildReply creates a TunnelBuildReply with one failure
func createSingleFailureTunnelBuildReply() *TunnelBuildReply {
	var reply TunnelBuildReply
	for i := 0; i < 8; i++ {
		if i == 3 {
			reply.Records[i] = createValidResponseRecordWithReply(TUNNEL_BUILD_REPLY_OVERLOAD)
		} else {
			reply.Records[i] = createValidResponseRecordWithReply(TUNNEL_BUILD_REPLY_SUCCESS)
		}
	}
	return &reply
}

// createUnknownReplyCodeTunnelBuildReply creates a TunnelBuildReply with unknown reply code
func createUnknownReplyCodeTunnelBuildReply() *TunnelBuildReply {
	var reply TunnelBuildReply
	for i := 0; i < 8; i++ {
		if i == 0 {
			reply.Records[i] = createValidResponseRecordWithReply(0xFF)
		} else {
			reply.Records[i] = createValidResponseRecordWithReply(TUNNEL_BUILD_REPLY_SUCCESS)
		}
	}
	return &reply
}

// createEmptyHashTunnelBuildReply creates a TunnelBuildReply with empty hash
func createEmptyHashTunnelBuildReply() *TunnelBuildReply {
	var reply TunnelBuildReply
	for i := 0; i < 8; i++ {
		if i == 0 {
			reply.Records[i] = BuildResponseRecord{
				Hash:       common.Hash{},
				RandomData: [495]byte{},
				Reply:      TUNNEL_BUILD_REPLY_SUCCESS,
			}
		} else {
			reply.Records[i] = createValidResponseRecord()
			reply.Records[i].Reply = TUNNEL_BUILD_REPLY_SUCCESS
		}
	}
	return &reply
}

// createSuccessfulVariableTunnelBuildReply creates a successful VariableTunnelBuildReply
func createSuccessfulVariableTunnelBuildReply(hopCount int) *VariableTunnelBuildReply {
	records := make([]BuildResponseRecord, hopCount)
	for i := 0; i < hopCount; i++ {
		records[i] = createValidResponseRecordWithReply(TUNNEL_BUILD_REPLY_SUCCESS)
	}
	return &VariableTunnelBuildReply{
		Count:                hopCount,
		BuildResponseRecords: records,
	}
}

// createMixedVariableTunnelBuildReply creates a VariableTunnelBuildReply with mixed responses
func createMixedVariableTunnelBuildReply(hopCount int) *VariableTunnelBuildReply {
	records := make([]BuildResponseRecord, hopCount)
	replyCodes := []byte{
		TUNNEL_BUILD_REPLY_SUCCESS,
		TUNNEL_BUILD_REPLY_REJECT,
		TUNNEL_BUILD_REPLY_SUCCESS,
		TUNNEL_BUILD_REPLY_OVERLOAD,
	}
	for i := 0; i < hopCount; i++ {
		records[i] = createValidResponseRecordWithReply(replyCodes[i%len(replyCodes)])
	}
	return &VariableTunnelBuildReply{
		Count:                hopCount,
		BuildResponseRecords: records,
	}
}

// createValidResponseRecord creates a valid BuildResponseRecord for testing
func createValidResponseRecord() BuildResponseRecord {
	return createValidResponseRecordWithReply(TUNNEL_BUILD_REPLY_SUCCESS)
}

// createValidResponseRecordWithReply creates a valid BuildResponseRecord with a specific reply code
func createValidResponseRecordWithReply(replyCode byte) BuildResponseRecord {
	var randomData [495]byte
	copy(randomData[:], "test_random_data_for_response_record")

	// Compute the correct hash: SHA256(randomData + reply)
	data := make([]byte, 496)
	copy(data[0:495], randomData[:])
	data[495] = replyCode

	hash := types.SHA256(data)

	return BuildResponseRecord{
		Hash:       hash,
		RandomData: randomData,
		Reply:      replyCode,
	}
}
