// Mock types for interfaces used in I2NP tests.
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
	sentMessages []Message
}

func NewMockTransportSession() *MockTransportSession {
	return &MockTransportSession{
		sentMessages: make([]Message, 0),
	}
}

func (m *MockTransportSession) QueueSendI2NP(msg Message) error {
	m.sentMessages = append(m.sentMessages, msg)
	return nil
}

func (m *MockTransportSession) SendQueueSize() int {
	return len(m.sentMessages)
}

func (m *MockTransportSession) GetSentMessages() []Message {
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

func (m *MockSessionProvider) GetSessionByHash(hash common.Hash) (I2NPTransportSession, error) {
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
	inputMessageType int // track input message type for reply type verification
}

type tunnelForwardCall struct {
	gatewayHash      common.Hash
	tunnelID         tunnel.TunnelID
	messageID        int
	encryptedRecords []byte
	inputMessageType int // track input message type for reply type verification
}

// requestForwardCall records a transit-hop relay of a type-25 build request.
type requestForwardCall struct {
	routerHash common.Hash
	messageID  int
	body       []byte
}

// mockBuildReplyForwarder implements BuildReplyForwarder for testing
type mockBuildReplyForwarder struct {
	mu                 sync.Mutex
	routerCalls        []routerForwardCall
	tunnelCalls        []tunnelForwardCall
	requestCalls       []requestForwardCall
	forwardToRouterErr error
	forwardToTunnelErr error
	forwardRequestErr  error
}

func newMockBuildReplyForwarder() *mockBuildReplyForwarder {
	return &mockBuildReplyForwarder{
		routerCalls: make([]routerForwardCall, 0),
		tunnelCalls: make([]tunnelForwardCall, 0),
	}
}

func (m *mockBuildReplyForwarder) ForwardBuildReplyToRouter(routerHash common.Hash, messageID int, encryptedRecords []byte, inputMessageType int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.routerCalls = append(m.routerCalls, routerForwardCall{
		routerHash:       routerHash,
		messageID:        messageID,
		encryptedRecords: encryptedRecords,
		inputMessageType: inputMessageType,
	})
	return m.forwardToRouterErr
}

func (m *mockBuildReplyForwarder) ForwardBuildReplyThroughTunnel(gatewayHash common.Hash, tunnelID tunnel.TunnelID, messageID int, encryptedRecords []byte, inputMessageType int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tunnelCalls = append(m.tunnelCalls, tunnelForwardCall{
		gatewayHash:      gatewayHash,
		tunnelID:         tunnelID,
		messageID:        messageID,
		encryptedRecords: encryptedRecords,
		inputMessageType: inputMessageType,
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

func (m *mockBuildReplyForwarder) ForwardBuildRequestToRouter(routerHash common.Hash, messageID int, body []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]byte, len(body))
	copy(cp, body)
	m.requestCalls = append(m.requestCalls, requestForwardCall{
		routerHash: routerHash,
		messageID:  messageID,
		body:       cp,
	})
	return m.forwardRequestErr
}

func (m *mockBuildReplyForwarder) getRequestCalls() []requestForwardCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]requestForwardCall, len(m.requestCalls))
	copy(result, m.requestCalls)
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
	bwRejectCode    byte
	bwAvailableKBps uint32
}

func newMockParticipantManager(acceptAll bool) *mockParticipantManager {
	return &mockParticipantManager{
		acceptAll:    acceptAll,
		rejectCode:   TunnelBuildReplyProbabilisticReject,
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

func (m *mockParticipantManager) RegisterParticipant(tunnelID tunnel.TunnelID, sourceHash common.Hash, expiry time.Time, layerKey, ivKey session_key.SessionKey, nextHopIdent common.Hash, nextHopTunnel tunnel.TunnelID) error {
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

func (m *mockParticipantManager) EvaluateBuildBandwidth(minKBps, requestedKBps uint32) (rejectCode byte, availableKBps uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.bwRejectCode, m.bwAvailableKBps
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
		// OBEP by default: the reply-generation tests exercise the endpoint
		// branch (send a type-26 OutboundTunnelBuildReply). Transit-relay tests
		// clear this flag explicitly.
		Flag:          tunnel.FlagOBEP,
		RequestTime:   time.Now(),
		SendMessageID: 42,
		Padding:       padding,
	}
}

// --- Shared helpers: tunnel build reply factories ---
//
// These factories build OutboundTunnelBuildReply values (the reply this router
// implements, type 26 — the counterpart of ShortTunnelBuild 25) so the
// reply-handler tests exercise the shared processReplySteps path. The fixed
// 8-record TunnelBuildReply (type 22) and VariableTunnelBuildReply (type 24) are
// not implemented: their 528-byte records are dropped by the dispatch.

// createSuccessfulTunnelBuildReply creates a reply where all hops accepted
func createSuccessfulTunnelBuildReply() *OutboundTunnelBuildReply {
	records := make([]BuildResponseRecord, 8)
	for i := range records {
		records[i] = createValidResponseRecordWithReply(TunnelBuildReplySuccess)
	}
	return &OutboundTunnelBuildReply{Count: 8, BuildResponseRecords: records}
}

// createRejectedTunnelBuildReply creates a reply where all hops rejected
func createRejectedTunnelBuildReply() *OutboundTunnelBuildReply {
	records := make([]BuildResponseRecord, 8)
	for i := range records {
		records[i] = createValidResponseRecordWithReply(TunnelBuildReplyProbabilisticReject)
	}
	return &OutboundTunnelBuildReply{Count: 8, BuildResponseRecords: records}
}

// createMixedTunnelBuildReply creates a reply with mixed responses
func createMixedTunnelBuildReply() *OutboundTunnelBuildReply {
	replyCodes := []byte{
		TunnelBuildReplySuccess,
		TunnelBuildReplySuccess,
		TunnelBuildReplyProbabilisticReject,
		TunnelBuildReplySuccess,
		TunnelBuildReplyTransientOverload,
		TunnelBuildReplySuccess,
		TunnelBuildReplyBandwidth,
		TunnelBuildReplySuccess,
	}
	records := make([]BuildResponseRecord, len(replyCodes))
	for i, replyCode := range replyCodes {
		records[i] = createValidResponseRecordWithReply(replyCode)
	}
	return &OutboundTunnelBuildReply{Count: len(records), BuildResponseRecords: records}
}

// createSingleFailureTunnelBuildReply creates a reply with one failure
func createSingleFailureTunnelBuildReply() *OutboundTunnelBuildReply {
	records := make([]BuildResponseRecord, 8)
	for i := range records {
		if i == 3 {
			records[i] = createValidResponseRecordWithReply(TunnelBuildReplyTransientOverload)
		} else {
			records[i] = createValidResponseRecordWithReply(TunnelBuildReplySuccess)
		}
	}
	return &OutboundTunnelBuildReply{Count: 8, BuildResponseRecords: records}
}

// createUnknownReplyCodeTunnelBuildReply creates a reply with unknown reply code
func createUnknownReplyCodeTunnelBuildReply() *OutboundTunnelBuildReply {
	records := make([]BuildResponseRecord, 8)
	for i := range records {
		if i == 0 {
			records[i] = createValidResponseRecordWithReply(0xFF)
		} else {
			records[i] = createValidResponseRecordWithReply(TunnelBuildReplySuccess)
		}
	}
	return &OutboundTunnelBuildReply{Count: 8, BuildResponseRecords: records}
}

// createEmptyHashTunnelBuildReply creates a reply with empty hash
func createEmptyHashTunnelBuildReply() *OutboundTunnelBuildReply {
	records := make([]BuildResponseRecord, 8)
	for i := range records {
		if i == 0 {
			records[i] = BuildResponseRecord{
				Hash:       common.Hash{},
				RandomData: [495]byte{},
				Reply:      TunnelBuildReplySuccess,
			}
		} else {
			records[i] = createValidResponseRecord()
			records[i].Reply = TunnelBuildReplySuccess
		}
	}
	return &OutboundTunnelBuildReply{Count: 8, BuildResponseRecords: records}
}

// createSuccessfulOutboundTunnelBuildReply creates a successful OutboundTunnelBuildReply
func createSuccessfulOutboundTunnelBuildReply(hopCount int) *OutboundTunnelBuildReply {
	records := make([]BuildResponseRecord, hopCount)
	for i := 0; i < hopCount; i++ {
		records[i] = createValidResponseRecordWithReply(TunnelBuildReplySuccess)
	}
	return &OutboundTunnelBuildReply{
		Count:                hopCount,
		BuildResponseRecords: records,
	}
}

// createMixedOutboundTunnelBuildReply creates a OutboundTunnelBuildReply with mixed responses
func createMixedOutboundTunnelBuildReply(hopCount int) *OutboundTunnelBuildReply {
	records := make([]BuildResponseRecord, hopCount)
	replyCodes := []byte{
		TunnelBuildReplySuccess,
		TunnelBuildReplyProbabilisticReject,
		TunnelBuildReplySuccess,
		TunnelBuildReplyTransientOverload,
	}
	for i := 0; i < hopCount; i++ {
		records[i] = createValidResponseRecordWithReply(replyCodes[i%len(replyCodes)])
	}
	return &OutboundTunnelBuildReply{
		Count:                hopCount,
		BuildResponseRecords: records,
	}
}

// createValidResponseRecord creates a valid BuildResponseRecord for testing
func createValidResponseRecord() BuildResponseRecord {
	return createValidResponseRecordWithReply(TunnelBuildReplySuccess)
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
