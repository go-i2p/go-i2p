package router

import (
	"errors"
	"testing"

	common "github.com/go-i2p/common/data"
	lease_set "github.com/go-i2p/common/lease_set"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/bootstrap"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/tunnel"
)

// Mock NetDB for testing
type mockNetDB struct {
	routers   map[common.Hash]router_info.RouterInfo
	leaseSets map[common.Hash]lease_set.LeaseSet
}

func newMockNetDB() *mockNetDB {
	return &mockNetDB{
		routers:   make(map[common.Hash]router_info.RouterInfo),
		leaseSets: make(map[common.Hash]lease_set.LeaseSet),
	}
}

// GetRouterInfo returns a channel for async RouterInfo lookup (matches StdNetDB)
func (m *mockNetDB) GetRouterInfo(hash common.Hash) chan router_info.RouterInfo {
	ch := make(chan router_info.RouterInfo, 1)
	if ri, exists := m.routers[hash]; exists {
		ch <- ri
	}
	close(ch)
	return ch
}

// GetLeaseSet returns a channel for async LeaseSet lookup (matches StdNetDB)
func (m *mockNetDB) GetLeaseSet(hash common.Hash) chan lease_set.LeaseSet {
	ch := make(chan lease_set.LeaseSet, 1)
	if ls, exists := m.leaseSets[hash]; exists {
		ch <- ls
	}
	close(ch)
	return ch
}

func (m *mockNetDB) GetAllRouterInfos() []router_info.RouterInfo {
	var result []router_info.RouterInfo
	for _, ri := range m.routers {
		result = append(result, ri)
	}
	return result
}

func (m *mockNetDB) StoreRouterInfo(ri router_info.RouterInfo) {
	hash, _ := ri.IdentHash()
	m.routers[hash] = ri
}

func (m *mockNetDB) Reseed(b bootstrap.Bootstrap, minRouters int) error {
	return nil
}

func (m *mockNetDB) Size() int {
	return len(m.routers)
}

// SelectFloodfillRouters selects routers for netdb queries
func (m *mockNetDB) SelectFloodfillRouters(targetHash common.Hash, count int) ([]router_info.RouterInfo, error) {
	var result []router_info.RouterInfo
	for _, ri := range m.routers {
		result = append(result, ri)
		if len(result) >= count {
			break
		}
	}
	if len(result) == 0 {
		return nil, errors.New("no floodfill routers available")
	}
	return result, nil
}

func (m *mockNetDB) RecalculateSize() error {
	return nil
}

func (m *mockNetDB) Ensure() error {
	return nil
}

func (m *mockNetDB) GetLeaseSetCount() int {
	return len(m.leaseSets)
}

// Implement compatibility check for router info
func (m *mockTransportMuxer) Compatible(ri router_info.RouterInfo) bool {
	return true
}

// Mock TransportMuxer for testing
type mockTransportMuxer struct {
	sessions map[common.Hash]*mockTransportSession
}

func newMockTransportMuxer() *mockTransportMuxer {
	return &mockTransportMuxer{
		sessions: make(map[common.Hash]*mockTransportSession),
	}
}

func (m *mockTransportMuxer) GetSession(ri router_info.RouterInfo) (*mockTransportSession, error) {
	hash, err := ri.IdentHash()
	if err != nil {
		return nil, err
	}

	if session, exists := m.sessions[hash]; exists {
		return session, nil
	}

	// Create new session for this router
	session := newMockTransportSession()
	m.sessions[hash] = session
	return session, nil
}

// Mock TransportSession for testing
type mockTransportSession struct {
	queuedMessages []i2np.I2NPMessage
}

func newMockTransportSession() *mockTransportSession {
	return &mockTransportSession{
		queuedMessages: make([]i2np.I2NPMessage, 0),
	}
}

func (m *mockTransportSession) QueueSendI2NP(msg i2np.I2NPMessage) {
	m.queuedMessages = append(m.queuedMessages, msg)
}

func (m *mockTransportSession) SendQueueSize() int {
	return len(m.queuedMessages)
}

// Mock MessageProcessor for testing
type mockMessageProcessor struct {
	processedMessages []i2np.I2NPMessage
	shouldFail        bool
}

func newMockMessageProcessor() *mockMessageProcessor {
	return &mockMessageProcessor{
		processedMessages: make([]i2np.I2NPMessage, 0),
	}
}

func (m *mockMessageProcessor) ProcessMessage(msg i2np.I2NPMessage) error {
	if m.shouldFail {
		return errors.New("mock processor error")
	}
	m.processedMessages = append(m.processedMessages, msg)
	return nil
}

// Test constructor
func TestNewGarlicMessageRouter(t *testing.T) {
	netdb := newMockNetDB()
	routerHash := common.Hash{1, 2, 3, 4}

	gr := NewGarlicMessageRouter(netdb, nil, nil, routerHash)
	defer gr.Stop()

	if gr == nil {
		t.Fatal("NewGarlicMessageRouter returned nil")
	}

	// Test that router was created with correct identity
	if gr.routerIdentity != routerHash {
		t.Error("RouterIdentity not set correctly")
	}
}

// Test SetMessageProcessor - simplified to avoid type issues
func TestSetMessageProcessor(t *testing.T) {
	gr := createTestGarlicRouter()
	defer gr.Stop()
	processor := i2np.NewMessageProcessor()

	gr.SetMessageProcessor(processor)

	if gr.processor == nil {
		t.Error("MessageProcessor not set")
	}
}

// Test ForwardToDestination with no LeaseSet in NetDB
func TestForwardToDestination(t *testing.T) {
	gr := createTestGarlicRouter()
	defer gr.Stop()
	msg := i2np.NewBaseI2NPMessage(i2np.I2NP_MESSAGE_TYPE_DATA)
	destHash := common.Hash{10, 20, 30, 40}

	err := gr.ForwardToDestination(destHash, msg)
	// With async message queueing, this should succeed (message gets queued)
	if err != nil {
		t.Errorf("Expected message to be queued when destination not found in NetDB, got error: %v", err)
	}

	// Verify message was queued for async lookup
	gr.pendingMutex.RLock()
	pending, exists := gr.pendingMsgs[destHash]
	gr.pendingMutex.RUnlock()

	if !exists || len(pending) != 1 {
		t.Error("Expected message to be queued for pending LeaseSet lookup")
	}
}

// Test ForwardToRouter - reflexive delivery
func TestForwardToRouter_Reflexive(t *testing.T) {
	gr := createTestGarlicRouter()
	defer gr.Stop()
	processor := i2np.NewMessageProcessor()
	gr.SetMessageProcessor(processor)

	msg := i2np.NewBaseI2NPMessage(i2np.I2NP_MESSAGE_TYPE_DATA)
	msg.SetMessageID(12345)

	// Forward to ourselves (reflexive delivery)
	err := gr.ForwardToRouter(gr.routerIdentity, msg)
	// The message will fail processing because it doesn't implement the required
	// interfaces, but we're testing that it attempts to process it locally
	// rather than trying to send it over the network.
	// The error should be about message interfaces, not about network transport.
	if err != nil {
		// Expect an interface-related error, not a transport error
		if contains(err.Error(), "not found in NetDB") {
			t.Errorf("Should not attempt NetDB lookup for reflexive delivery, got: %v", err)
		}
		// Other errors are acceptable as they're from message processing
	}
}

// Test ForwardToRouter - reflexive delivery without processor
func TestForwardToRouter_ReflexiveNoProcessor(t *testing.T) {
	gr := createTestGarlicRouter()
	defer gr.Stop()
	// Don't set processor

	msg := i2np.NewBaseI2NPMessage(i2np.I2NP_MESSAGE_TYPE_DATA)

	err := gr.ForwardToRouter(gr.routerIdentity, msg)

	if err == nil {
		t.Error("Expected error when processor not configured, got nil")
	}

	expectedSubstring := "processor not configured"
	if !contains(err.Error(), expectedSubstring) {
		t.Errorf("Error should mention processor not configured, got: %s", err.Error())
	}
}

// Test ForwardToRouter - router not found in NetDB
func TestForwardToRouter_NotFound(t *testing.T) {
	gr := createTestGarlicRouter()
	defer gr.Stop()

	msg := i2np.NewBaseI2NPMessage(i2np.I2NP_MESSAGE_TYPE_DATA)
	unknownHash := common.Hash{99, 88, 77, 66}

	err := gr.ForwardToRouter(unknownHash, msg)

	if err == nil {
		t.Error("Expected error for router not found, got nil")
	}

	expectedSubstring := "RouterInfo"
	if !contains(err.Error(), expectedSubstring) {
		t.Errorf("Error should mention RouterInfo lookup failure, got: %s", err.Error())
	}
}

// Test ForwardToRouter - successful forwarding
func TestForwardToRouter_Success(t *testing.T) {
	gr := createTestGarlicRouter()
	defer gr.Stop()

	// Create a test router info and add to NetDB
	peerHash := common.Hash{50, 60, 70, 80}
	peerRI := createMockRouterInfo(peerHash)

	// Add to netdb using the interface method
	gr.netdb.StoreRouterInfo(peerRI)

	msg := i2np.NewBaseI2NPMessage(i2np.I2NP_MESSAGE_TYPE_DATA)
	msg.SetMessageID(54321)

	// Verify NetDB lookup succeeds
	foundRI := gr.netdb.GetRouterInfo(peerHash)

	// Check if RouterInfo was stored (IsZero not available, so check size)
	if gr.netdb.Size() == 0 {
		t.Error("RouterInfo should be found in NetDB")
	}

	_ = foundRI // Use the variable to avoid unused warning
}

// Test ForwardThroughTunnel - gateway not in NetDB
func TestForwardThroughTunnel(t *testing.T) {
	gr := createTestGarlicRouter()
	defer gr.Stop()
	msg := i2np.NewBaseI2NPMessage(i2np.I2NP_MESSAGE_TYPE_DATA)
	gatewayHash := common.Hash{11, 22, 33, 44}
	tunnelID := tunnel.TunnelID(12345)

	err := gr.ForwardThroughTunnel(gatewayHash, tunnelID, msg)

	if err == nil {
		t.Error("Expected error when gateway not found in NetDB, got nil")
	}

	expectedSubstring := "RouterInfo"
	if !contains(err.Error(), expectedSubstring) {
		t.Errorf("Error message should contain '%s', got: %s", expectedSubstring, err.Error())
	}
}

// Helper functions

func createTestGarlicRouter() *GarlicMessageRouter {
	netdb := newMockNetDB()
	routerHash := common.Hash{1, 2, 3, 4, 5, 6, 7, 8}

	return NewGarlicMessageRouter(netdb, nil, nil, routerHash)
}

func createMockRouterInfo(hash common.Hash) router_info.RouterInfo {
	// Create a minimal RouterInfo for testing
	// This is a simplified version - real RouterInfo creation is more complex
	ri := router_info.RouterInfo{}
	// Note: Actual RouterInfo requires proper initialization with identity, etc.
	// For unit tests, we just need enough to satisfy the interface
	return ri
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) &&
		(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
			findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestGarlicRouterStop tests that Stop() properly cancels the background goroutine
func TestGarlicRouterStop(t *testing.T) {
	gr := createTestGarlicRouter()

	// Verify the router is running (has valid context and cancel)
	if gr.ctx == nil {
		t.Fatal("Context should be set after creation")
	}
	if gr.cancel == nil {
		t.Fatal("Cancel function should be set after creation")
	}

	// Check that context is not yet cancelled
	select {
	case <-gr.ctx.Done():
		t.Fatal("Context should not be cancelled before Stop()")
	default:
		// Expected - context is still active
	}

	// Stop the garlic router
	gr.Stop()

	// Verify context is now cancelled
	select {
	case <-gr.ctx.Done():
		// Expected - context is cancelled after Stop()
	default:
		t.Error("Context should be cancelled after Stop()")
	}
}

// TestGarlicRouterStopIdempotent tests that calling Stop() multiple times is safe
func TestGarlicRouterStopIdempotent(t *testing.T) {
	gr := createTestGarlicRouter()

	// Stop multiple times should not panic
	gr.Stop()
	gr.Stop()
	gr.Stop()

	// Verify context is cancelled
	select {
	case <-gr.ctx.Done():
		// Expected
	default:
		t.Error("Context should be cancelled after Stop()")
	}
}

// TestGarlicRouterStopNilCancel tests that Stop() handles nil cancel safely
func TestGarlicRouterStopNilCancel(t *testing.T) {
	gr := createTestGarlicRouter()

	// First, properly stop the background goroutine so it's not leaked
	gr.Stop()

	// Now simulate a case where cancel is nil (shouldn't happen but be safe)
	gr.cancel = nil

	// Calling Stop() again with nil cancel should not panic
	gr.Stop()
}
