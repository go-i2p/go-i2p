package i2np

import (
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
)

// mockFloodfillNetDB implements NetDBStore, NetDBRetriever, and FloodfillSelector
type mockFloodfillNetDB struct {
	routerInfos          map[common.Hash][]byte
	floodfillCount       int // Track number of floodfills without actual RouterInfo
	selectCalled         bool
	selectTargetHash     common.Hash
	selectRequestedCount int
}

func newMockFloodfillNetDB() *mockFloodfillNetDB {
	return &mockFloodfillNetDB{
		routerInfos: make(map[common.Hash][]byte),
	}
}

// NetDBStore interface
func (m *mockFloodfillNetDB) Store(key common.Hash, data []byte, dataType byte) error {
	m.routerInfos[key] = data
	return nil
}

// NetDBRetriever interface
func (m *mockFloodfillNetDB) GetRouterInfoBytes(hash common.Hash) ([]byte, error) {
	if data, exists := m.routerInfos[hash]; exists {
		return data, nil
	}
	return nil, nil
}

func (m *mockFloodfillNetDB) GetRouterInfoCount() int {
	return len(m.routerInfos)
}

// FloodfillSelector interface - returns empty RouterInfos for testing
func (m *mockFloodfillNetDB) SelectFloodfillRouters(targetHash common.Hash, count int) ([]router_info.RouterInfo, error) {
	m.selectCalled = true
	m.selectTargetHash = targetHash
	m.selectRequestedCount = count

	// Return empty RouterInfos up to count or floodfillCount, whichever is smaller
	resultCount := count
	if m.floodfillCount < count {
		resultCount = m.floodfillCount
	}

	// Return empty RouterInfos (we can't easily create valid ones in tests)
	result := make([]router_info.RouterInfo, resultCount)
	return result, nil
}

// Helper to add a mock floodfill router
func (m *mockFloodfillNetDB) addFloodfillRouter() {
	m.floodfillCount++
}

// TestDatabaseManager_FloodfillConfiguration tests that floodfill selector is properly configured
func TestDatabaseManager_FloodfillConfiguration(t *testing.T) {
	mockNetDB := newMockFloodfillNetDB()
	dbManager := NewDatabaseManager(mockNetDB)

	// Configure floodfill selector
	dbManager.SetFloodfillSelector(mockNetDB)
	dbManager.SetRetriever(mockNetDB)

	if dbManager.floodfillSelector == nil {
		t.Error("FloodfillSelector should be configured")
	}

	if dbManager.retriever == nil {
		t.Error("NetDBRetriever should be configured")
	}
}

// TestDatabaseManager_SelectClosestFloodfills tests floodfill router selection
func TestDatabaseManager_SelectClosestFloodfills(t *testing.T) {
	mockNetDB := newMockFloodfillNetDB()

	// Add some mock floodfill routers
	for i := 0; i < 10; i++ {
		mockNetDB.addFloodfillRouter()
	}

	dbManager := NewDatabaseManager(mockNetDB)
	dbManager.SetFloodfillSelector(mockNetDB)

	targetKey := common.Hash{0xFF}
	// Don't call IdentHash() on the returned RouterInfos - just check the count
	_ = dbManager.selectClosestFloodfills(targetKey)

	// Verify SelectFloodfillRouters was called with correct parameters
	if !mockNetDB.selectCalled {
		t.Error("SelectFloodfillRouters should have been called")
	}

	if mockNetDB.selectTargetHash != targetKey {
		t.Errorf("Expected target hash %x, got %x", targetKey, mockNetDB.selectTargetHash)
	}

	if mockNetDB.selectRequestedCount != 7 {
		t.Errorf("Expected request count 7, got %d", mockNetDB.selectRequestedCount)
	}
}

// TestDatabaseManager_SelectClosestFloodfills_LimitedPeers tests with fewer floodfills than requested
func TestDatabaseManager_SelectClosestFloodfills_LimitedPeers(t *testing.T) {
	mockNetDB := newMockFloodfillNetDB()

	// Add only 3 mock floodfill routers (less than default 7)
	for i := 0; i < 3; i++ {
		mockNetDB.addFloodfillRouter()
	}

	dbManager := NewDatabaseManager(mockNetDB)
	dbManager.SetFloodfillSelector(mockNetDB)

	targetKey := common.Hash{0xFF}
	_ = dbManager.selectClosestFloodfills(targetKey)

	// Should have requested 7 but only 3 available
	if mockNetDB.selectRequestedCount != 7 {
		t.Errorf("Expected request count 7, got %d", mockNetDB.selectRequestedCount)
	}
}

// TestDatabaseManager_SelectClosestFloodfills_NoSelector tests fallback when no selector configured
func TestDatabaseManager_SelectClosestFloodfills_NoSelector(t *testing.T) {
	dbManager := NewDatabaseManager(nil)
	// Don't set floodfill selector

	targetKey := common.Hash{0xFF}
	peerHashes := dbManager.selectClosestFloodfills(targetKey)

	// Should return empty list when no selector configured
	if len(peerHashes) != 0 {
		t.Errorf("Expected 0 floodfill suggestions without selector, got %d", len(peerHashes))
	}
}

// TestDatabaseManager_SendDatabaseSearchReply tests DatabaseSearchReply creation
func TestDatabaseManager_SendDatabaseSearchReply(t *testing.T) {
	mockNetDB := newMockFloodfillNetDB()

	// Add mock floodfill routers
	for i := 0; i < 5; i++ {
		mockNetDB.addFloodfillRouter()
	}

	dbManager := NewDatabaseManager(mockNetDB)
	dbManager.SetFloodfillSelector(mockNetDB)

	// Set our router hash
	ourHash := common.Hash{0xAA, 0xBB}
	dbManager.SetOurRouterHash(ourHash)

	// Mock session provider
	mockSession := &mockTransportSession{
		messages: make([]I2NPMessage, 0),
	}
	mockProvider := &mockSessionProvider{
		sessions: map[common.Hash]*mockTransportSession{
			{0x11}: mockSession,
		},
	}
	dbManager.SetSessionProvider(mockProvider)

	// Send DatabaseSearchReply
	targetKey := common.Hash{0xFF}
	toHash := common.Hash{0x11}
	err := dbManager.sendDatabaseSearchReply(targetKey, toHash)
	if err != nil {
		t.Fatalf("sendDatabaseSearchReply failed: %v", err)
	}

	// Verify message was queued
	if len(mockSession.messages) != 1 {
		t.Fatalf("Expected 1 message queued, got %d", len(mockSession.messages))
	}

	msg := mockSession.messages[0]
	if msg.Type() != I2NP_MESSAGE_TYPE_DATABASE_SEARCH_REPLY {
		t.Errorf("Expected DatabaseSearchReply message type, got %d", msg.Type())
	}

	// Verify SelectFloodfillRouters was called
	if !mockNetDB.selectCalled {
		t.Error("SelectFloodfillRouters should have been called")
	}
}

// TestMessageRouter_SetOurRouterHash tests router hash configuration
func TestMessageRouter_SetOurRouterHash(t *testing.T) {
	config := MessageRouterConfig{
		EnableLogging: false,
	}
	router := NewMessageRouter(config)

	ourHash := common.Hash{0xDE, 0xAD, 0xBE, 0xEF}
	router.SetOurRouterHash(ourHash)

	if router.dbManager.ourRouterHash != ourHash {
		t.Errorf("Router hash not set correctly: expected %x, got %x", ourHash, router.dbManager.ourRouterHash)
	}
}

// TestMessageRouter_SetNetDB_FloodfillAutoConfiguration tests automatic floodfill configuration
func TestMessageRouter_SetNetDB_FloodfillAutoConfiguration(t *testing.T) {
	config := MessageRouterConfig{
		EnableLogging: false,
	}
	router := NewMessageRouter(config)

	mockNetDB := newMockFloodfillNetDB()
	router.SetNetDB(mockNetDB)

	// Verify floodfill selector was auto-configured
	if router.dbManager.floodfillSelector == nil {
		t.Error("FloodfillSelector should be auto-configured from NetDB")
	}

	// Verify retriever was auto-configured
	if router.dbManager.retriever == nil {
		t.Error("NetDBRetriever should be auto-configured from NetDB")
	}
}

// TestDatabaseManager_PerformLookup_NotFound_WithFloodfills tests lookup miss returns floodfill suggestions
func TestDatabaseManager_PerformLookup_NotFound_WithFloodfills(t *testing.T) {
	mockNetDB := newMockFloodfillNetDB()

	// Add floodfill routers but no data for the lookup key
	for i := 0; i < 5; i++ {
		mockNetDB.addFloodfillRouter()
	}

	dbManager := NewDatabaseManager(mockNetDB)
	dbManager.SetFloodfillSelector(mockNetDB)
	dbManager.SetRetriever(mockNetDB)
	dbManager.SetOurRouterHash(common.Hash{0xAA})

	// Mock session provider
	mockSession := &mockTransportSession{
		messages: make([]I2NPMessage, 0),
	}
	mockProvider := &mockSessionProvider{
		sessions: map[common.Hash]*mockTransportSession{
			{0x11}: mockSession,
		},
	}
	dbManager.SetSessionProvider(mockProvider)

	// Create lookup request for non-existent key
	lookup := &DatabaseLookup{
		Key:  common.Hash{0xFF}, // Key not in NetDB
		From: common.Hash{0x11},
	}

	err := dbManager.PerformLookup(lookup)
	if err != nil {
		t.Fatalf("PerformLookup failed: %v", err)
	}

	// Verify DatabaseSearchReply was sent (not DatabaseStore)
	if len(mockSession.messages) != 1 {
		t.Fatalf("Expected 1 message, got %d", len(mockSession.messages))
	}

	msg := mockSession.messages[0]
	if msg.Type() != I2NP_MESSAGE_TYPE_DATABASE_SEARCH_REPLY {
		t.Errorf("Expected DatabaseSearchReply for lookup miss, got message type %d", msg.Type())
	}

	// Verify floodfill selection was called
	if !mockNetDB.selectCalled {
		t.Error("Floodfill selection should have been called for lookup miss")
	}
}

// TestDatabaseManager_PerformLookup_Found tests lookup success returns DatabaseStore
func TestDatabaseManager_PerformLookup_Found(t *testing.T) {
	mockNetDB := newMockFloodfillNetDB()

	// Add RouterInfo data to NetDB
	targetKey := common.Hash{0xFF}
	routerInfoData := []byte{1, 2, 3, 4, 5} // Mock RouterInfo bytes
	if err := mockNetDB.Store(targetKey, routerInfoData, 0); err != nil {
		t.Fatalf("Failed to store router info: %v", err)
	}

	dbManager := NewDatabaseManager(mockNetDB)
	dbManager.SetRetriever(mockNetDB)

	// Mock session provider
	mockSession := &mockTransportSession{
		messages: make([]I2NPMessage, 0),
	}
	mockProvider := &mockSessionProvider{
		sessions: map[common.Hash]*mockTransportSession{
			{0x11}: mockSession,
		},
	}
	dbManager.SetSessionProvider(mockProvider)

	// Create lookup request for existing key
	lookup := &DatabaseLookup{
		Key:  targetKey,
		From: common.Hash{0x11},
	}

	err := dbManager.PerformLookup(lookup)
	if err != nil {
		t.Fatalf("PerformLookup failed: %v", err)
	}

	// Verify DatabaseStore was sent (not DatabaseSearchReply)
	if len(mockSession.messages) != 1 {
		t.Fatalf("Expected 1 message, got %d", len(mockSession.messages))
	}

	msg := mockSession.messages[0]
	if msg.Type() != I2NP_MESSAGE_TYPE_DATABASE_STORE {
		t.Errorf("Expected DatabaseStore for lookup hit, got message type %d", msg.Type())
	}
}

// Mock types for testing
type mockTransportSession struct {
	messages []I2NPMessage
}

func (m *mockTransportSession) QueueSendI2NP(msg I2NPMessage) error {
	m.messages = append(m.messages, msg)
	return nil
}

func (m *mockTransportSession) SendQueueSize() int {
	return len(m.messages)
}

type mockSessionProvider struct {
	sessions map[common.Hash]*mockTransportSession
}

func (m *mockSessionProvider) GetSessionByHash(hash common.Hash) (TransportSession, error) {
	if session, exists := m.sessions[hash]; exists {
		return session, nil
	}
	return nil, nil
}
