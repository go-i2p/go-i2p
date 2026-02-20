package i2np

import (
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
)

// mockNetDBStore implements NetDBStore interface for testing
type mockNetDBStore struct {
	storeFunc func(key common.Hash, data []byte, dataType byte) error
	stored    map[string][]byte // Track what was stored
	callCount int               // Track number of calls
}

func newMockNetDBStore() *mockNetDBStore {
	return &mockNetDBStore{
		stored: make(map[string][]byte),
	}
}

func (m *mockNetDBStore) Store(key common.Hash, data []byte, dataType byte) error {
	m.callCount++
	if m.storeFunc != nil {
		return m.storeFunc(key, data, dataType)
	}

	// Default behavior: store successfully
	keyStr := string(key[:])
	m.stored[keyStr] = data
	return nil
}

// testError implements error interface for testing
type testError struct {
	message string
}

func (e *testError) Error() string {
	return e.message
}

func TestDatabaseManager_StoreData_Success(t *testing.T) {
	// Create mock NetDB store
	mockStore := newMockNetDBStore()

	// Create test data
	var testKey common.Hash
	copy(testKey[:], "test-router-key-12345678901234567")
	testData := []byte("test-router-info-data")
	testType := byte(0)

	// Create DatabaseManager with mock
	dm := NewDatabaseManager(mockStore)

	// Create DatabaseStore message
	dbStore := &DatabaseStore{
		BaseI2NPMessage: NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_DATABASE_STORE),
		Key:             testKey,
		Data:            testData,
		StoreType:       testType,
	}

	// Test StoreData
	err := dm.StoreData(dbStore)
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	// Verify mock was called
	if mockStore.callCount != 1 {
		t.Errorf("Expected 1 call to Store, got %d", mockStore.callCount)
	}

	// Verify data was stored
	if storedData, exists := mockStore.stored[string(testKey[:])]; !exists {
		t.Error("Data was not stored in mock NetDB")
	} else if string(storedData) != string(testData) {
		t.Errorf("Stored data mismatch: expected %s, got %s", string(testData), string(storedData))
	}
}

func TestDatabaseManager_StoreData_NetDBError(t *testing.T) {
	// Create mock NetDB store that returns error
	mockStore := newMockNetDBStore()
	testErr := &testError{message: "mock netdb error"}
	mockStore.storeFunc = func(key common.Hash, data []byte, dataType byte) error {
		return testErr
	}

	// Create test data
	var testKey common.Hash
	copy(testKey[:], "test-router-key-12345678901234567")
	testData := []byte("test-router-info-data")
	testType := byte(0)

	// Create DatabaseManager with mock
	dm := NewDatabaseManager(mockStore)

	// Create DatabaseStore message
	dbStore := &DatabaseStore{
		BaseI2NPMessage: NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_DATABASE_STORE),
		Key:             testKey,
		Data:            testData,
		StoreType:       testType,
	}

	// Test StoreData - should return the error from NetDB
	err := dm.StoreData(dbStore)
	if err == nil {
		t.Error("Expected error from NetDB, got nil")
	}
	if err != testErr {
		t.Errorf("Expected specific test error, got: %v", err)
	}

	// Verify mock was called
	if mockStore.callCount != 1 {
		t.Errorf("Expected 1 call to Store, got %d", mockStore.callCount)
	}
}

func TestDatabaseManager_StoreData_NoNetDB(t *testing.T) {
	// Create DatabaseManager without NetDB (nil)
	dm := NewDatabaseManager(nil)

	// Create test data
	var testKey common.Hash
	testData := []byte("test-data")
	testType := byte(0)

	// Create DatabaseStore message
	dbStore := &DatabaseStore{
		BaseI2NPMessage: NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_DATABASE_STORE),
		Key:             testKey,
		Data:            testData,
		StoreType:       testType,
	}

	// Test StoreData - should return error when no NetDB available
	err := dm.StoreData(dbStore)
	if err == nil {
		t.Error("Expected error for nil NetDB, got nil")
	}
	if err != nil && !containsString(err.Error(), "no NetDB available for storage") {
		t.Errorf("Expected 'no NetDB available' error, got: %v", err)
	}
}

func TestMessageRouter_SetNetDB(t *testing.T) {
	// Create MessageRouter
	config := MessageRouterConfig{
		MaxRetries:     3,
		DefaultTimeout: 30 * time.Second,
		EnableLogging:  false,
	}
	router := NewMessageRouter(config)

	// Initially should have nil NetDB (will cause "no NetDB available" error)
	var testKey common.Hash
	dbStore := &DatabaseStore{
		Key:       testKey,
		Data:      []byte("test"),
		StoreType: 0,
	}

	err := router.RouteDatabaseMessage(dbStore)
	if err == nil {
		t.Error("Expected error for nil NetDB, got nil")
	}
	if err != nil && !containsString(err.Error(), "no NetDB available") {
		t.Errorf("Expected 'no NetDB available' error, got: %v", err)
	}

	// Set NetDB and test again
	mockStore := newMockNetDBStore()
	router.SetNetDB(mockStore)

	err = router.RouteDatabaseMessage(dbStore)
	if err != nil {
		t.Errorf("Expected no error after setting NetDB, got: %v", err)
	}
	if mockStore.callCount != 1 {
		t.Errorf("Expected 1 call to Store after setting NetDB, got %d", mockStore.callCount)
	}
}

// Helper function for string contains check
func containsString(s, substr string) bool {
	if len(substr) > len(s) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestNetDBStore_DispatchByType verifies that the NetDBStore interface's Store method
// is called with the correct data type for all DatabaseStore types, ensuring that
// LeaseSets are not misrouted through RouterInfo-only storage.
func TestNetDBStore_DispatchByType(t *testing.T) {
	tests := []struct {
		name     string
		dataType byte
	}{
		{"RouterInfo", 0},
		{"LeaseSet", 1},
		{"LeaseSet2", 3},
		{"EncryptedLeaseSet", 5},
		{"MetaLeaseSet", 7},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var receivedType byte
			mockStore := newMockNetDBStore()
			mockStore.storeFunc = func(key common.Hash, data []byte, dataType byte) error {
				receivedType = dataType
				return nil
			}

			dm := NewDatabaseManager(mockStore)

			var testKey common.Hash
			copy(testKey[:], "test-key-for-dispatch-test-12345")

			dbStore := &DatabaseStore{
				BaseI2NPMessage: NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_DATABASE_STORE),
				Key:             testKey,
				Data:            []byte("test-data"),
				StoreType:       tt.dataType,
			}

			err := dm.StoreData(dbStore)
			if err != nil {
				t.Errorf("StoreData with type %d should not error: %v", tt.dataType, err)
			}

			if receivedType != tt.dataType {
				t.Errorf("Expected Store called with dataType %d, got %d", tt.dataType, receivedType)
			}
		})
	}
}

// mockDataMessageHandler implements DataMessageHandler for testing
type mockDataMessageHandler struct {
	received []byte
	err      error
}

func (m *mockDataMessageHandler) HandleDataMessage(payload []byte) error {
	m.received = payload
	return m.err
}

// mockDeliveryStatusHandler implements DeliveryStatusHandler for testing
type mockDeliveryStatusHandler struct {
	receivedMsgID     int
	receivedTimestamp time.Time
	err               error
}

func (m *mockDeliveryStatusHandler) HandleDeliveryStatus(msgID int, timestamp time.Time) error {
	m.receivedMsgID = msgID
	m.receivedTimestamp = timestamp
	return m.err
}

// TestProcessDataMessage_WithHandler tests that data messages are forwarded to the handler
func TestProcessDataMessage_WithHandler(t *testing.T) {
	processor := NewMessageProcessor()
	handler := &mockDataMessageHandler{}
	processor.SetDataMessageHandler(handler)

	// Create a data message with a payload
	payload := []byte("test payload data for I2CP delivery")
	msg := NewDataMessage(payload)

	err := processor.processDataMessage(msg)
	assert.NoError(t, err)
	assert.Equal(t, payload, handler.received)
}

// TestProcessDataMessage_WithoutHandler tests that data messages are logged but not an error
func TestProcessDataMessage_WithoutHandler(t *testing.T) {
	processor := NewMessageProcessor()

	payload := []byte("test payload data")
	msg := NewDataMessage(payload)

	err := processor.processDataMessage(msg)
	assert.NoError(t, err) // Should not error, just log a warning
}

// TestProcessDataMessage_HandlerError tests that handler errors are propagated
func TestProcessDataMessage_HandlerError(t *testing.T) {
	processor := NewMessageProcessor()
	handler := &mockDataMessageHandler{err: &testError{"handler failed"}}
	processor.SetDataMessageHandler(handler)

	payload := []byte("test payload")
	msg := NewDataMessage(payload)

	err := processor.processDataMessage(msg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "handler failed")
}

// TestProcessDeliveryStatusMessage_WithHandler tests that delivery status is forwarded
func TestProcessDeliveryStatusMessage_WithHandler(t *testing.T) {
	processor := NewMessageProcessor()
	handler := &mockDeliveryStatusHandler{}
	processor.SetDeliveryStatusHandler(handler)

	timestamp := time.Now()
	msg := NewDeliveryStatusReporter(12345, timestamp)

	err := processor.processDeliveryStatusMessage(msg.(I2NPMessage))
	assert.NoError(t, err)
	assert.Equal(t, 12345, handler.receivedMsgID)
	assert.WithinDuration(t, timestamp, handler.receivedTimestamp, time.Second)
}

// TestProcessDeliveryStatusMessage_WithoutHandler tests no-handler case
func TestProcessDeliveryStatusMessage_WithoutHandler(t *testing.T) {
	processor := NewMessageProcessor()

	timestamp := time.Now()
	msg := NewDeliveryStatusReporter(12345, timestamp)

	err := processor.processDeliveryStatusMessage(msg.(I2NPMessage))
	assert.NoError(t, err) // Should not error, just log a warning
}

// TestProcessDeliveryStatusMessage_HandlerError tests handler error propagation
func TestProcessDeliveryStatusMessage_HandlerError(t *testing.T) {
	processor := NewMessageProcessor()
	handler := &mockDeliveryStatusHandler{err: &testError{"status handler failed"}}
	processor.SetDeliveryStatusHandler(handler)

	timestamp := time.Now()
	msg := NewDeliveryStatusReporter(12345, timestamp)

	err := processor.processDeliveryStatusMessage(msg.(I2NPMessage))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "status handler failed")
}

// TestSetDataMessageHandler tests setter
func TestSetDataMessageHandler(t *testing.T) {
	processor := NewMessageProcessor()
	assert.Nil(t, processor.dataMessageHandler)

	handler := &mockDataMessageHandler{}
	processor.SetDataMessageHandler(handler)
	assert.NotNil(t, processor.dataMessageHandler)
}

// TestSetDeliveryStatusHandler tests setter
func TestSetDeliveryStatusHandler(t *testing.T) {
	processor := NewMessageProcessor()
	assert.Nil(t, processor.deliveryStatusHandler)

	handler := &mockDeliveryStatusHandler{}
	processor.SetDeliveryStatusHandler(handler)
	assert.NotNil(t, processor.deliveryStatusHandler)
}

// mockBuildReplyProcessor implements TunnelBuildReplyProcessor for testing
type mockBuildReplyProcessor struct {
	called    bool
	messageID int
	handler   TunnelReplyHandler
	err       error
}

func (m *mockBuildReplyProcessor) ProcessTunnelBuildReply(handler TunnelReplyHandler, messageID int) error {
	m.called = true
	m.messageID = messageID
	m.handler = handler
	return m.err
}

// TestSetBuildReplyProcessor tests setter
func TestSetBuildReplyProcessor(t *testing.T) {
	processor := NewMessageProcessor()
	assert.Nil(t, processor.buildReplyProcessor)

	proc := &mockBuildReplyProcessor{}
	processor.SetBuildReplyProcessor(proc)
	assert.NotNil(t, processor.buildReplyProcessor)
}

// TestProcessBuildReplyCommon_NoProcessor tests that replies are discarded when no processor is set
func TestProcessBuildReplyCommon_NoProcessor(t *testing.T) {
	processor := NewMessageProcessor()

	msg := NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_VARIABLE_TUNNEL_BUILD_REPLY)
	err := processor.processBuildReplyCommon(msg, false)
	assert.NoError(t, err) // Should succeed silently (logged + discarded)
}

// TestProcessBuildReplyCommon_EmptyData tests handling of empty reply data
func TestProcessBuildReplyCommon_EmptyData(t *testing.T) {
	processor := NewMessageProcessor()
	proc := &mockBuildReplyProcessor{}
	processor.SetBuildReplyProcessor(proc)

	msg := NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_VARIABLE_TUNNEL_BUILD_REPLY)
	// No data set on message
	err := processor.processBuildReplyCommon(msg, false)
	assert.Error(t, err)
	assert.False(t, proc.called)
}

// TestProcessBuildReplyCommon_InvalidRecordCount tests handling of invalid record count
func TestProcessBuildReplyCommon_InvalidRecordCount(t *testing.T) {
	processor := NewMessageProcessor()
	proc := &mockBuildReplyProcessor{}
	processor.SetBuildReplyProcessor(proc)

	msg := NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_VARIABLE_TUNNEL_BUILD_REPLY)
	msg.SetData([]byte{0}) // record count 0 is invalid
	err := processor.processBuildReplyCommon(msg, false)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid record count")
	assert.False(t, proc.called)
}

// TestProcessMessageDispatch_TunnelBuildReply tests dispatch routing for reply types
func TestProcessMessageDispatch_TunnelBuildReply(t *testing.T) {
	processor := NewMessageProcessor()
	proc := &mockBuildReplyProcessor{}
	processor.SetBuildReplyProcessor(proc)

	// Test that reply types no longer return "unknown message type"
	for _, msgType := range []int{
		I2NP_MESSAGE_TYPE_TUNNEL_BUILD_REPLY,
		I2NP_MESSAGE_TYPE_VARIABLE_TUNNEL_BUILD_REPLY,
		I2NP_MESSAGE_TYPE_SHORT_TUNNEL_BUILD_REPLY,
	} {
		msg := NewBaseI2NPMessage(msgType)
		// Even with no data, it should not return "unknown message type"
		err := processor.processMessageDispatch(msg)
		if err != nil {
			assert.NotContains(t, err.Error(), "unknown message type",
				"message type %d should not be unknown", msgType)
		}
	}
}
