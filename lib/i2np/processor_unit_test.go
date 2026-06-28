package i2np

import (
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// newTestDatabaseStore creates a standard test DatabaseStore message.
func newTestDatabaseStore(t *testing.T) (common.Hash, []byte, *DatabaseStore) {
	t.Helper()
	var testKey common.Hash
	copy(testKey[:], "test-router-key-12345678901234567")
	testData := []byte("test-router-info-data")

	dbStore := &DatabaseStore{
		BaseI2NPMessage: NewBaseI2NPMessage(I2NPMessageTypeDatabaseStore),
		Key:             testKey,
		Data:            testData,
		StoreType:       byte(0),
	}
	return testKey, testData, dbStore
}

func TestDatabaseManager_StoreData_Success(t *testing.T) {
	mockStore := newMockNetDBStore()
	dm := NewDatabaseManager(mockStore)
	testKey, testData, dbStore := newTestDatabaseStore(t)

	err := dm.StoreData(dbStore)
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	if mockStore.callCount != 1 {
		t.Errorf("Expected 1 call to Store, got %d", mockStore.callCount)
	}

	if storedData, exists := mockStore.stored[string(testKey[:])]; !exists {
		t.Error("Data was not stored in mock NetDB")
	} else if string(storedData) != string(testData) {
		t.Errorf("Stored data mismatch: expected %s, got %s", string(testData), string(storedData))
	}
}

func TestDatabaseManager_StoreData_NetDBError(t *testing.T) {
	mockStore := newMockNetDBStore()
	testErr := &testError{message: "mock netdb error"}
	mockStore.storeFunc = func(key common.Hash, data []byte, dataType byte) error {
		return testErr
	}
	dm := NewDatabaseManager(mockStore)
	_, _, dbStore := newTestDatabaseStore(t)

	err := dm.StoreData(dbStore)
	if err == nil {
		t.Error("Expected error from NetDB, got nil")
	}
	if err != testErr {
		t.Errorf("Expected specific test error, got: %v", err)
	}

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
		BaseI2NPMessage: NewBaseI2NPMessage(I2NPMessageTypeDatabaseStore),
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
	config := I2NPMessageDispatcherConfig{
		MaxRetries:     3,
		DefaultTimeout: 30 * time.Second,
		EnableLogging:  false,
	}
	router := NewI2NPMessageDispatcher(config)

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
				BaseI2NPMessage: NewBaseI2NPMessage(I2NPMessageTypeDatabaseStore),
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

	err := processor.processDeliveryStatusMessage(msg.(Message))
	assert.NoError(t, err)
	assert.Equal(t, 12345, handler.receivedMsgID)
	assert.WithinDuration(t, timestamp, handler.receivedTimestamp, time.Second)
}

// TestProcessDeliveryStatusMessage_WithoutHandler tests no-handler case
func TestProcessDeliveryStatusMessage_WithoutHandler(t *testing.T) {
	processor := NewMessageProcessor()

	timestamp := time.Now()
	msg := NewDeliveryStatusReporter(12345, timestamp)

	err := processor.processDeliveryStatusMessage(msg.(Message))
	assert.NoError(t, err) // Should not error, just log a warning
}

// TestProcessDeliveryStatusMessage_HandlerError tests handler error propagation
func TestProcessDeliveryStatusMessage_HandlerError(t *testing.T) {
	processor := NewMessageProcessor()
	handler := &mockDeliveryStatusHandler{err: &testError{"status handler failed"}}
	processor.SetDeliveryStatusHandler(handler)

	timestamp := time.Now()
	msg := NewDeliveryStatusReporter(12345, timestamp)

	err := processor.processDeliveryStatusMessage(msg.(Message))
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

func TestProcessDatabaseStoreMessage_FromBaseMessageDataCarrier(t *testing.T) {
	processor := NewMessageProcessor()
	mockStore := newMockNetDBStore()
	processor.SetDatabaseManager(NewDatabaseManager(mockStore))

	var key common.Hash
	copy(key[:], "dbstore-base-message-key-123456789")

	dbStore := &DatabaseStore{
		BaseI2NPMessage: NewBaseI2NPMessage(I2NPMessageTypeDatabaseStore),
		Key:             key,
		Data:            []byte("router-info-body"),
		StoreType:       0,
	}
	body, err := dbStore.MarshalPayload()
	require.NoError(t, err)

	base := NewBaseI2NPMessage(I2NPMessageTypeDatabaseStore)
	base.SetData(body)

	err = processor.processDatabaseStoreMessage(base)
	require.NoError(t, err)
	assert.Equal(t, 1, mockStore.callCount)
}

func TestProcessDatabaseSearchReplyMessage_FromBaseMessageDataCarrier(t *testing.T) {
	processor := NewMessageProcessor()
	handler := &mockSearchReplyHandler{}
	processor.SetSearchReplyHandler(handler)

	var key common.Hash
	copy(key[:], "dbsearchreply-base-key-123456789012")
	var from common.Hash
	copy(from[:], "dbsearchreply-from-key-12345678901")
	var peer common.Hash
	copy(peer[:], "dbsearchreply-peer-key-12345678901")

	reply := DatabaseSearchReply{
		BaseI2NPMessage: NewBaseI2NPMessage(I2NPMessageTypeDatabaseSearchReply),
		Key:             key,
		From:            from,
		Count:           1,
		PeerHashes:      []common.Hash{peer},
	}
	body, err := reply.MarshalPayload()
	require.NoError(t, err)

	base := NewBaseI2NPMessage(I2NPMessageTypeDatabaseSearchReply)
	base.SetData(body)

	err = processor.processDatabaseSearchReplyMessage(base)
	require.NoError(t, err)
	require.Equal(t, 1, len(handler.calls))
	assert.Equal(t, key, handler.calls[0].key)
	require.Equal(t, 1, len(handler.calls[0].peerHashes))
	assert.Equal(t, peer, handler.calls[0].peerHashes[0])
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

	msg := NewBaseI2NPMessage(I2NPMessageTypeVariableTunnelBuildReply)
	err := processor.processBuildReplyCommon(msg, false)
	assert.NoError(t, err) // Should succeed silently (logged + discarded)
}

// TestProcessBuildReplyCommon_EmptyData tests handling of empty reply data
func TestProcessBuildReplyCommon_EmptyData(t *testing.T) {
	processor := NewMessageProcessor()
	proc := &mockBuildReplyProcessor{}
	processor.SetBuildReplyProcessor(proc)

	msg := NewBaseI2NPMessage(I2NPMessageTypeVariableTunnelBuildReply)
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

	msg := NewBaseI2NPMessage(I2NPMessageTypeVariableTunnelBuildReply)
	msg.SetData([]byte{0}) // record count 0 is invalid
	err := processor.processBuildReplyCommon(msg, false)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid record count")
	assert.False(t, proc.called)
}

// TestProcessBuildReplyCommon_ShortReply_EncryptedSlots verifies that type-26
// replies carrying 218-byte encrypted slots are forwarded to the build reply
// processor without premature legacy 528-byte parsing.
func TestProcessBuildReplyCommon_ShortReply_EncryptedSlots(t *testing.T) {
	processor := NewMessageProcessor()
	proc := &mockBuildReplyProcessor{}
	processor.SetBuildReplyProcessor(proc)

	msg := NewBaseI2NPMessage(I2NPMessageTypeShortTunnelBuildReply)
	msg.SetMessageID(12345)

	data := make([]byte, 1+ShortBuildRecordSize)
	data[0] = 1 // one short reply slot
	msg.SetData(data)

	err := processor.processBuildReplyCommon(msg, true)
	assert.NoError(t, err)
	assert.True(t, proc.called)
	assert.Equal(t, 12345, proc.messageID)

	handler, ok := proc.handler.(*ShortTunnelBuildReply)
	if !ok {
		t.Fatalf("expected *ShortTunnelBuildReply handler, got %T", proc.handler)
	}

	assert.Equal(t, 1, handler.Count)
	assert.Len(t, handler.RawRecordData, 1)
	assert.Len(t, handler.RawRecordData[0], ShortBuildRecordSize)
	assert.Len(t, handler.BuildResponseRecords, 1)
	assert.Equal(t, byte(TunnelBuildReplyReject), handler.BuildResponseRecords[0].Reply)
}

// TestProcessMessageDispatch_ShortReply_EncryptedSlots verifies dispatch path
// integration for ShortTunnelBuildReply parsing with 218-byte records.
func TestProcessMessageDispatch_ShortReply_EncryptedSlots(t *testing.T) {
	processor := NewMessageProcessor()
	proc := &mockBuildReplyProcessor{}
	processor.SetBuildReplyProcessor(proc)

	msg := NewBaseI2NPMessage(I2NPMessageTypeShortTunnelBuildReply)
	msg.SetMessageID(777)
	data := make([]byte, 1+ShortBuildRecordSize)
	data[0] = 1
	msg.SetData(data)

	err := processor.processMessageDispatch(msg, 0)
	assert.NoError(t, err)
	assert.True(t, proc.called)
	assert.Equal(t, 777, proc.messageID)
}

// TestProcessMessageDispatch_TunnelBuildReply tests dispatch routing for reply types
func TestProcessMessageDispatch_TunnelBuildReply(t *testing.T) {
	processor := NewMessageProcessor()
	proc := &mockBuildReplyProcessor{}
	processor.SetBuildReplyProcessor(proc)

	// Test that reply types no longer return "unknown message type"
	for _, msgType := range []int{
		I2NPMessageTypeTunnelBuildReply,
		I2NPMessageTypeVariableTunnelBuildReply,
		I2NPMessageTypeShortTunnelBuildReply,
	} {
		msg := NewBaseI2NPMessage(msgType)
		// Even with no data, it should not return "unknown message type"
		err := processor.processMessageDispatch(msg, 0)
		if err != nil {
			assert.NotContains(t, err.Error(), "unknown message type",
				"message type %d should not be unknown", msgType)
		}
	}
}

func TestProcessMessage_TypedNilMessageDoesNotPanic(t *testing.T) {
	processor := NewMessageProcessor()

	var nilBase *BaseI2NPMessage
	var msg Message = nilBase

	err := processor.ProcessMessage(msg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid I2NP message metadata")
}

func TestProcessMessage_NilEmbeddedBaseDoesNotPanic(t *testing.T) {
	processor := NewMessageProcessor()

	msg := &DatabaseSearchReply{}
	err := processor.ProcessMessage(msg)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid I2NP message metadata")
}

// =============================================================================
// MOCK-BASED GARLIC INTERFACE TESTS
// =============================================================================

// TestSetGarlicSessionManager_MockDecryptor tests that a mock decryptor
// can be injected into the processor via the interface.
func TestSetGarlicSessionManager_MockDecryptor(t *testing.T) {
	processor := NewMessageProcessor()

	// Initially nil
	assert.Nil(t, processor.garlicSessions)

	// Inject mock decryptor
	mock := newMockGarlicDecryptor()
	processor.SetGarlicSessionManager(mock)

	assert.NotNil(t, processor.garlicSessions)
}

// TestSetBuildRecordCrypto_MockEncryptor tests that a mock reply encryptor
// can be injected into the processor via the interface.
func TestSetBuildRecordCrypto_MockEncryptor(t *testing.T) {
	processor := NewMessageProcessor()

	// Initially set to real BuildRecordCrypto from constructor
	assert.NotNil(t, processor.buildRecordCrypto)

	// Inject mock encryptor
	mock := newMockReplyEncryptor()
	processor.SetBuildRecordCrypto(mock)

	assert.NotNil(t, processor.buildRecordCrypto)
}

// TestDecryptGarlicData_WithMock tests garlic decryption using a mock.
func TestDecryptGarlicData_WithMock(t *testing.T) {
	processor := NewMessageProcessor()

	// Set up mock to return specific plaintext
	expectedPlaintext := []byte("decrypted garlic payload")
	expectedTag := [8]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22}
	mock := newMockGarlicDecryptorWithPlaintext(expectedPlaintext, expectedTag)
	processor.SetGarlicSessionManager(mock)

	// Call decryptGarlicData
	plaintexts, tag, err := processor.decryptGarlicData(42, []byte("encrypted-data"))
	assert.NoError(t, err)
	require.Len(t, plaintexts, 1, "mock returns one clove")
	assert.Equal(t, expectedPlaintext, plaintexts[0])
	assert.Equal(t, expectedTag, tag)

	// Verify mock was called
	assert.Equal(t, 1, mock.callCount)
	assert.Equal(t, []byte("encrypted-data"), mock.lastEncrypted)
}

// TestDecryptGarlicData_MockError tests garlic decryption error handling with a mock.
func TestDecryptGarlicData_MockError(t *testing.T) {
	processor := NewMessageProcessor()

	mock := newMockGarlicDecryptorWithError(fmt.Errorf("decryption failed: invalid session tag"))
	processor.SetGarlicSessionManager(mock)

	_, _, err := processor.decryptGarlicData(42, []byte("bad-data"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "decryption failed")
}

// TestValidateGarlicSession_NilDecryptor tests that nil decryptor returns error.
func TestValidateGarlicSession_NilDecryptor(t *testing.T) {
	processor := NewMessageProcessor()

	// Don't set garlic session manager
	err := processor.validateGarlicSession()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "garlic session manager not configured")
}

// TestValidateGarlicSession_WithMock tests that a set mock passes validation.
func TestValidateGarlicSession_WithMock(t *testing.T) {
	processor := NewMessageProcessor()

	mock := newMockGarlicDecryptor()
	processor.SetGarlicSessionManager(mock)

	err := processor.validateGarlicSession()
	assert.NoError(t, err)
}

func TestExtractGarlicData_StripsLengthPrefix(t *testing.T) {
	processor := NewMessageProcessor()

	ciphertext := []byte{0x11, 0x22, 0x33, 0x44, 0x55}
	framed := make([]byte, 4+len(ciphertext))
	binary.BigEndian.PutUint32(framed[:4], uint32(len(ciphertext)))
	copy(framed[4:], ciphertext)

	msg := NewBaseI2NPMessage(I2NPMessageTypeGarlic)
	msg.SetMessageID(123)
	msg.SetData(framed)

	got, err := processor.extractGarlicData(msg)
	assert.NoError(t, err)
	assert.Equal(t, ciphertext, got)
}

func TestExtractGarlicData_LeavesUnframedPayloadUntouched(t *testing.T) {
	processor := NewMessageProcessor()

	raw := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE}
	msg := NewBaseI2NPMessage(I2NPMessageTypeGarlic)
	msg.SetMessageID(124)
	msg.SetData(raw)

	got, err := processor.extractGarlicData(msg)
	assert.NoError(t, err)
	assert.Equal(t, raw, got)
}
