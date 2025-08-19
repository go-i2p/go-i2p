package i2np

import (
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
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

func (m *mockNetDBStore) StoreRouterInfo(key common.Hash, data []byte, dataType byte) error {
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
		Key:  testKey,
		Data: testData,
		Type: testType,
	}

	// Test StoreData
	err := dm.StoreData(dbStore)
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	// Verify mock was called
	if mockStore.callCount != 1 {
		t.Errorf("Expected 1 call to StoreRouterInfo, got %d", mockStore.callCount)
	}

	// Verify data was stored
	keyStr := string(testKey[:])
	if storedData, exists := mockStore.stored[keyStr]; !exists {
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
		Key:  testKey,
		Data: testData,
		Type: testType,
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
		t.Errorf("Expected 1 call to StoreRouterInfo, got %d", mockStore.callCount)
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
		Key:  testKey,
		Data: testData,
		Type: testType,
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
		Key:  testKey,
		Data: []byte("test"),
		Type: 0,
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
		t.Errorf("Expected 1 call to StoreRouterInfo after setting NetDB, got %d", mockStore.callCount)
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
