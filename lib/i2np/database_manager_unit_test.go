package i2np

import (
	"testing"

	common "github.com/go-i2p/common/data"
)

// TestDatabaseLookupFound tests successful RouterInfo retrieval and DatabaseStore response
func TestDatabaseLookupFound(t *testing.T) {
	// Setup
	retriever := NewMockNetDBRetriever()
	sessionProvider := NewMockSessionProvider()

	dbManager := NewDatabaseManager(nil)
	dbManager.SetRetriever(retriever)
	dbManager.SetSessionProvider(sessionProvider)

	// Add test data
	testKey := common.Hash{0x01, 0x02, 0x03} // Simplified hash
	testData := []byte("test RouterInfo data")
	retriever.AddRouterInfo(testKey, testData)

	// Create lookup request
	lookup := CreateDatabaseQuery(testKey, common.Hash{0x04, 0x05, 0x06}, 0x00)

	// Execute lookup
	err := dbManager.PerformLookup(lookup)
	// Verify results
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	// Check that response was sent
	session := sessionProvider.GetMockSession()
	sentMessages := session.GetSentMessages()

	if len(sentMessages) != 1 {
		t.Fatalf("Expected 1 sent message, got %d", len(sentMessages))
	}

	// Verify message type is DatabaseStore
	msg := sentMessages[0]
	if msg.Type() != I2NP_MESSAGE_TYPE_DATABASE_STORE {
		t.Errorf("Expected DatabaseStore message type %d, got %d", I2NP_MESSAGE_TYPE_DATABASE_STORE, msg.Type())
	}
}

// TestDatabaseLookupNotFound tests RouterInfo not found scenario and DatabaseSearchReply response
func TestDatabaseLookupNotFound(t *testing.T) {
	// Setup
	retriever := NewMockNetDBRetriever()
	sessionProvider := NewMockSessionProvider()

	dbManager := NewDatabaseManager(nil)
	dbManager.SetRetriever(retriever)
	dbManager.SetSessionProvider(sessionProvider)

	// Create lookup request for non-existent RouterInfo
	testKey := common.Hash{0x99, 0x99, 0x99}
	lookup := CreateDatabaseQuery(testKey, common.Hash{0x04, 0x05, 0x06}, 0x00)

	// Execute lookup
	err := dbManager.PerformLookup(lookup)
	// Verify results
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	// Check that response was sent
	session := sessionProvider.GetMockSession()
	sentMessages := session.GetSentMessages()

	if len(sentMessages) != 1 {
		t.Fatalf("Expected 1 sent message, got %d", len(sentMessages))
	}

	// Verify message type is DatabaseSearchReply
	msg := sentMessages[0]
	if msg.Type() != I2NP_MESSAGE_TYPE_DATABASE_SEARCH_REPLY {
		t.Errorf("Expected DatabaseSearchReply message type %d, got %d", I2NP_MESSAGE_TYPE_DATABASE_SEARCH_REPLY, msg.Type())
	}
}

// TestDatabaseLookupWithoutRetriever tests error handling when no retriever is set
func TestDatabaseLookupWithoutRetriever(t *testing.T) {
	// Setup - no retriever set
	sessionProvider := NewMockSessionProvider()

	dbManager := NewDatabaseManager(nil)
	dbManager.SetSessionProvider(sessionProvider)

	// Create lookup request
	testKey := common.Hash{0x01, 0x02, 0x03}
	lookup := CreateDatabaseQuery(testKey, common.Hash{0x04, 0x05, 0x06}, 0x00)

	// Execute lookup
	err := dbManager.PerformLookup(lookup)
	// Should still work - will send DatabaseSearchReply
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	// Check that DatabaseSearchReply was sent
	session := sessionProvider.GetMockSession()
	sentMessages := session.GetSentMessages()

	if len(sentMessages) != 1 {
		t.Fatalf("Expected 1 sent message, got %d", len(sentMessages))
	}

	// Verify message type is DatabaseSearchReply
	msg := sentMessages[0]
	if msg.Type() != I2NP_MESSAGE_TYPE_DATABASE_SEARCH_REPLY {
		t.Errorf("Expected DatabaseSearchReply message type %d, got %d", I2NP_MESSAGE_TYPE_DATABASE_SEARCH_REPLY, msg.Type())
	}
}
