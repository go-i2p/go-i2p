package i2np

import (
	"testing"

	common "github.com/go-i2p/common/data"
)

// TestDatabaseLookupScenarios tests RouterInfo retrieval, not-found, and no-retriever scenarios
// using a table-driven approach to consolidate the shared setup/verify pattern.
func TestDatabaseLookupScenarios(t *testing.T) {
	tests := []struct {
		name            string
		setupRetriever  bool // whether to set a retriever on the manager
		addData         bool // whether to add test data to the retriever
		lookupKey       common.Hash
		expectedMsgType int
	}{
		{
			name:            "Found_DatabaseStore",
			setupRetriever:  true,
			addData:         true,
			lookupKey:       common.Hash{0x01, 0x02, 0x03},
			expectedMsgType: I2NP_MESSAGE_TYPE_DATABASE_STORE,
		},
		{
			name:            "NotFound_DatabaseSearchReply",
			setupRetriever:  true,
			addData:         false,
			lookupKey:       common.Hash{0x99, 0x99, 0x99},
			expectedMsgType: I2NP_MESSAGE_TYPE_DATABASE_SEARCH_REPLY,
		},
		{
			name:            "NoRetriever_DatabaseSearchReply",
			setupRetriever:  false,
			addData:         false,
			lookupKey:       common.Hash{0x01, 0x02, 0x03},
			expectedMsgType: I2NP_MESSAGE_TYPE_DATABASE_SEARCH_REPLY,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			retriever := NewMockNetDBRetriever()
			sessionProvider := NewMockSessionProvider()

			dbManager := NewDatabaseManager(nil)
			if tt.setupRetriever {
				dbManager.SetRetriever(retriever)
			}
			dbManager.SetSessionProvider(sessionProvider)

			if tt.addData {
				retriever.AddRouterInfo(tt.lookupKey, []byte("test RouterInfo data"))
			}

			lookup := CreateDatabaseQuery(tt.lookupKey, common.Hash{0x04, 0x05, 0x06}, 0x00)

			err := dbManager.PerformLookup(lookup)
			if err != nil {
				t.Fatalf("Expected no error, got: %v", err)
			}

			session := sessionProvider.GetMockSession()
			sentMessages := session.GetSentMessages()

			if len(sentMessages) != 1 {
				t.Fatalf("Expected 1 sent message, got %d", len(sentMessages))
			}

			msg := sentMessages[0]
			if msg.Type() != tt.expectedMsgType {
				t.Errorf("Expected message type %d, got %d", tt.expectedMsgType, msg.Type())
			}
		})
	}
}
