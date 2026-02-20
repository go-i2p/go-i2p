package i2np

import (
	"testing"

	common "github.com/go-i2p/common/data"
)

// mockSearchReplyHandler implements SearchReplyHandler for testing.
type mockSearchReplyHandler struct {
	calls []searchReplyCall
}

type searchReplyCall struct {
	key        common.Hash
	peerHashes []common.Hash
}

func (m *mockSearchReplyHandler) HandleSearchReply(key common.Hash, peerHashes []common.Hash) {
	m.calls = append(m.calls, searchReplyCall{key: key, peerHashes: peerHashes})
}

// TestSetSearchReplyHandler tests setting the search reply handler.
func TestSetSearchReplyHandler(t *testing.T) {
	processor := NewMessageProcessor()

	if processor.searchReplyHandler != nil {
		t.Error("searchReplyHandler should initially be nil")
	}

	handler := &mockSearchReplyHandler{}
	processor.SetSearchReplyHandler(handler)

	if processor.searchReplyHandler == nil {
		t.Error("searchReplyHandler should be set")
	}
}

// TestProcessDatabaseSearchReplyWithHandler tests that the handler receives suggestions.
func TestProcessDatabaseSearchReplyWithHandler(t *testing.T) {
	processor := NewMessageProcessor()
	processor.DisableExpirationCheck()

	handler := &mockSearchReplyHandler{}
	processor.SetSearchReplyHandler(handler)

	key := common.Hash{1, 2, 3}
	from := common.Hash{4, 5, 6}
	peerHashes := []common.Hash{{10, 20}, {30, 40}, {50, 60}}

	msg := NewDatabaseSearchReply(key, from, peerHashes)

	err := processor.ProcessMessage(msg)
	if err != nil {
		t.Fatalf("ProcessMessage failed: %v", err)
	}

	if len(handler.calls) != 1 {
		t.Fatalf("expected 1 handler call, got %d", len(handler.calls))
	}

	call := handler.calls[0]
	if call.key != key {
		t.Errorf("expected key %x, got %x", key[:4], call.key[:4])
	}
	if len(call.peerHashes) != 3 {
		t.Errorf("expected 3 peer hashes, got %d", len(call.peerHashes))
	}
	for i, ph := range call.peerHashes {
		if ph != peerHashes[i] {
			t.Errorf("peer hash %d mismatch", i)
		}
	}
}

// TestProcessDatabaseSearchReplyWithoutHandler tests graceful behavior when no handler is set.
func TestProcessDatabaseSearchReplyWithoutHandler(t *testing.T) {
	processor := NewMessageProcessor()
	processor.DisableExpirationCheck()

	key := common.Hash{1, 2, 3}
	from := common.Hash{4, 5, 6}
	peerHashes := []common.Hash{{10, 20}}

	msg := NewDatabaseSearchReply(key, from, peerHashes)

	// Should not panic or error when no handler is set
	err := processor.ProcessMessage(msg)
	if err != nil {
		t.Fatalf("ProcessMessage should succeed without handler: %v", err)
	}
}

// TestProcessDatabaseSearchReplyEmptySuggestions tests handling with no peer suggestions.
func TestProcessDatabaseSearchReplyEmptySuggestions(t *testing.T) {
	processor := NewMessageProcessor()
	processor.DisableExpirationCheck()

	handler := &mockSearchReplyHandler{}
	processor.SetSearchReplyHandler(handler)

	key := common.Hash{1, 2, 3}
	from := common.Hash{4, 5, 6}

	msg := NewDatabaseSearchReply(key, from, nil)

	err := processor.ProcessMessage(msg)
	if err != nil {
		t.Fatalf("ProcessMessage failed: %v", err)
	}

	// Handler should NOT be called with empty suggestions
	if len(handler.calls) != 0 {
		t.Errorf("expected 0 handler calls for empty suggestions, got %d", len(handler.calls))
	}
}
