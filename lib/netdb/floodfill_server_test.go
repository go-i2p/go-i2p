package netdb

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/i2np"
)

// mockFloodfillTransport records messages sent by the floodfill server.
type mockFloodfillTransport struct {
	mu       sync.Mutex
	messages []sentMessage
}

type sentMessage struct {
	to  common.Hash
	msg i2np.I2NPMessage
}

func (m *mockFloodfillTransport) SendI2NPMessage(_ context.Context, routerHash common.Hash, msg i2np.I2NPMessage) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.messages = append(m.messages, sentMessage{to: routerHash, msg: msg})
	return nil
}

func (m *mockFloodfillTransport) getMessages() []sentMessage {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]sentMessage, len(m.messages))
	copy(result, m.messages)
	return result
}

func TestNewFloodfillServer(t *testing.T) {
	db := NewStdNetDB(t.TempDir())
	config := DefaultFloodfillConfig()

	fs := NewFloodfillServer(db, nil, config)

	if fs == nil {
		t.Fatal("NewFloodfillServer returned nil")
	}
	if fs.IsEnabled() {
		t.Error("Default config should have floodfill disabled")
	}
	if fs.floodCount != 4 {
		t.Errorf("Expected flood count 4, got %d", fs.floodCount)
	}
}

func TestFloodfillServerEnable(t *testing.T) {
	db := NewStdNetDB(t.TempDir())
	fs := NewFloodfillServer(db, nil, DefaultFloodfillConfig())

	fs.SetEnabled(true)
	if !fs.IsEnabled() {
		t.Error("Expected server to be enabled after SetEnabled(true)")
	}

	fs.SetEnabled(false)
	if fs.IsEnabled() {
		t.Error("Expected server to be disabled after SetEnabled(false)")
	}
}

func TestHandleDatabaseLookupDisabled(t *testing.T) {
	db := NewStdNetDB(t.TempDir())
	transport := &mockFloodfillTransport{}
	fs := NewFloodfillServer(db, transport, DefaultFloodfillConfig())

	// Server is disabled by default
	lookup := &i2np.DatabaseLookup{}

	err := fs.HandleDatabaseLookup(lookup)
	if err == nil {
		t.Error("Expected error when server is disabled")
	}

	// No messages should have been sent
	if len(transport.getMessages()) != 0 {
		t.Error("No messages should be sent when server is disabled")
	}
}

func TestHandleDatabaseLookupNotFound(t *testing.T) {
	db := NewStdNetDB(t.TempDir())
	if err := db.Ensure(); err != nil {
		t.Fatalf("Failed to ensure DB: %v", err)
	}

	transport := &mockFloodfillTransport{}
	config := FloodfillConfig{
		Enabled:    true,
		FloodCount: 4,
	}
	fs := NewFloodfillServer(db, transport, config)

	var key common.Hash
	copy(key[:], []byte("test_key_for_lookup_not_found!!!!"))
	var from common.Hash
	copy(from[:], []byte("requester_hash_for_test_not_fnd!"))

	lookup := &i2np.DatabaseLookup{
		Key:   key,
		From:  from,
		Flags: 0x04, // RI lookup type (bits 3-2 = 10)
	}

	err := fs.HandleDatabaseLookup(lookup)
	if err != nil {
		t.Fatalf("HandleDatabaseLookup failed: %v", err)
	}

	// Should have sent a DatabaseSearchReply
	msgs := transport.getMessages()
	if len(msgs) != 1 {
		t.Fatalf("Expected 1 message sent, got %d", len(msgs))
	}

	if msgs[0].to != from {
		t.Error("Response should be sent to the 'from' hash")
	}
}

func TestDetermineLookupType(t *testing.T) {
	db := NewStdNetDB(t.TempDir())
	fs := NewFloodfillServer(db, nil, DefaultFloodfillConfig())

	tests := []struct {
		name     string
		flags    byte
		expected string
	}{
		{"normal lookup", 0x00, "any"},
		{"LS lookup", 0x04, "ls"},
		{"RI lookup", 0x08, "ri"},
		{"exploration", 0x0C, "exploration"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lookup := &i2np.DatabaseLookup{Flags: tt.flags}
			result := fs.determineLookupType(lookup)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q for flags 0x%02x", tt.expected, result, tt.flags)
			}
		})
	}
}

func TestFloodfillSetTransport(t *testing.T) {
	db := NewStdNetDB(t.TempDir())
	fs := NewFloodfillServer(db, nil, DefaultFloodfillConfig())

	if fs.transport != nil {
		t.Error("Transport should be nil initially")
	}

	transport := &mockFloodfillTransport{}
	fs.SetTransport(transport)

	if fs.transport == nil {
		t.Error("Transport should be set after SetTransport")
	}
}

func TestFloodDatabaseStoreDisabled(t *testing.T) {
	db := NewStdNetDB(t.TempDir())
	transport := &mockFloodfillTransport{}
	fs := NewFloodfillServer(db, transport, DefaultFloodfillConfig())

	var key common.Hash
	copy(key[:], []byte("flood_test_key_for_disabled_srv!"))

	// Should be a no-op when disabled
	fs.FloodDatabaseStore(key, []byte("test data"), i2np.DATABASE_STORE_TYPE_ROUTER_INFO)

	msgs := transport.getMessages()
	if len(msgs) != 0 {
		t.Errorf("Expected 0 messages when disabled, got %d", len(msgs))
	}
}

func TestFloodfillServerStop(t *testing.T) {
	db := NewStdNetDB(t.TempDir())
	fs := NewFloodfillServer(db, nil, DefaultFloodfillConfig())

	// Stop should not panic
	fs.Stop()
}

func TestGzipCompress(t *testing.T) {
	original := []byte("test data for compression, test data for compression, test data for compression")
	compressed, err := gzipCompress(original)
	if err != nil {
		t.Fatalf("gzipCompress failed: %v", err)
	}
	if len(compressed) == 0 {
		t.Error("Compressed data should not be empty")
	}
	if len(compressed) >= len(original) {
		t.Log("Compressed data is not smaller (expected for very short inputs)")
	}
}

func TestGzipDecompress(t *testing.T) {
	original := []byte("test data for decompression, test data for decompression, test data for decompression")

	// Compress first
	compressed, err := gzipCompress(original)
	if err != nil {
		t.Fatalf("gzipCompress failed: %v", err)
	}

	// Decompress and verify roundtrip
	decompressed, err := gzipDecompress(compressed)
	if err != nil {
		t.Fatalf("gzipDecompress failed: %v", err)
	}
	if !bytes.Equal(original, decompressed) {
		t.Errorf("Roundtrip mismatch: got %q, want %q", decompressed, original)
	}
}

func TestGzipDecompressInvalidData(t *testing.T) {
	// Should fail on non-gzip data
	_, err := gzipDecompress([]byte("not gzip data"))
	if err == nil {
		t.Error("Expected error for non-gzip data, got nil")
	}

	// Should fail on empty data
	_, err = gzipDecompress([]byte{})
	if err == nil {
		t.Error("Expected error for empty data, got nil")
	}
}

func TestSelectClosestFloodfills(t *testing.T) {
	db := NewStdNetDB(t.TempDir())

	var ourHash common.Hash
	copy(ourHash[:], []byte("our_router_hash_for_ff_select!!"))

	config := FloodfillConfig{
		Enabled:    true,
		OurHash:    ourHash,
		FloodCount: 4,
	}
	fs := NewFloodfillServer(db, nil, config)

	var targetKey common.Hash
	copy(targetKey[:], []byte("target_key_for_floodfill_select"))

	// With empty DB, should return empty list
	peerHashes := fs.selectClosestFloodfills(targetKey)
	if len(peerHashes) != 0 {
		t.Errorf("Expected 0 peers from empty DB, got %d", len(peerHashes))
	}
}

func TestHandleDatabaseLookupNoTransport(t *testing.T) {
	db := NewStdNetDB(t.TempDir())
	config := FloodfillConfig{
		Enabled: true,
	}
	fs := NewFloodfillServer(db, nil, config)

	lookup := &i2np.DatabaseLookup{}

	err := fs.HandleDatabaseLookup(lookup)
	if err == nil {
		t.Error("Expected error when no transport is available")
	}
}

func TestExplorationLookupAlwaysReturnsSearchReply(t *testing.T) {
	db := NewStdNetDB(t.TempDir())
	fs := NewFloodfillServer(db, nil, DefaultFloodfillConfig())

	var key common.Hash
	copy(key[:], []byte("exploration_key_for_test_lookup!"))

	_, _, err := fs.lookupData(key, "exploration")
	if err == nil {
		t.Error("Exploration lookups should always return an error to trigger SearchReply")
	}

	_, _, err = fs.lookupData(key, "ri")
	if err == nil {
		// RI not found in empty DB is expected
		t.Log("RI lookup returned data from empty DB — unexpected but not fatal")
	}
}

func TestFloodfillConfigDefaults(t *testing.T) {
	config := DefaultFloodfillConfig()
	if config.Enabled {
		t.Error("Default should be disabled")
	}
	if config.FloodCount != 4 {
		t.Errorf("Expected default flood count 4, got %d", config.FloodCount)
	}
	var emptyHash common.Hash
	if config.OurHash != emptyHash {
		t.Error("Default OurHash should be empty")
	}
}

func TestFloodCountMinimum(t *testing.T) {
	db := NewStdNetDB(t.TempDir())
	config := FloodfillConfig{
		FloodCount: 0, // Should be set to 4
	}
	fs := NewFloodfillServer(db, nil, config)
	if fs.floodCount != 4 {
		t.Errorf("Expected flood count 4 for zero input, got %d", fs.floodCount)
	}

	config.FloodCount = -1
	fs = NewFloodfillServer(db, nil, config)
	if fs.floodCount != 4 {
		t.Errorf("Expected flood count 4 for negative input, got %d", fs.floodCount)
	}
}

func TestSendDatabaseStoreNoTransport(t *testing.T) {
	db := NewStdNetDB(t.TempDir())
	fs := NewFloodfillServer(db, nil, DefaultFloodfillConfig())

	var key, to common.Hash
	err := fs.sendDatabaseStore(key, []byte("data"), 0, to, nil)
	if err == nil {
		t.Error("Expected error with nil transport")
	}
}

func TestSendDatabaseSearchReplyNoTransport(t *testing.T) {
	db := NewStdNetDB(t.TempDir())
	fs := NewFloodfillServer(db, nil, DefaultFloodfillConfig())

	var key, to common.Hash
	err := fs.sendDatabaseSearchReply(key, to, nil)
	if err == nil {
		t.Error("Expected error with nil transport")
	}
}

func TestSendDatabaseStoreWithTransport(t *testing.T) {
	db := NewStdNetDB(t.TempDir())
	transport := &mockFloodfillTransport{}

	var ourHash common.Hash
	copy(ourHash[:], []byte("our_hash_for_store_test_value!!"))
	fs := NewFloodfillServer(db, transport, FloodfillConfig{
		Enabled:    true,
		OurHash:    ourHash,
		FloodCount: 4,
	})

	var key, to common.Hash
	copy(key[:], []byte("store_key_for_db_store_test_msg"))
	copy(to[:], []byte("destination_for_store_response!"))

	err := fs.sendDatabaseStore(key, []byte("test data"), i2np.DATABASE_STORE_TYPE_ROUTER_INFO, to, transport)
	if err != nil {
		t.Fatalf("sendDatabaseStore failed: %v", err)
	}

	msgs := transport.getMessages()
	if len(msgs) != 1 {
		t.Fatalf("Expected 1 message, got %d", len(msgs))
	}
	if msgs[0].to != to {
		t.Error("Response sent to wrong destination")
	}

	_ = fs                // suppress unused
	fmt.Sprintf("%v", fs) // use fs
}
