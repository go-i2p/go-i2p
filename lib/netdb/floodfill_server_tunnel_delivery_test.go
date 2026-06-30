package netdb

import (
	"encoding/binary"
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/session_key"
	"github.com/go-i2p/common/session_tag"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/tunnel"
)

// TestHandleDatabaseLookupDirectResponse tests that direct lookups (deliveryFlag=0) receive direct responses
// This test verifies the routing logic by checking that responses are sent to the requester directly
// when deliveryFlag=0, rather than through a tunnel gateway
func TestHandleDatabaseLookupDirectResponse(t *testing.T) {
	db := NewStdNetDB(t.TempDir())
	if err := db.Ensure(); err != nil {
		t.Fatalf("Failed to ensure DB: %v", err)
	}

	transport := &mockFloodfillTransport{}
	var ourHash common.Hash
	copy(ourHash[:], []byte("our_hash_for_direct_response_tst"))

	config := FloodfillConfig{
		Enabled:    true,
		OurHash:    ourHash,
		FloodCount: 4,
	}
	fs := NewFloodfillServer(db, transport, config)

	// Create a lookup for non-existent key with deliveryFlag=0 (direct response)
	// We use non-existent key to avoid the complexity of storing valid RouterInfo
	var testKey common.Hash
	copy(testKey[:], []byte("nonexistent_key_for_direct_test"))
	var requesterHash common.Hash
	copy(requesterHash[:], []byte("requester_direct_response_test!!"))

	lookup := &i2np.DatabaseLookup{
		Key:   testKey,
		From:  requesterHash,
		Flags: 0x00, // deliveryFlag=0 (direct), lookup type = 00 (any)
	}

	err := fs.HandleDatabaseLookup(lookup)
	if err != nil {
		t.Fatalf("HandleDatabaseLookup failed: %v", err)
	}

	// Should have sent a DatabaseSearchReply directly to requester
	msgs := transport.getMessages()
	if len(msgs) != 1 {
		t.Fatalf("Expected 1 message, got %d", len(msgs))
	}

	// Message should be sent to requester, not to a gateway through tunnel
	if msgs[0].to != requesterHash {
		t.Error("Direct response should be sent to requester hash")
	}

	// Message should be DatabaseSearchReply, not TunnelGateway
	_, ok := msgs[0].msg.(*i2np.DatabaseSearchReply)
	if !ok {
		t.Fatalf("Expected DatabaseSearchReply message, got %T", msgs[0].msg)
	}
}

// TestHandleDatabaseLookupTunnelResponse tests that tunnel lookups (deliveryFlag=1) receive tunnel-wrapped responses
// This test verifies that when deliveryFlag=1, responses are wrapped in TunnelGateway messages
// and sent to the gateway hash instead of the requester directly
func TestHandleDatabaseLookupTunnelResponse(t *testing.T) {
	db := NewStdNetDB(t.TempDir())
	if err := db.Ensure(); err != nil {
		t.Fatalf("Failed to ensure DB: %v", err)
	}

	transport := &mockFloodfillTransport{}
	var ourHash common.Hash
	copy(ourHash[:], []byte("our_hash_for_tunnel_response_test"))

	config := FloodfillConfig{
		Enabled:    true,
		OurHash:    ourHash,
		FloodCount: 4,
	}
	fs := NewFloodfillServer(db, transport, config)

	// Create a lookup for non-existent key with deliveryFlag=1 (tunnel response)
	// We use non-existent key to avoid the complexity of storing valid RouterInfo
	var testKey common.Hash
	copy(testKey[:], []byte("nonexistent_key_for_tunnel_test"))
	var gatewayHash common.Hash
	copy(gatewayHash[:], []byte("gateway_hash_for_tunnel_response!"))

	// Create a lookup with deliveryFlag=1 (tunnel response)
	replyTunnelID := [4]byte{0x00, 0x00, 0x30, 0x39} // tunnel ID 12345 in big-endian
	lookup := &i2np.DatabaseLookup{
		Key:           testKey,
		From:          gatewayHash,
		Flags:         0x01, // deliveryFlag=1 (tunnel), lookup type = 00 (any)
		ReplyTunnelID: replyTunnelID,
	}

	err := fs.HandleDatabaseLookup(lookup)
	if err != nil {
		t.Fatalf("HandleDatabaseLookup failed: %v", err)
	}

	// Should have sent a TunnelGateway message to the gateway
	msgs := transport.getMessages()
	if len(msgs) != 1 {
		t.Fatalf("Expected 1 message, got %d", len(msgs))
	}

	// Message should be sent to gateway hash (not to requester directly)
	if msgs[0].to != gatewayHash {
		t.Error("Tunnel response should be sent to gateway hash")
	}

	// Message should be TunnelGateway (wrapped)
	gatewayMsg, ok := msgs[0].msg.(*i2np.TunnelGateway)
	if !ok {
		t.Fatalf("Expected TunnelGateway, got %T", msgs[0].msg)
	}

	// Verify tunnel ID matches
	expectedTunnelID := tunnel.TunnelID(binary.BigEndian.Uint32(replyTunnelID[:]))
	if gatewayMsg.TunnelID != expectedTunnelID {
		t.Errorf("Tunnel ID mismatch: expected %d, got %d", expectedTunnelID, gatewayMsg.TunnelID)
	}
}

// TestHandleDatabaseLookupDirectSearchReply tests that direct lookups receive direct search replies
func TestHandleDatabaseLookupDirectSearchReply(t *testing.T) {
	db := NewStdNetDB(t.TempDir())
	if err := db.Ensure(); err != nil {
		t.Fatalf("Failed to ensure DB: %v", err)
	}

	transport := &mockFloodfillTransport{}
	var ourHash common.Hash
	copy(ourHash[:], []byte("our_hash_for_search_reply_direct"))

	config := FloodfillConfig{
		Enabled:    true,
		OurHash:    ourHash,
		FloodCount: 4,
	}
	fs := NewFloodfillServer(db, transport, config)

	// Create a lookup for non-existent key with deliveryFlag=0 (direct reply)
	var testKey common.Hash
	copy(testKey[:], []byte("nonexistent_key_for_search_reply"))
	var requesterHash common.Hash
	copy(requesterHash[:], []byte("requester_search_reply_direct!!!"))

	lookup := &i2np.DatabaseLookup{
		Key:   testKey,
		From:  requesterHash,
		Flags: 0x00, // deliveryFlag=0 (direct)
	}

	err := fs.HandleDatabaseLookup(lookup)
	if err != nil {
		t.Fatalf("HandleDatabaseLookup failed: %v", err)
	}

	// Should have sent a DatabaseSearchReply directly
	msgs := transport.getMessages()
	if len(msgs) != 1 {
		t.Fatalf("Expected 1 message, got %d", len(msgs))
	}

	// Message should be sent to requester
	if msgs[0].to != requesterHash {
		t.Error("Direct search reply should be sent to requester hash")
	}

	// Message should be DatabaseSearchReply, not TunnelGateway
	searchReply, ok := msgs[0].msg.(*i2np.DatabaseSearchReply)
	if !ok {
		t.Fatalf("Expected DatabaseSearchReply, got %T", msgs[0].msg)
	}

	// Verify it's a search reply for the requested key
	if searchReply.Key != testKey {
		t.Error("Search reply key does not match lookup key")
	}
}

// TestHandleDatabaseLookupTunnelSearchReply tests that tunnel lookups receive tunnel-wrapped search replies
func TestHandleDatabaseLookupTunnelSearchReply(t *testing.T) {
	db := NewStdNetDB(t.TempDir())
	if err := db.Ensure(); err != nil {
		t.Fatalf("Failed to ensure DB: %v", err)
	}

	transport := &mockFloodfillTransport{}
	var ourHash common.Hash
	copy(ourHash[:], []byte("our_hash_for_search_reply_tunnel"))

	config := FloodfillConfig{
		Enabled:    true,
		OurHash:    ourHash,
		FloodCount: 4,
	}
	fs := NewFloodfillServer(db, transport, config)

	// Create a lookup for non-existent key with deliveryFlag=1 (tunnel reply)
	var testKey common.Hash
	copy(testKey[:], []byte("nonexistent_key_for_tunnel_search"))
	var gatewayHash common.Hash
	copy(gatewayHash[:], []byte("gateway_hash_for_search_reply_tunn"))

	replyTunnelID := [4]byte{0x00, 0x00, 0x27, 0x10} // tunnel ID 10000 in big-endian
	lookup := &i2np.DatabaseLookup{
		Key:           testKey,
		From:          gatewayHash,
		Flags:         0x01, // deliveryFlag=1 (tunnel)
		ReplyTunnelID: replyTunnelID,
	}

	err := fs.HandleDatabaseLookup(lookup)
	if err != nil {
		t.Fatalf("HandleDatabaseLookup failed: %v", err)
	}

	// Should have sent a TunnelGateway message with search reply
	msgs := transport.getMessages()
	if len(msgs) != 1 {
		t.Fatalf("Expected 1 message, got %d", len(msgs))
	}

	// Message should be sent to gateway
	if msgs[0].to != gatewayHash {
		t.Error("Tunnel search reply should be sent to gateway hash")
	}

	// Message should be TunnelGateway
	gatewayMsg, ok := msgs[0].msg.(*i2np.TunnelGateway)
	if !ok {
		t.Fatalf("Expected TunnelGateway, got %T", msgs[0].msg)
	}

	// Verify tunnel ID matches
	expectedTunnelID := tunnel.TunnelID(binary.BigEndian.Uint32(replyTunnelID[:]))
	if gatewayMsg.TunnelID != expectedTunnelID {
		t.Errorf("Tunnel ID mismatch: expected %d, got %d", expectedTunnelID, gatewayMsg.TunnelID)
	}
}

// TestDeliveryFlagExtraction tests the bitwise extraction of deliveryFlag
func TestDeliveryFlagExtraction(t *testing.T) {
	tests := []struct {
		flags        byte
		expectedFlag byte
		description  string
	}{
		{0x00, 0, "direct delivery (bit 0 = 0)"},
		{0x01, 1, "tunnel delivery (bit 0 = 1)"},
		{0x05, 1, "tunnel delivery with other bits set"},
		{0x08, 0, "direct delivery with lookup type bits set"},
		{0x0F, 1, "all bits set, deliveryFlag = 1"},
	}

	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			deliveryFlag := tt.flags & 0x01
			if deliveryFlag != tt.expectedFlag {
				t.Errorf("Expected deliveryFlag %d, got %d", tt.expectedFlag, deliveryFlag)
			}
		})
	}
}

func TestHandleDatabaseLookupDirectECIESResponse(t *testing.T) {
	db := NewStdNetDB(t.TempDir())
	if err := db.Ensure(); err != nil {
		t.Fatalf("Failed to ensure DB: %v", err)
	}

	transport := &mockFloodfillTransport{}
	var ourHash common.Hash
	copy(ourHash[:], []byte("our_hash_for_ecies_direct_reply!!"))

	fs := NewFloodfillServer(db, transport, FloodfillConfig{Enabled: true, OurHash: ourHash, FloodCount: 4})

	var testKey common.Hash
	copy(testKey[:], []byte("nonexistent_key_for_ecies_direct!!"))
	var requesterHash common.Hash
	copy(requesterHash[:], []byte("requester_for_ecies_direct_reply!"))

	var replyKey session_key.SessionKey
	replyKey[0] = 0x11
	tagBytes := make([]byte, 8)
	tagBytes[0] = 0x22
	eciesTag, err := session_tag.NewECIESSessionTagFromBytes(tagBytes)
	if err != nil {
		t.Fatalf("Failed to create ECIES tag: %v", err)
	}

	lookup := &i2np.DatabaseLookup{
		Key:            testKey,
		From:           requesterHash,
		Flags:          i2np.DatabaseLookupFlagECIES,
		ReplyKey:       replyKey,
		Tags:           1,
		ECIESReplyTags: []session_tag.ECIESSessionTag{eciesTag},
	}

	err = fs.HandleDatabaseLookup(lookup)
	if err != nil {
		t.Fatalf("HandleDatabaseLookup failed: %v", err)
	}

	msgs := transport.getMessages()
	if len(msgs) != 1 {
		t.Fatalf("Expected 1 message, got %d", len(msgs))
	}
	if msgs[0].to != requesterHash {
		t.Fatal("ECIES direct reply should be sent to requester")
	}
	garlic, ok := msgs[0].msg.(*i2np.BaseI2NPMessage)
	if !ok {
		t.Fatalf("Expected garlic BaseI2NPMessage, got %T", msgs[0].msg)
	}
	if garlic.Type() != i2np.I2NPMessageTypeGarlic {
		t.Fatalf("Expected garlic message type, got %d", garlic.Type())
	}
	data := garlic.GetData()
	if len(data) < 8+12+16 {
		t.Fatalf("ECIES garlic reply too short: %d", len(data))
	}
	if got := data[:8]; string(got) != string(tagBytes) {
		t.Fatalf("ECIES reply did not preserve requested session tag")
	}
}

func TestHandleDatabaseLookupTunnelECIESResponse(t *testing.T) {
	db := NewStdNetDB(t.TempDir())
	if err := db.Ensure(); err != nil {
		t.Fatalf("Failed to ensure DB: %v", err)
	}

	transport := &mockFloodfillTransport{}
	var ourHash common.Hash
	copy(ourHash[:], []byte("our_hash_for_ecies_tunnel_reply!!"))

	fs := NewFloodfillServer(db, transport, FloodfillConfig{Enabled: true, OurHash: ourHash, FloodCount: 4})

	var testKey common.Hash
	copy(testKey[:], []byte("nonexistent_key_for_ecies_tunnel!!"))
	var gatewayHash common.Hash
	copy(gatewayHash[:], []byte("gateway_for_ecies_tunnel_reply!!!"))

	var replyKey session_key.SessionKey
	replyKey[1] = 0x33
	tagBytes := make([]byte, 8)
	tagBytes[1] = 0x44
	eciesTag, err := session_tag.NewECIESSessionTagFromBytes(tagBytes)
	if err != nil {
		t.Fatalf("Failed to create ECIES tag: %v", err)
	}
	replyTunnelID := [4]byte{0x00, 0x00, 0x27, 0x11}

	lookup := &i2np.DatabaseLookup{
		Key:            testKey,
		From:           gatewayHash,
		Flags:          i2np.DatabaseLookupFlagTunnel | i2np.DatabaseLookupFlagECIES,
		ReplyTunnelID:  replyTunnelID,
		ReplyKey:       replyKey,
		Tags:           1,
		ECIESReplyTags: []session_tag.ECIESSessionTag{eciesTag},
	}

	err = fs.HandleDatabaseLookup(lookup)
	if err != nil {
		t.Fatalf("HandleDatabaseLookup failed: %v", err)
	}

	msgs := transport.getMessages()
	if len(msgs) != 1 {
		t.Fatalf("Expected 1 message, got %d", len(msgs))
	}
	if msgs[0].to != gatewayHash {
		t.Fatal("ECIES tunnel reply should be sent to gateway")
	}
	gatewayMsg, ok := msgs[0].msg.(*i2np.TunnelGateway)
	if !ok {
		t.Fatalf("Expected TunnelGateway, got %T", msgs[0].msg)
	}
	expectedTunnelID := tunnel.TunnelID(binary.BigEndian.Uint32(replyTunnelID[:]))
	if gatewayMsg.TunnelID != expectedTunnelID {
		t.Fatalf("Tunnel ID mismatch: expected %d, got %d", expectedTunnelID, gatewayMsg.TunnelID)
	}
}
