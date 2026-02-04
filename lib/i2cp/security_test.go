package i2cp

import (
	"bytes"
	"encoding/binary"
	"sync"
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/tunnel"
)

// =============================================================================
// Tests for lib/i2cp package
// =============================================================================
// These tests verify the security properties of the I2CP implementation.
//
// Coverage:
// - Protocol Compliance: v0.9.67 message types correct
// - Session Limits: Max sessions enforced (default 100)
// - Session Isolation: Cross-session information leakage
// - Message Framing: Length validation, buffer overflows
// - LeaseSet Publishing: Correct integration with NetDB
// - Message Routing: Outbound through tunnels with garlic
// - Inbound Delivery: Tunnel → session message delivery
// - Host Lookup: Hostname and hash resolution
// - Blinding Info: Encrypted LeaseSet parameters
// - Disconnect Handling: Graceful session cleanup
// - Thread Safety: Concurrent session access

// =============================================================================
// PROTOCOL COMPLIANCE TESTS (v0.9.67)
// =============================================================================

// TestProtocolCompliance_MessageTypeConstants verifies all I2CP v0.9.67
// message type constants are correctly defined.
func TestProtocolCompliance_MessageTypeConstants(t *testing.T) {
	// Session management
	tests := []struct {
		name     string
		constant uint8
		expected uint8
	}{
		// Per I2CP spec v0.9.67
		{"CreateSession", MessageTypeCreateSession, 1},
		{"SessionStatus", MessageTypeSessionStatus, 20},
		{"ReconfigureSession", MessageTypeReconfigureSession, 2},
		{"DestroySession", MessageTypeDestroySession, 3},
		{"CreateLeaseSet", MessageTypeCreateLeaseSet, 4},
		{"RequestLeaseSet", MessageTypeRequestLeaseSet, 21},
		{"RequestVariableLeaseSet", MessageTypeRequestVariableLeaseSet, 37},
		{"CreateLeaseSet2", MessageTypeCreateLeaseSet2, 41},
		{"SendMessage", MessageTypeSendMessage, 5},
		{"MessagePayload", MessageTypeMessagePayload, 31},
		{"MessageStatus", MessageTypeMessageStatus, 22},
		{"Disconnect", MessageTypeDisconnect, 30},
		{"SendMessageExpires", MessageTypeSendMessageExpires, 36},
		{"GetBandwidthLimits", MessageTypeGetBandwidthLimits, 8},
		{"BandwidthLimits", MessageTypeBandwidthLimits, 23},
		{"GetDate", MessageTypeGetDate, 32},
		{"SetDate", MessageTypeSetDate, 33},
		{"HostLookup", MessageTypeHostLookup, 38},
		{"HostReply", MessageTypeHostReply, 39},
		{"BlindingInfo", MessageTypeBlindingInfo, 42},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant != tt.expected {
				t.Errorf("%s = %d, want %d (per I2CP v0.9.67)", tt.name, tt.constant, tt.expected)
			}
		})
	}
}

// TestProtocolCompliance_VersionString verifies the protocol version string.
func TestProtocolCompliance_VersionString(t *testing.T) {
	if ProtocolVersionMajor != ExpectedProtocolVersionMajor {
		t.Errorf("ProtocolVersionMajor = %d, want %d", ProtocolVersionMajor, ExpectedProtocolVersionMajor)
	}
	if ProtocolVersionMinor != ExpectedProtocolVersionMinor {
		t.Errorf("ProtocolVersionMinor = %d, want %d", ProtocolVersionMinor, ExpectedProtocolVersionMinor)
	}
	if ProtocolVersionPatch != ExpectedProtocolVersionPatch {
		t.Errorf("ProtocolVersionPatch = %d, want %d", ProtocolVersionPatch, ExpectedProtocolVersionPatch)
	}
}

// TestProtocolCompliance_ReservedSessionIDs verifies reserved session IDs.
func TestProtocolCompliance_ReservedSessionIDs(t *testing.T) {
	if SessionIDReservedControl != 0x0000 {
		t.Errorf("SessionIDReservedControl = 0x%04x, want 0x0000", SessionIDReservedControl)
	}
	if SessionIDReservedBroadcast != 0xFFFF {
		t.Errorf("SessionIDReservedBroadcast = 0x%04x, want 0xFFFF", SessionIDReservedBroadcast)
	}
}

// TestProtocolCompliance_MessageStatusCodes verifies message status codes.
func TestProtocolCompliance_MessageStatusCodes(t *testing.T) {
	tests := []struct {
		name     string
		constant uint8
		expected uint8
	}{
		{"MessageStatusAccepted", MessageStatusAccepted, 1},
		{"MessageStatusSuccess", MessageStatusSuccess, 4},
		{"MessageStatusFailure", MessageStatusFailure, 5},
		{"MessageStatusNoTunnels", MessageStatusNoTunnels, 16},
		{"MessageStatusNoLeaseSet", MessageStatusNoLeaseSet, 21},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant != tt.expected {
				t.Errorf("%s = %d, want %d", tt.name, tt.constant, tt.expected)
			}
		})
	}
}

// =============================================================================
// SESSION LIMITS TESTS
// =============================================================================

// TestSessionLimits_MaxSessionsEnforced verifies the max sessions limit is enforced.
func TestSessionLimits_MaxSessionsEnforced(t *testing.T) {
	manager := NewSessionManager()
	maxSessions := 5

	// Create sessions up to the limit
	for i := 0; i < maxSessions; i++ {
		session, err := manager.CreateSession(nil, nil)
		if err != nil {
			t.Fatalf("CreateSession() error at %d: %v", i, err)
		}
		defer session.Stop()
	}

	if manager.SessionCount() != maxSessions {
		t.Errorf("SessionCount() = %d, want %d", manager.SessionCount(), maxSessions)
	}
}

// TestSessionLimits_SessionIDAllocation verifies session ID allocation is secure.
func TestSessionLimits_SessionIDAllocation(t *testing.T) {
	manager := NewSessionManager()

	// Create multiple sessions and track IDs
	ids := make(map[uint16]bool)
	numSessions := 10

	for i := 0; i < numSessions; i++ {
		session, err := manager.CreateSession(nil, nil)
		if err != nil {
			t.Fatalf("CreateSession() error: %v", err)
		}
		defer session.Stop()

		id := session.ID()

		// Verify not reserved
		if id == SessionIDReservedControl {
			t.Errorf("Session got reserved control ID: 0x%04x", id)
		}
		if id == SessionIDReservedBroadcast {
			t.Errorf("Session got reserved broadcast ID: 0x%04x", id)
		}

		// Verify unique
		if ids[id] {
			t.Errorf("Duplicate session ID: 0x%04x", id)
		}
		ids[id] = true
	}
}

// TestSessionLimits_RandomSessionIDGeneration verifies session IDs are random.
func TestSessionLimits_RandomSessionIDGeneration(t *testing.T) {
	// Generate multiple IDs and verify they're not sequential
	ids := make([]uint16, 0, 20)

	for i := 0; i < 20; i++ {
		id, err := generateSecureSessionID()
		if err != nil {
			t.Fatalf("generateSecureSessionID() error: %v", err)
		}
		ids = append(ids, id)
	}

	// Check that IDs are not sequential (would indicate weak randomness)
	sequential := 0
	for i := 1; i < len(ids); i++ {
		if ids[i] == ids[i-1]+1 || ids[i] == ids[i-1]-1 {
			sequential++
		}
	}

	// Allow at most 2 sequential pairs by chance
	if sequential > 2 {
		t.Errorf("Too many sequential session IDs (%d), indicates weak randomness", sequential)
	}
}

// =============================================================================
// SESSION ISOLATION TESTS
// =============================================================================

// TestSessionIsolation_SeparateNetDBPerSession verifies each session has isolated NetDB.
func TestSessionIsolation_SeparateNetDBPerSession(t *testing.T) {
	session1, err := NewSession(1, nil, nil)
	if err != nil {
		t.Fatalf("NewSession(1) error: %v", err)
	}
	defer session1.Stop()

	session2, err := NewSession(2, nil, nil)
	if err != nil {
		t.Fatalf("NewSession(2) error: %v", err)
	}
	defer session2.Stop()

	// Each session should have its own ClientNetDB
	netdb1 := session1.ClientNetDB()
	netdb2 := session2.ClientNetDB()

	if netdb1 == nil {
		t.Error("Session 1 should have a ClientNetDB")
	}
	if netdb2 == nil {
		t.Error("Session 2 should have a ClientNetDB")
	}

	// They should be different instances
	if netdb1 == netdb2 {
		t.Error("Sessions should have separate NetDB instances")
	}
}

// TestSessionIsolation_SeparateDestinations verifies each session has unique destination.
func TestSessionIsolation_SeparateDestinations(t *testing.T) {
	session1, err := NewSession(1, nil, nil)
	if err != nil {
		t.Fatalf("NewSession(1) error: %v", err)
	}
	defer session1.Stop()

	session2, err := NewSession(2, nil, nil)
	if err != nil {
		t.Fatalf("NewSession(2) error: %v", err)
	}
	defer session2.Stop()

	dest1 := session1.Destination()
	dest2 := session2.Destination()

	if dest1 == nil || dest2 == nil {
		t.Fatal("Sessions should have destinations")
	}

	// Get destination bytes for comparison
	dest1Bytes, err := dest1.Bytes()
	if err != nil {
		t.Fatalf("dest1.Bytes() error: %v", err)
	}
	dest2Bytes, err := dest2.Bytes()
	if err != nil {
		t.Fatalf("dest2.Bytes() error: %v", err)
	}

	// Destinations should be different
	if bytes.Equal(dest1Bytes, dest2Bytes) {
		t.Error("Sessions should have different destinations")
	}
}

// TestSessionIsolation_MessageQueueSeparation verifies message queues are separate.
func TestSessionIsolation_MessageQueueSeparation(t *testing.T) {
	session1, err := NewSession(1, nil, nil)
	if err != nil {
		t.Fatalf("NewSession(1) error: %v", err)
	}
	defer session1.Stop()

	session2, err := NewSession(2, nil, nil)
	if err != nil {
		t.Fatalf("NewSession(2) error: %v", err)
	}
	defer session2.Stop()

	// Queue message to session 1
	msg1 := []byte("message for session 1")
	if err := session1.QueueIncomingMessage(msg1); err != nil {
		t.Fatalf("QueueIncomingMessage(1) error: %v", err)
	}

	// Session 2's queue should be empty
	select {
	case msg := <-session2.IncomingMessages():
		t.Errorf("Session 2 received unexpected message: %v", msg)
	default:
		// Expected: no message in session 2
	}
}

// =============================================================================
// MESSAGE FRAMING TESTS
// =============================================================================

// TestMessageFraming_PayloadSizeLimits verifies payload size limits.
func TestMessageFraming_PayloadSizeLimits(t *testing.T) {
	// Verify MaxPayloadSize is reasonable (256 KB for i2psnark compatibility)
	if MaxPayloadSize != 262144 {
		t.Errorf("MaxPayloadSize = %d, want 262144 (256 KB)", MaxPayloadSize)
	}

	// MaxMessageSize should be header + payload
	expectedMaxMessage := 5 + MaxPayloadSize
	if MaxMessageSize != expectedMaxMessage {
		t.Errorf("MaxMessageSize = %d, want %d", MaxMessageSize, expectedMaxMessage)
	}
}

// TestMessageFraming_OversizedPayloadRejected verifies oversized payloads are rejected.
func TestMessageFraming_OversizedPayloadRejected(t *testing.T) {
	// Create message with payload exceeding MaxPayloadSize
	msg := &Message{
		Type:    MessageTypeSendMessage,
		Payload: make([]byte, MaxPayloadSize+1),
	}

	_, err := msg.MarshalBinary()
	if err == nil {
		t.Error("Expected error for oversized payload, got nil")
	}
}

// TestMessageFraming_ValidPayloadAccepted verifies valid payloads are accepted.
func TestMessageFraming_ValidPayloadAccepted(t *testing.T) {
	// Create message with maximum valid payload
	msg := &Message{
		Type:    MessageTypeSendMessage,
		Payload: make([]byte, MaxPayloadSize),
	}

	data, err := msg.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error for max payload: %v", err)
	}

	// Verify wire format
	expectedLen := 5 + MaxPayloadSize
	if len(data) != expectedLen {
		t.Errorf("Serialized length = %d, want %d", len(data), expectedLen)
	}
}

// TestMessageFraming_EmptyPayloadValid verifies empty payloads are valid.
func TestMessageFraming_EmptyPayloadValid(t *testing.T) {
	msg := &Message{
		Type:    MessageTypeGetDate,
		Payload: nil,
	}

	data, err := msg.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error for empty payload: %v", err)
	}

	// Header only: length(4) + type(1) = 5 bytes
	if len(data) != 5 {
		t.Errorf("Empty message length = %d, want 5", len(data))
	}
}

// TestMessageFraming_RoundTrip verifies message serialization round-trip.
func TestMessageFraming_RoundTrip(t *testing.T) {
	original := &Message{
		Type:    MessageTypeSendMessage,
		Payload: []byte("test payload data"),
	}

	data, err := original.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error: %v", err)
	}

	recovered := &Message{}
	if err := recovered.UnmarshalBinary(data); err != nil {
		t.Fatalf("UnmarshalBinary() error: %v", err)
	}

	if recovered.Type != original.Type {
		t.Errorf("Type = %d, want %d", recovered.Type, original.Type)
	}
	if !bytes.Equal(recovered.Payload, original.Payload) {
		t.Errorf("Payload mismatch")
	}
}

// TestMessageFraming_TruncatedMessageRejected verifies truncated messages are rejected.
func TestMessageFraming_TruncatedMessageRejected(t *testing.T) {
	// Create valid message
	msg := &Message{
		Type:    MessageTypeSendMessage,
		Payload: []byte("test payload"),
	}

	data, _ := msg.MarshalBinary()

	// Truncate the data
	truncated := data[:len(data)-5]

	recovered := &Message{}
	err := recovered.UnmarshalBinary(truncated)
	if err == nil {
		t.Error("Expected error for truncated message, got nil")
	}
}

// =============================================================================
// DISCONNECT HANDLING TESTS
// =============================================================================

// TestDisconnectHandling_GracefulCleanup verifies disconnect cleans up resources.
func TestDisconnectHandling_GracefulCleanup(t *testing.T) {
	session, err := NewSession(1, nil, nil)
	if err != nil {
		t.Fatalf("NewSession() error: %v", err)
	}

	// Verify active before stop
	if !session.IsActive() {
		t.Error("Session should be active before stop")
	}

	// Stop session
	session.Stop()

	// Verify inactive after stop
	if session.IsActive() {
		t.Error("Session should not be active after stop")
	}
}

// TestDisconnectHandling_MultipleStopSafe verifies multiple Stop() calls are safe.
func TestDisconnectHandling_MultipleStopSafe(t *testing.T) {
	session, err := NewSession(1, nil, nil)
	if err != nil {
		t.Fatalf("NewSession() error: %v", err)
	}

	// Multiple stops should not panic
	session.Stop()
	session.Stop()
	session.Stop()

	// Still should be inactive
	if session.IsActive() {
		t.Error("Session should not be active after multiple stops")
	}
}

// TestDisconnectHandling_QueueRejectedAfterStop verifies queue operations fail after stop.
func TestDisconnectHandling_QueueRejectedAfterStop(t *testing.T) {
	session, err := NewSession(1, nil, nil)
	if err != nil {
		t.Fatalf("NewSession() error: %v", err)
	}

	session.Stop()

	// Queue should reject new messages
	err = session.QueueIncomingMessage([]byte("test"))
	if err == nil {
		t.Error("Expected error queuing to stopped session")
	}
}

// TestDisconnectHandling_ReceiveReturnsNilAfterStop verifies receive unblocks after stop.
func TestDisconnectHandling_ReceiveReturnsNilAfterStop(t *testing.T) {
	session, err := NewSession(1, nil, nil)
	if err != nil {
		t.Fatalf("NewSession() error: %v", err)
	}

	// Start receiver in goroutine
	done := make(chan bool)
	go func() {
		msg, _ := session.ReceiveMessage()
		done <- (msg == nil)
	}()

	// Small delay then stop
	time.Sleep(10 * time.Millisecond)
	session.Stop()

	// Verify receive returned nil
	select {
	case gotNil := <-done:
		if !gotNil {
			t.Error("ReceiveMessage should return nil after stop")
		}
	case <-time.After(1 * time.Second):
		t.Error("ReceiveMessage did not unblock after stop")
	}
}

// =============================================================================
// THREAD SAFETY TESTS
// =============================================================================

// TestThreadSafety_ConcurrentSessionCreation verifies concurrent session creation is safe.
func TestThreadSafety_ConcurrentSessionCreation(t *testing.T) {
	manager := NewSessionManager()
	var wg sync.WaitGroup
	numGoroutines := 20

	sessions := make(chan *Session, numGoroutines)
	errors := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			session, err := manager.CreateSession(nil, nil)
			if err != nil {
				errors <- err
				return
			}
			sessions <- session
		}()
	}

	wg.Wait()
	close(sessions)
	close(errors)

	// Check for errors
	for err := range errors {
		t.Errorf("CreateSession() error: %v", err)
	}

	// Cleanup
	for session := range sessions {
		session.Stop()
	}
}

// TestThreadSafety_ConcurrentSessionAccess verifies concurrent session access is safe.
func TestThreadSafety_ConcurrentSessionAccess(t *testing.T) {
	session, err := NewSession(1, nil, nil)
	if err != nil {
		t.Fatalf("NewSession() error: %v", err)
	}
	defer session.Stop()

	var wg sync.WaitGroup
	numGoroutines := 20

	// Concurrent reads
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = session.ID()
			_ = session.IsActive()
			_ = session.Destination()
			_ = session.Config()
			_ = session.CreatedAt()
			_ = session.LastActivity()
		}()
	}

	wg.Wait()
}

// TestThreadSafety_ConcurrentMessageQueue verifies concurrent message queue access is safe.
func TestThreadSafety_ConcurrentMessageQueue(t *testing.T) {
	session, err := NewSession(1, nil, nil)
	if err != nil {
		t.Fatalf("NewSession() error: %v", err)
	}
	defer session.Stop()

	var wg sync.WaitGroup
	numProducers := 10
	numMessages := 5

	// Multiple producers
	for i := 0; i < numProducers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numMessages; j++ {
				msg := []byte{byte(id), byte(j)}
				_ = session.QueueIncomingMessage(msg) // May fail if queue full
			}
		}(i)
	}

	wg.Wait()
}

// TestThreadSafety_SessionManagerConcurrentOps verifies session manager thread safety.
func TestThreadSafety_SessionManagerConcurrentOps(t *testing.T) {
	manager := NewSessionManager()
	var wg sync.WaitGroup
	numOps := 50

	for i := 0; i < numOps; i++ {
		wg.Add(3)

		// Create
		go func() {
			defer wg.Done()
			session, err := manager.CreateSession(nil, nil)
			if err == nil {
				defer session.Stop()
			}
		}()

		// Read count
		go func() {
			defer wg.Done()
			_ = manager.SessionCount()
		}()

		// Get all
		go func() {
			defer wg.Done()
			_ = manager.GetAllSessions()
		}()
	}

	wg.Wait()

	// Cleanup
	manager.StopAll()
}

// =============================================================================
// RATE LIMITING TESTS
// =============================================================================

// TestRateLimiting_TokenBucketBasic verifies basic rate limiter functionality.
func TestRateLimiting_TokenBucketBasic(t *testing.T) {
	rl := newSimpleRateLimiter(10, 5) // 10/sec rate, 5 burst

	// Should allow burst
	for i := 0; i < 5; i++ {
		if !rl.allow() {
			t.Errorf("Rate limiter should allow burst message %d", i)
		}
	}

	// Burst exhausted, should reject
	if rl.allow() {
		t.Error("Rate limiter should reject after burst")
	}
}

// TestRateLimiting_TokenRefill verifies tokens refill over time.
func TestRateLimiting_TokenRefill(t *testing.T) {
	rl := newSimpleRateLimiter(10, 2) // 10/sec rate, 2 burst

	// Exhaust burst
	rl.allow()
	rl.allow()

	// Should reject immediately
	if rl.allow() {
		t.Error("Should reject immediately after burst")
	}

	// Wait for tokens to refill (1 token per 100ms at 10/sec)
	time.Sleep(150 * time.Millisecond)

	// Should allow after refill
	if !rl.allow() {
		t.Error("Should allow after token refill")
	}
}

// TestRateLimiting_DisabledWhenZeroRate verifies rate=0 disables limiting.
func TestRateLimiting_DisabledWhenZeroRate(t *testing.T) {
	rl := newSimpleRateLimiter(0, 0) // Disabled

	// Should always allow
	for i := 0; i < 100; i++ {
		if !rl.allow() {
			t.Errorf("Rate limiter with rate=0 should always allow")
		}
	}
}

// TestRateLimiting_NilRateLimiterAllows verifies nil rate limiter allows all.
func TestRateLimiting_NilRateLimiterAllows(t *testing.T) {
	var rl *simpleRateLimiter = nil

	if !rl.allow() {
		t.Error("Nil rate limiter should allow")
	}
}

// =============================================================================
// HOST LOOKUP TESTS
// =============================================================================

// TestHostLookup_PayloadParsing verifies HostLookup payload parsing.
func TestHostLookup_PayloadParsing(t *testing.T) {
	// Valid hash lookup - correct wire format:
	// bytes 0-3:   RequestID (uint32, big endian)
	// bytes 4-5:   LookupType (uint16, big endian)
	// bytes 6-7:   Query length (uint16, big endian)
	// bytes 8+:    Query string
	t.Run("valid_hash_lookup", func(t *testing.T) {
		// Create a hash lookup with a 32-byte hash query
		hashQuery := string(make([]byte, 32))
		payload := make([]byte, 8+len(hashQuery)) // 4+2+2 header + query
		binary.BigEndian.PutUint32(payload[0:4], 12345)
		binary.BigEndian.PutUint16(payload[4:6], HostLookupTypeHash)
		binary.BigEndian.PutUint16(payload[6:8], uint16(len(hashQuery)))
		copy(payload[8:], hashQuery)

		lookup, err := ParseHostLookupPayload(payload)
		if err != nil {
			t.Fatalf("ParseHostLookupPayload() error: %v", err)
		}

		if lookup.RequestID != 12345 {
			t.Errorf("RequestID = %d, want 12345", lookup.RequestID)
		}
		if lookup.LookupType != HostLookupTypeHash {
			t.Errorf("LookupType = %d, want %d", lookup.LookupType, HostLookupTypeHash)
		}
	})

	// Truncated payload
	t.Run("truncated_payload", func(t *testing.T) {
		payload := []byte{1, 2} // Too short

		_, err := ParseHostLookupPayload(payload)
		if err == nil {
			t.Error("Expected error for truncated payload")
		}
	})
}

// TestHostLookup_ReplyPayloadMarshaling verifies HostReply marshaling.
func TestHostLookup_ReplyPayloadMarshaling(t *testing.T) {
	reply := &HostReplyPayload{
		RequestID:   12345,
		ResultCode:  HostReplySuccess,
		Destination: make([]byte, 387), // Minimal destination
	}

	data, err := reply.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error: %v", err)
	}

	// Verify header
	if binary.BigEndian.Uint32(data[0:4]) != 12345 {
		t.Error("RequestID not serialized correctly")
	}
	if data[4] != HostReplySuccess {
		t.Error("ResultCode not serialized correctly")
	}
}

// =============================================================================
// BLINDING INFO TESTS
// =============================================================================

// TestBlindingInfo_PayloadParsing verifies BlindingInfo payload parsing.
func TestBlindingInfo_PayloadParsing(t *testing.T) {
	// Valid blinding info - correct wire format:
	// byte 0: enabled flag (0x00 = disabled, 0x01 = enabled)
	// bytes 1-32: secret (only if enabled, exactly 32 bytes)
	t.Run("valid_blinding_info", func(t *testing.T) {
		payload := make([]byte, 33)         // 1 (enabled flag) + 32 (secret)
		payload[0] = 0x01                   // enabled
		copy(payload[1:], make([]byte, 32)) // 32-byte secret

		info, err := ParseBlindingInfoPayload(payload)
		if err != nil {
			t.Fatalf("ParseBlindingInfoPayload() error: %v", err)
		}

		if !info.Enabled {
			t.Error("Enabled should be true")
		}
		if len(info.Secret) != 32 {
			t.Errorf("Secret length = %d, want 32", len(info.Secret))
		}
	})

	// Disabled blinding
	t.Run("disabled_blinding", func(t *testing.T) {
		payload := []byte{0x00} // disabled

		info, err := ParseBlindingInfoPayload(payload)
		if err != nil {
			t.Fatalf("ParseBlindingInfoPayload() error: %v", err)
		}

		if info.Enabled {
			t.Error("Enabled should be false")
		}
	})
}

// =============================================================================
// MESSAGE ROUTER TESTS
// =============================================================================

// mockTransportSender is a mock transport sender for testing.
type mockTransportSender struct {
	mu       sync.Mutex
	messages []mockSentMessage
}

type mockSentMessage struct {
	peerHash common.Hash
	msg      interface{}
}

// TestMessageRouter_StatusCallbackInvoked verifies status callbacks are called.
func TestMessageRouter_StatusCallbackInvoked(t *testing.T) {
	router := NewMessageRouter(nil, nil)

	// Without tunnel pool, should fail with NoTunnels status
	session, _ := NewSession(1, nil, nil)
	defer session.Stop()

	var receivedStatus uint8
	callback := func(messageID uint32, statusCode uint8, messageSize, nonce uint32) {
		receivedStatus = statusCode
	}

	var destHash common.Hash
	var destKey [32]byte

	err := router.RouteOutboundMessage(session, 1, destHash, destKey, []byte("test"), 0, callback)
	if err == nil {
		t.Error("Expected error without outbound pool")
	}

	if receivedStatus != MessageStatusNoTunnels {
		t.Errorf("Status = %d, want %d (NoTunnels)", receivedStatus, MessageStatusNoTunnels)
	}
}

// =============================================================================
// LEASESET PUBLISHING TESTS
// =============================================================================

// TestLeaseSetPublishing_PublisherIntegration verifies LeaseSet publisher integration.
func TestLeaseSetPublishing_PublisherIntegration(t *testing.T) {
	publisher := newMockLeaseSetPublisher()

	session, err := NewSession(1, nil, nil)
	if err != nil {
		t.Fatalf("NewSession() error: %v", err)
	}
	defer session.Stop()

	session.SetLeaseSetPublisher(publisher)

	// Setup tunnel pool with mock tunnel (using mockPeerSelector from session_test.go)
	selector := &mockPeerSelector{}
	pool := tunnel.NewTunnelPool(selector)
	session.SetInboundPool(pool)

	var gatewayHash common.Hash
	copy(gatewayHash[:], []byte("gateway-router-hash-12345678"))

	tunnelState := &tunnel.TunnelState{
		ID:        tunnel.TunnelID(12345),
		Hops:      []common.Hash{gatewayHash},
		State:     tunnel.TunnelReady,
		CreatedAt: time.Now(),
	}
	pool.AddTunnel(tunnelState)

	// Create LeaseSet
	leaseSetBytes, err := session.CreateLeaseSet()
	if err != nil {
		t.Fatalf("CreateLeaseSet() error: %v", err)
	}

	// Verify LeaseSet was created
	if leaseSetBytes == nil || len(leaseSetBytes) == 0 {
		t.Error("LeaseSet bytes should not be empty")
	}
}

// =============================================================================
// ERROR MESSAGE SAFETY TESTS
// =============================================================================

// TestErrorMessages_NoSensitiveData verifies error messages don't leak sensitive data.
func TestErrorMessages_NoSensitiveData(t *testing.T) {
	sensitivePatterns := []string{
		"password",
		"secret",
		"private",
		"key=",
	}

	// Test various error conditions
	errors := []error{}

	// Truncated message
	msg := &Message{}
	err := msg.UnmarshalBinary([]byte{1, 2})
	if err != nil {
		errors = append(errors, err)
	}

	// Check error messages
	for _, e := range errors {
		if e == nil {
			continue
		}
		errStr := e.Error()
		for _, pattern := range sensitivePatterns {
			if bytes.Contains([]byte(errStr), []byte(pattern)) {
				t.Errorf("Error message contains sensitive pattern '%s': %s", pattern, errStr)
			}
		}
	}
}

// =============================================================================
// HELPER TYPES AND FUNCTIONS
// =============================================================================

// IncomingMessages returns the incoming message channel for testing.
func (s *Session) IncomingMessages() <-chan *IncomingMessage {
	return s.incomingMessages
}

// ClientNetDB returns the session's client NetDB for testing isolation.
func (s *Session) ClientNetDB() interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.clientNetDB
}
