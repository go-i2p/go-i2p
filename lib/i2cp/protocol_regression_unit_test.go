package i2cp

import (
	"encoding/binary"
	"testing"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/tunnel"
)

// Regression tests for AUDIT.md critical bugs:
// 1. SessionStatus uses wrong status code (0x00 Destroyed instead of 0x01 Created)
// 2. SendMessage payload offset — SessionID not stripped before destination parsing

// TestSessionStatusCreatedCode verifies that buildSessionStatusResponse returns
// status byte 0x01 (Created) per I2CP spec v0.9.67, not 0x00 (Destroyed).
func TestSessionStatusCreatedCode(t *testing.T) {
	sessionID := uint16(42)
	msg := buildSessionStatusResponse(sessionID)

	if msg.Type != MessageTypeSessionStatus {
		t.Errorf("message type = %d, want %d (SessionStatus)", msg.Type, MessageTypeSessionStatus)
	}

	if len(msg.Payload) != 3 {
		t.Fatalf("payload length = %d, want 3 (SessionID(2) + Status(1))", len(msg.Payload))
	}

	// Verify SessionID in payload
	payloadSessionID := binary.BigEndian.Uint16(msg.Payload[0:2])
	if payloadSessionID != sessionID {
		t.Errorf("payload SessionID = %d, want %d", payloadSessionID, sessionID)
	}

	// Critical: status byte MUST be 1 (Created), not 0 (Destroyed)
	if msg.Payload[2] != SessionStatusCreated {
		t.Errorf("status byte = 0x%02x, want 0x%02x (Created)", msg.Payload[2], SessionStatusCreated)
	}
}

// TestSessionStatusDestroyedCode verifies that handleDestroySession returns
// status byte 0x00 (Destroyed) per I2CP spec.
func TestSessionStatusDestroyedCode(t *testing.T) {
	config := &ServerConfig{
		ListenAddr:  "localhost:17690",
		Network:     "tcp",
		MaxSessions: 100,
	}

	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	session, err := server.manager.CreateSession(nil, nil)
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}

	sessionID := session.ID()
	sessionCopy := session

	destroyMsg := &Message{
		Type:      MessageTypeDestroySession,
		SessionID: sessionID,
	}

	response, err := server.handleDestroySession(destroyMsg, &sessionCopy)
	if err != nil {
		t.Fatalf("handleDestroySession() error = %v", err)
	}

	if response == nil {
		t.Fatal("handleDestroySession() returned nil response")
	}

	if len(response.Payload) != 3 {
		t.Fatalf("payload length = %d, want 3", len(response.Payload))
	}

	// Destroyed status must be 0
	if response.Payload[2] != SessionStatusDestroyed {
		t.Errorf("status byte = 0x%02x, want 0x%02x (Destroyed)", response.Payload[2], SessionStatusDestroyed)
	}
}

// TestSessionStatusConstants verifies the session status constants match the I2CP spec.
func TestSessionStatusConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant byte
		expected byte
	}{
		{"Destroyed", SessionStatusDestroyed, 0},
		{"Created", SessionStatusCreated, 1},
		{"Updated", SessionStatusUpdated, 2},
		{"Invalid", SessionStatusInvalid, 3},
		{"Refused", SessionStatusRefused, 4},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant != tt.expected {
				t.Errorf("SessionStatus%s = %d, want %d", tt.name, tt.constant, tt.expected)
			}
		})
	}
}

// TestParseSendMessagePayloadWithSessionIDPrefix verifies that
// parseSendMessagePayload correctly strips the 2-byte SessionID prefix
// from the wire payload before parsing the destination hash.
func TestParseSendMessagePayloadWithSessionIDPrefix(t *testing.T) {
	server, err := NewServer(nil)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	session, err := server.manager.CreateSession(nil, nil)
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}

	// Create a known destination hash
	var destHash data.Hash
	copy(destHash[:], []byte("known_destination_hash_32bytes!"))

	messagePayload := []byte("hello i2p network")

	// Build the inner payload (what ParseSendMessagePayload expects)
	sendPayload := &SendMessagePayload{
		Destination: destHash,
		Payload:     messagePayload,
	}

	innerBytes, err := sendPayload.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}

	// Build the WIRE payload: SessionID(2) + inner payload
	// This is what ReadMessage produces in msg.Payload
	wirePayload := make([]byte, 2+len(innerBytes))
	binary.BigEndian.PutUint16(wirePayload[0:2], session.ID())
	copy(wirePayload[2:], innerBytes)

	msg := &Message{
		Type:      MessageTypeSendMessage,
		SessionID: session.ID(),
		Payload:   wirePayload,
	}

	// Parse via the server method (which should strip SessionID prefix)
	parsed, err := server.parseSendMessagePayload(msg, session)
	if err != nil {
		t.Fatalf("parseSendMessagePayload() error = %v", err)
	}

	// Verify the destination hash was correctly extracted
	if parsed.Destination != destHash {
		t.Errorf("destination hash mismatch:\n  got:  %x\n  want: %x", parsed.Destination, destHash)
	}

	// Verify the payload data was correctly extracted
	if string(parsed.Payload) != string(messagePayload) {
		t.Errorf("payload mismatch:\n  got:  %q\n  want: %q", parsed.Payload, messagePayload)
	}
}

// TestParseSendMessagePayloadTooShort verifies that parseSendMessagePayload
// returns an error when the payload is too short to contain even a SessionID.
func TestParseSendMessagePayloadTooShort(t *testing.T) {
	server, err := NewServer(nil)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	session, err := server.manager.CreateSession(nil, nil)
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}

	msg := &Message{
		Type:      MessageTypeSendMessage,
		SessionID: session.ID(),
		Payload:   []byte{0x01}, // Only 1 byte — too short for 2-byte SessionID
	}

	_, err = server.parseSendMessagePayload(msg, session)
	if err == nil {
		t.Error("Expected error for payload too short for SessionID, got nil")
	}
}

// TestParseSendMessageExpiresPayloadWithSessionIDPrefix verifies that
// parseSendMessageExpiresPayload correctly strips the 2-byte SessionID prefix
// from the wire payload before parsing the destination hash.
func TestParseSendMessageExpiresPayloadWithSessionIDPrefix(t *testing.T) {
	server, err := NewServer(nil)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	session, err := server.manager.CreateSession(nil, nil)
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}

	// Create a known destination hash
	var destHash data.Hash
	copy(destHash[:], []byte("known_destination_hash_32bytes!"))

	messagePayload := []byte("expires test payload")

	// Build the inner payload (what ParseSendMessageExpiresPayload expects)
	sendPayload := &SendMessageExpiresPayload{
		Destination: destHash,
		Payload:     messagePayload,
		Nonce:       12345,
		Expiration:  1700000000000, // milliseconds
	}

	innerBytes, err := sendPayload.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}

	// Build the WIRE payload: SessionID(2) + inner payload
	wirePayload := make([]byte, 2+len(innerBytes))
	binary.BigEndian.PutUint16(wirePayload[0:2], session.ID())
	copy(wirePayload[2:], innerBytes)

	msg := &Message{
		Type:      MessageTypeSendMessageExpires,
		SessionID: session.ID(),
		Payload:   wirePayload,
	}

	// Parse via the server method (which should strip SessionID prefix)
	parsed, err := server.parseSendMessageExpiresPayload(msg, session)
	if err != nil {
		t.Fatalf("parseSendMessageExpiresPayload() error = %v", err)
	}

	// Verify the destination hash was correctly extracted
	if parsed.Destination != destHash {
		t.Errorf("destination hash mismatch:\n  got:  %x\n  want: %x", parsed.Destination, destHash)
	}

	// Verify the payload data was correctly extracted
	if string(parsed.Payload) != string(messagePayload) {
		t.Errorf("payload mismatch:\n  got:  %q\n  want: %q", parsed.Payload, messagePayload)
	}

	// Verify nonce and expiration
	if parsed.Nonce != 12345 {
		t.Errorf("nonce = %d, want 12345", parsed.Nonce)
	}
	if parsed.Expiration != 1700000000000 {
		t.Errorf("expiration = %d, want 1700000000000", parsed.Expiration)
	}
}

// TestParseSendMessageExpiresPayloadTooShort verifies that
// parseSendMessageExpiresPayload returns an error when the payload is too short.
func TestParseSendMessageExpiresPayloadTooShort(t *testing.T) {
	server, err := NewServer(nil)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	session, err := server.manager.CreateSession(nil, nil)
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}

	msg := &Message{
		Type:      MessageTypeSendMessageExpires,
		SessionID: session.ID(),
		Payload:   []byte{0x00}, // Only 1 byte — too short for 2-byte SessionID
	}

	_, err = server.parseSendMessageExpiresPayload(msg, session)
	if err == nil {
		t.Error("Expected error for payload too short for SessionID, got nil")
	}
}

// TestHandleSendMessageWithWireFormatPayload is an end-to-end test that
// exercises handleSendMessage with a wire-format payload (SessionID prefix included)
// and verifies the full handler path including message acceptance.
func TestHandleSendMessageWithWireFormatPayload(t *testing.T) {
	server, err := NewServer(nil)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	session, err := server.manager.CreateSession(nil, nil)
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}

	// Set up outbound pool (required for message sending)
	pool := &tunnel.Pool{}
	session.SetOutboundPool(pool)

	// Create known destination
	var destHash data.Hash
	copy(destHash[:], []byte("wire_format_test_destination_32!"))

	sendPayload := &SendMessagePayload{
		Destination: destHash,
		Payload:     []byte("wire format end-to-end test"),
	}

	innerBytes, err := sendPayload.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}

	// Build wire-format payload with SessionID prefix
	wirePayload := make([]byte, 2+len(innerBytes))
	binary.BigEndian.PutUint16(wirePayload[0:2], session.ID())
	copy(wirePayload[2:], innerBytes)

	msg := &Message{
		Type:      MessageTypeSendMessage,
		SessionID: session.ID(),
		Payload:   wirePayload,
	}

	sessionPtr := session
	response, err := server.handleSendMessage(msg, &sessionPtr)
	if err != nil {
		t.Fatalf("handleSendMessage() error = %v", err)
	}

	if response == nil {
		t.Fatal("Expected MessageStatus response, got nil")
	}

	if response.Type != MessageTypeMessageStatus {
		t.Errorf("response type = %d, want %d (MessageStatus)", response.Type, MessageTypeMessageStatus)
	}

	// MessageStatus payload: SessionID(2) + MessageID(4) + Status(1) + Size(4) + Nonce(4) = 15
	if len(response.Payload) < 15 {
		t.Fatalf("MessageStatus payload too short: %d bytes, want >= 15", len(response.Payload))
	}

	// Status byte at index 6 should be MessageStatusAccepted
	if response.Payload[6] != MessageStatusAccepted {
		t.Errorf("message status = %d, want %d (Accepted)", response.Payload[6], MessageStatusAccepted)
	}
}
