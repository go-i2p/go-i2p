package i2cp

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/tunnel"
)

// TestHandleSendMessage tests the SendMessage handler
func TestHandleSendMessage(t *testing.T) {
	// Create server
	server, err := NewServer(nil)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Create session
	session, err := server.manager.CreateSession(nil, nil)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Create test destination hash
	var destHash data.Hash
	copy(destHash[:], []byte("test_destination_hash_32_bytes!"))

	// Create SendMessage payload
	sendPayload := &SendMessagePayload{
		Destination: destHash,
		Payload:     []byte("Test message to send"),
	}

	payloadBytes, err := sendPayload.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to marshal payload: %v", err)
	}

	// Create I2CP message
	msg := &Message{
		Type:      MessageTypeSendMessage,
		SessionID: session.ID(),
		Payload:   payloadBytes,
	}

	// Test without outbound pool (should fail)
	sessionPtr := session
	response, err := server.handleSendMessage(msg, &sessionPtr)
	if err == nil {
		t.Error("Expected error when no outbound pool, got nil")
	}
	if response != nil {
		t.Error("Expected nil response on error")
	}

	// Add outbound pool
	pool := &tunnel.Pool{}
	session.SetOutboundPool(pool)

	// Test with pool (should succeed and return acceptance status)
	response, err = server.handleSendMessage(msg, &sessionPtr)
	if err != nil {
		t.Errorf("Unexpected error with outbound pool: %v", err)
	}
	if response == nil {
		t.Fatal("Expected MessageStatus response, got nil")
	}
	if response.Type != MessageTypeMessageStatus {
		t.Errorf("Expected MessageStatus type, got %d", response.Type)
	}
	// Verify it's an acceptance status (status code should be 1)
	if len(response.Payload) < 5 {
		t.Fatal("MessageStatus payload too short")
	}
	if response.Payload[4] != MessageStatusAccepted {
		t.Errorf("Expected MessageStatusAccepted (%d), got %d", MessageStatusAccepted, response.Payload[4])
	}
}

// TestHandleSendMessageNoSession tests SendMessage without active session
func TestHandleSendMessageNoSession(t *testing.T) {
	server, err := NewServer(nil)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	msg := &Message{
		Type:      MessageTypeSendMessage,
		SessionID: 0x1234,
		Payload:   make([]byte, 50),
	}

	var session *Session
	_, err = server.handleSendMessage(msg, &session)
	if err == nil {
		t.Error("Expected error when no session, got nil")
	}
}

// TestHandleSendMessageInvalidPayload tests SendMessage with malformed payload
func TestHandleSendMessageInvalidPayload(t *testing.T) {
	server, err := NewServer(nil)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	session, err := server.manager.CreateSession(nil, nil)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Add outbound pool
	pool := &tunnel.Pool{}
	session.SetOutboundPool(pool)

	// Create invalid payload (too short)
	msg := &Message{
		Type:      MessageTypeSendMessage,
		SessionID: session.ID(),
		Payload:   make([]byte, 10), // Too short, needs at least 32 bytes
	}

	sessionPtr := session
	_, err = server.handleSendMessage(msg, &sessionPtr)
	if err == nil {
		t.Error("Expected error for invalid payload, got nil")
	}
}

// TestSessionQueueIncomingMessage tests queuing messages for delivery
func TestSessionQueueIncomingMessage(t *testing.T) {
	session, err := NewSession(1, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}
	defer session.Stop()

	// Queue a message
	payload := []byte("Incoming message payload")
	err = session.QueueIncomingMessage(payload)
	if err != nil {
		t.Fatalf("Failed to queue message: %v", err)
	}

	// Receive the message
	received, err := session.ReceiveMessage()
	if err != nil {
		t.Fatalf("Failed to receive message: %v", err)
	}

	if received == nil {
		t.Fatal("Received nil message")
	}

	if !bytes.Equal(received.Payload, payload) {
		t.Errorf("Payload mismatch: got %v, want %v", received.Payload, payload)
	}
}

// TestSessionQueueIncomingMessageAfterStop tests queuing after session stop
func TestSessionQueueIncomingMessageAfterStop(t *testing.T) {
	session, err := NewSession(1, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Stop session
	session.Stop()

	// Try to queue message
	err = session.QueueIncomingMessage([]byte("test"))
	if err == nil {
		t.Error("Expected error when queuing to stopped session, got nil")
	}
}

// TestSessionReceiveMessageAfterStop tests receiving after session stop
func TestSessionReceiveMessageAfterStop(t *testing.T) {
	session, err := NewSession(1, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Stop session
	session.Stop()

	// Try to receive message (should return nil without error)
	msg, err := session.ReceiveMessage()
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if msg != nil {
		t.Error("Expected nil message after stop")
	}
}

// TestSessionIncomingQueueFull tests queue overflow handling
func TestSessionIncomingQueueFull(t *testing.T) {
	session, err := NewSession(1, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}
	defer session.Stop()

	// Fill the queue (buffer is 100)
	for i := 0; i < 100; i++ {
		if err := session.QueueIncomingMessage([]byte("message")); err != nil {
			t.Fatalf("Failed to queue message %d: %v", i, err)
		}
	}

	// Try to queue one more (should fail)
	err = session.QueueIncomingMessage([]byte("overflow"))
	if err == nil {
		t.Error("Expected error when queue is full, got nil")
	}
}

// TestDeliverMessagesToClientIntegration tests the message delivery goroutine
func TestDeliverMessagesToClientIntegration(t *testing.T) {
	// Create in-memory pipe for testing
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	// Create server and session
	server, err := NewServer(nil)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	session, err := server.manager.CreateSession(nil, nil)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Start delivery goroutine
	server.wg.Add(1)
	go server.deliverMessagesToClient(session, serverConn)

	// Queue a message
	testPayload := []byte("Test incoming message")
	if err := session.QueueIncomingMessage(testPayload); err != nil {
		t.Fatalf("Failed to queue message: %v", err)
	}

	// Read MessagePayload from client connection
	readDone := make(chan struct{})
	var readMsg *Message
	var readErr error

	go func() {
		readMsg, readErr = ReadMessage(clientConn)
		close(readDone)
	}()

	// Wait for read with timeout
	select {
	case <-readDone:
		// Success
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for message delivery")
	}

	if readErr != nil {
		t.Fatalf("Failed to read message: %v", readErr)
	}

	// Verify message type
	if readMsg.Type != MessageTypeMessagePayload {
		t.Errorf("Message type = %d, want %d", readMsg.Type, MessageTypeMessagePayload)
	}

	// Verify session ID
	if readMsg.SessionID != session.ID() {
		t.Errorf("SessionID = %d, want %d", readMsg.SessionID, session.ID())
	}

	// Parse MessagePayload payload
	msgPayload, err := ParseMessagePayloadPayload(readMsg.Payload)
	if err != nil {
		t.Fatalf("Failed to parse MessagePayload: %v", err)
	}

	// Verify message ID is non-zero
	if msgPayload.MessageID == 0 {
		t.Error("Expected non-zero message ID")
	}

	// Verify payload
	if !bytes.Equal(msgPayload.Payload, testPayload) {
		t.Errorf("Payload mismatch: got %v, want %v", msgPayload.Payload, testPayload)
	}

	// Clean up
	session.Stop()
	server.wg.Wait()
}

// TestDeliverMessagesToClientMultiple tests delivering multiple messages
func TestDeliverMessagesToClientMultiple(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	server, err := NewServer(nil)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	session, err := server.manager.CreateSession(nil, nil)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Start delivery goroutine
	server.wg.Add(1)
	go server.deliverMessagesToClient(session, serverConn)

	// Queue multiple messages
	numMessages := 5
	for i := 0; i < numMessages; i++ {
		payload := []byte{byte(i), byte(i + 1), byte(i + 2)}
		if err := session.QueueIncomingMessage(payload); err != nil {
			t.Fatalf("Failed to queue message %d: %v", i, err)
		}
	}

	// Read all messages
	receivedCount := 0
	readDone := make(chan struct{})

	go func() {
		for i := 0; i < numMessages; i++ {
			msg, err := ReadMessage(clientConn)
			if err != nil {
				t.Logf("Read error: %v", err)
				break
			}

			if msg.Type != MessageTypeMessagePayload {
				t.Errorf("Message %d: wrong type %d", i, msg.Type)
				continue
			}

			receivedCount++
		}
		close(readDone)
	}()

	// Wait for reads
	select {
	case <-readDone:
		// Success
	case <-time.After(3 * time.Second):
		t.Fatal("Timeout waiting for messages")
	}

	if receivedCount != numMessages {
		t.Errorf("Received %d messages, want %d", receivedCount, numMessages)
	}

	// Clean up
	session.Stop()
	server.wg.Wait()
}

// TestDeliverMessagesToClientMessageIDIncrement tests message ID increments
func TestDeliverMessagesToClientMessageIDIncrement(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	server, err := NewServer(nil)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	session, err := server.manager.CreateSession(nil, nil)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	server.wg.Add(1)
	go server.deliverMessagesToClient(session, serverConn)

	// Queue messages and verify IDs increment
	numMessages := 3
	for i := 0; i < numMessages; i++ {
		if err := session.QueueIncomingMessage([]byte{byte(i)}); err != nil {
			t.Fatalf("Failed to queue message: %v", err)
		}
	}

	// Read and check message IDs
	messageIDs := make([]uint32, 0, numMessages)
	readDone := make(chan struct{})

	go func() {
		for i := 0; i < numMessages; i++ {
			msg, err := ReadMessage(clientConn)
			if err != nil {
				break
			}

			msgPayload, err := ParseMessagePayloadPayload(msg.Payload)
			if err != nil {
				t.Logf("Parse error: %v", err)
				break
			}

			messageIDs = append(messageIDs, msgPayload.MessageID)
		}
		close(readDone)
	}()

	select {
	case <-readDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout")
	}

	// Verify IDs increment
	if len(messageIDs) != numMessages {
		t.Fatalf("Got %d IDs, want %d", len(messageIDs), numMessages)
	}

	for i := 0; i < len(messageIDs); i++ {
		expectedID := uint32(i + 1) // IDs start at 1
		if messageIDs[i] != expectedID {
			t.Errorf("Message %d: ID = %d, want %d", i, messageIDs[i], expectedID)
		}
	}

	session.Stop()
	server.wg.Wait()
}
