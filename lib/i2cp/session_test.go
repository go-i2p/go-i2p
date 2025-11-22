package i2cp

import (
	"testing"
	"time"
)

func TestDefaultSessionConfig(t *testing.T) {
	config := DefaultSessionConfig()

	if config.InboundTunnelLength != 3 {
		t.Errorf("InboundTunnelLength = %d, want 3", config.InboundTunnelLength)
	}
	if config.OutboundTunnelLength != 3 {
		t.Errorf("OutboundTunnelLength = %d, want 3", config.OutboundTunnelLength)
	}
	if config.InboundTunnelCount != 5 {
		t.Errorf("InboundTunnelCount = %d, want 5", config.InboundTunnelCount)
	}
	if config.OutboundTunnelCount != 5 {
		t.Errorf("OutboundTunnelCount = %d, want 5", config.OutboundTunnelCount)
	}
	if config.TunnelLifetime != 10*time.Minute {
		t.Errorf("TunnelLifetime = %v, want 10m", config.TunnelLifetime)
	}
}

func TestNewSession(t *testing.T) {
	config := DefaultSessionConfig()
	config.Nickname = "test-session"

	session, err := NewSession(1, nil, config)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}

	if session.ID() != 1 {
		t.Errorf("ID() = %d, want 1", session.ID())
	}
	if !session.IsActive() {
		t.Error("Session should be active after creation")
	}
	if session.Config().Nickname != "test-session" {
		t.Errorf("Config().Nickname = %q, want %q", session.Config().Nickname, "test-session")
	}

	// Clean up
	session.Stop()
}

func TestSessionQueueMessage(t *testing.T) {
	session, err := NewSession(1, nil, nil)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	defer session.Stop()

	// Queue a message
	payload := []byte("test message")
	if err := session.QueueIncomingMessage(payload); err != nil {
		t.Fatalf("QueueIncomingMessage() error = %v", err)
	}

	// Receive the message (with timeout)
	done := make(chan struct{})
	var msg *IncomingMessage
	go func() {
		msg, _ = session.ReceiveMessage()
		close(done)
	}()

	select {
	case <-done:
		if msg == nil {
			t.Fatal("ReceiveMessage() returned nil")
		}
		if string(msg.Payload) != string(payload) {
			t.Errorf("Payload = %q, want %q", msg.Payload, payload)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("ReceiveMessage() timeout")
	}
}

func TestSessionQueueFull(t *testing.T) {
	session, err := NewSession(1, nil, nil)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	defer session.Stop()

	// Fill the queue (buffer size is 100)
	for i := 0; i < 100; i++ {
		if err := session.QueueIncomingMessage([]byte("msg")); err != nil {
			t.Fatalf("QueueIncomingMessage() error at %d: %v", i, err)
		}
	}

	// Next message should fail
	if err := session.QueueIncomingMessage([]byte("overflow")); err == nil {
		t.Error("Expected error when queue is full, got nil")
	}
}

func TestSessionStop(t *testing.T) {
	session, err := NewSession(1, nil, nil)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}

	session.Stop()

	if session.IsActive() {
		t.Error("Session should not be active after Stop()")
	}

	// Queuing to stopped session should fail
	if err := session.QueueIncomingMessage([]byte("msg")); err == nil {
		t.Error("Expected error queuing to stopped session, got nil")
	}

	// ReceiveMessage should return immediately
	msg, err := session.ReceiveMessage()
	if msg != nil {
		t.Errorf("ReceiveMessage() from stopped session = %v, want nil", msg)
	}
}

func TestSessionReconfigure(t *testing.T) {
	session, err := NewSession(1, nil, nil)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	defer session.Stop()

	newConfig := DefaultSessionConfig()
	newConfig.InboundTunnelCount = 10
	newConfig.Nickname = "updated"

	if err := session.Reconfigure(newConfig); err != nil {
		t.Fatalf("Reconfigure() error = %v", err)
	}

	if session.Config().InboundTunnelCount != 10 {
		t.Errorf("InboundTunnelCount = %d, want 10", session.Config().InboundTunnelCount)
	}
	if session.Config().Nickname != "updated" {
		t.Errorf("Nickname = %q, want %q", session.Config().Nickname, "updated")
	}
}

func TestSessionManager(t *testing.T) {
	manager := NewSessionManager()

	// Create first session
	session1, err := manager.CreateSession(nil, nil)
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}

	// Verify session is registered
	if manager.SessionCount() != 1 {
		t.Errorf("SessionCount() = %d, want 1", manager.SessionCount())
	}

	// Retrieve session
	retrieved, ok := manager.GetSession(session1.ID())
	if !ok {
		t.Error("GetSession() returned false")
	}
	if retrieved.ID() != session1.ID() {
		t.Errorf("Retrieved session ID = %d, want %d", retrieved.ID(), session1.ID())
	}

	// Create second session
	session2, err := manager.CreateSession(nil, nil)
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}

	if session1.ID() == session2.ID() {
		t.Error("Sessions should have different IDs")
	}

	if manager.SessionCount() != 2 {
		t.Errorf("SessionCount() = %d, want 2", manager.SessionCount())
	}

	// Destroy first session
	if err := manager.DestroySession(session1.ID()); err != nil {
		t.Fatalf("DestroySession() error = %v", err)
	}

	if manager.SessionCount() != 1 {
		t.Errorf("SessionCount() = %d, want 1", manager.SessionCount())
	}

	// First session should not be retrievable
	if _, ok := manager.GetSession(session1.ID()); ok {
		t.Error("Destroyed session should not be retrievable")
	}

	// Clean up
	manager.StopAll()

	if manager.SessionCount() != 0 {
		t.Errorf("SessionCount() after StopAll() = %d, want 0", manager.SessionCount())
	}
}

func TestSessionManagerDestroy_NotFound(t *testing.T) {
	manager := NewSessionManager()

	err := manager.DestroySession(9999)
	if err == nil {
		t.Error("Expected error destroying non-existent session, got nil")
	}
}

func TestSessionManager_MultipleCreatesAndDestroys(t *testing.T) {
	manager := NewSessionManager()

	// Create and destroy multiple sessions
	for i := 0; i < 10; i++ {
		session, err := manager.CreateSession(nil, nil)
		if err != nil {
			t.Fatalf("CreateSession() iteration %d error = %v", i, err)
		}

		if err := manager.DestroySession(session.ID()); err != nil {
			t.Fatalf("DestroySession() iteration %d error = %v", i, err)
		}
	}

	if manager.SessionCount() != 0 {
		t.Errorf("SessionCount() = %d, want 0", manager.SessionCount())
	}
}

func BenchmarkSessionQueueMessage(b *testing.B) {
	session, _ := NewSession(1, nil, nil)
	defer session.Stop()

	payload := []byte("benchmark message")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = session.QueueIncomingMessage(payload)
		// Drain to prevent queue full
		<-session.incomingMessages
	}
}

func BenchmarkSessionManagerCreateDestroy(b *testing.B) {
	manager := NewSessionManager()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		session, _ := manager.CreateSession(nil, nil)
		_ = manager.DestroySession(session.ID())
	}
}
