package i2cp

import (
	"net"
	"sync"
	"testing"
)

// TestC2_SendStatusToClient_AppliesWriteDeadline verifies that async
// MessageStatus writes use the same write-deadline protection as normal
// response writes.
func TestC2_SendStatusToClient_AppliesWriteDeadline(t *testing.T) {
	server := &Server{
		config: &ServerConfig{
			WriteTimeout: 0, // enforce minimumWriteTimeout via applyWriteDeadline
		},
		sessionConns: make(map[uint16]net.Conn),
		connWriteMu:  make(map[uint16]*sync.Mutex),
	}

	session := &Session{id: 42}
	conn := &mockConnWithDeadlineTracking{}
	server.sessionConns[session.ID()] = conn
	server.connWriteMu[session.ID()] = &sync.Mutex{}

	statusMsg := buildMessageStatusResponse(session.ID(), 1001, MessageStatusAccepted, 16, 77)
	server.sendStatusToClient(session, statusMsg)

	if conn.deadlineCalls == 0 {
		t.Fatal("expected sendStatusToClient to apply write deadline")
	}
	if conn.writeBuffer.Len() == 0 {
		t.Fatal("expected status message bytes to be written")
	}
}
