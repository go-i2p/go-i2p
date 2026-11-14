package i2cp

import (
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

// TestGI_I2CP_001_SendMessageToClient_AppliesWriteDeadline verifies that the
// I2CP message-delivery path re-arms the per-connection write deadline before
// each write, just like sendResponse and sendStatusToClient already do.
//
// Regression for GI-I2CP-001 (HIGH, deaf sessions): the delivery goroutine
// previously wrote MessagePayload messages without setting a write deadline.
// The absolute write-deadline floor set by an earlier response/status write
// persisted on the connection; once it lapsed (after minimumWriteTimeout), the
// next delivery write failed with os.ErrDeadlineExceeded, the delivery loop
// returned, and the goroutine died permanently — the attached client silently
// stopped receiving messages.
func TestGI_I2CP_001_SendMessageToClient_AppliesWriteDeadline(t *testing.T) {
	server := &Server{
		config: &ServerConfig{
			WriteTimeout: 0, // force applyWriteDeadline to use minimumWriteTimeout
		},
		sessionConns: make(map[uint16]net.Conn),
		connWriteMu:  make(map[uint16]*sync.Mutex),
	}

	const sessionID uint16 = 42
	conn := &mockConnWithDeadlineTracking{}
	server.sessionConns[sessionID] = conn
	server.connWriteMu[sessionID] = &sync.Mutex{}

	msg := &Message{
		Type:      MessageTypeMessagePayload,
		SessionID: sessionID,
		Payload:   []byte{0x00, 0x2a, 0x00, 0x00, 0x00, 0x01, 'h', 'i'},
	}

	before := time.Now()
	if stop := server.sendMessageToClient(conn, sessionID, msg); stop {
		t.Fatalf("sendMessageToClient returned stop=true, want delivery to continue")
	}

	// The delivery write must re-arm the deadline (the core of the fix).
	if conn.deadlineCalls == 0 {
		t.Fatal("expected sendMessageToClient to apply a write deadline before writing")
	}

	// The deadline must be freshly reset to ~now+minimumWriteTimeout, not a
	// stale absolute deadline carried over from an earlier write.
	expectedMin := before.Add(minimumWriteTimeout - 100*time.Millisecond)
	expectedMax := time.Now().Add(minimumWriteTimeout + 100*time.Millisecond)
	if conn.lastWriteDeadline.Before(expectedMin) || conn.lastWriteDeadline.After(expectedMax) {
		t.Errorf("write deadline not reset to now+minimumWriteTimeout: got %v, want within [%v, %v]",
			conn.lastWriteDeadline, expectedMin, expectedMax)
	}

	// The message bytes must actually have been written.
	if conn.writeBuffer.Len() == 0 {
		t.Fatal("expected message payload bytes to be written to the connection")
	}
}

// TestGI_I2CP_001_SendMessageToClient_ClosesConnOnWriteFailure verifies that a
// delivery write failure closes the connection instead of leaving the session
// attached-but-deaf. The delivery goroutine does not restart, so a silent
// return would permanently starve the client; closing forces the read loop to
// error out and run the normal coordinated teardown so the client reconnects.
func TestGI_I2CP_001_SendMessageToClient_ClosesConnOnWriteFailure(t *testing.T) {
	server := &Server{
		config: &ServerConfig{
			WriteTimeout: 0,
		},
		sessionConns: make(map[uint16]net.Conn),
		connWriteMu:  make(map[uint16]*sync.Mutex),
	}

	const sessionID uint16 = 7
	conn := &mockConn{writeErr: os.ErrDeadlineExceeded}
	server.sessionConns[sessionID] = conn
	server.connWriteMu[sessionID] = &sync.Mutex{}

	msg := &Message{
		Type:      MessageTypeMessagePayload,
		SessionID: sessionID,
		Payload:   []byte{0x00, 0x07, 0x00, 0x00, 0x00, 0x01, 'x'},
	}

	if stop := server.sendMessageToClient(conn, sessionID, msg); !stop {
		t.Fatal("sendMessageToClient returned stop=false on write error, want delivery to stop")
	}
	if !conn.closed {
		t.Fatal("expected connection to be closed on delivery write failure (no silent deaf session)")
	}
}
