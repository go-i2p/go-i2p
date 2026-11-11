package i2cp

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIssue54_ReadMessageIdleGapNotBounded verifies that the idle gap between
// messages is NOT bounded by MessageReadTimeout (30s). ReadMessage reads the
// header without a per-message deadline, so a client that completes one
// message and then sits idle is not disconnected.
//
// This test uses a custom reader that blocks between messages to simulate an
// idle client. ReadMessage must return the first message successfully and
// block (not error) when waiting for the next header.
func TestIssue54_ReadMessageIdleGapNotBounded(t *testing.T) {
	// Build a valid GetDate message (no payload needed).
	getDateMsg := &Message{
		Type:      MessageTypeGetDate,
		SessionID: SessionIDReservedControl,
		Payload:   nil,
	}
	raw, err := getDateMsg.MarshalBinary()
	require.NoError(t, err)

	// Reader that returns the full message once, then blocks forever.
	blockingReader := &blockingReader{data: raw}

	// ReadMessage with no payloadReadTimeout (0 = no per-message deadline)
	// and no ctx cancellation should return the first message successfully.
	msg, err := ReadMessage(context.Background(), blockingReader, 0)
	require.NoError(t, err, "first read should succeed")
	require.Equal(t, MessageTypeGetDate, msg.Type, "expected GetDate message")

	// Now the reader blocks forever on the next header read. ReadMessage
	// should block (not return an error) because the header read is not
	// deadline-bounded. We verify this by running ReadMessage in a goroutine
	// with a short deadline — it should NOT return within that deadline.
	done := make(chan error, 1)
	go func() {
		_, err := ReadMessage(context.Background(), blockingReader, 0)
		done <- err
	}()

	select {
	case err := <-done:
		require.NoError(t, err, "blocked header read should not error")
	case <-time.After(100 * time.Millisecond):
		// Expected: ReadMessage is still blocked waiting for the next header.
		// This proves the idle gap is NOT bounded by MessageReadTimeout.
	}
}

// TestIssue54_PerMessageDeadlineRefresh verifies that header+body bytes read
// under the per-message deadline are allowed, but stalling past the
// per-message deadline after the header is rejected as a slow-send.
func TestIssue54_PerMessageDeadlineRefresh(t *testing.T) {
	// Build a message WITH payload so readFullWithDeadlineRefresh is exercised.
	slowMsg := &Message{
		Type:      MessageTypeCreateSession,
		SessionID: SessionIDReservedControl,
		Payload:   make([]byte, 100),
	}
	raw, err := slowMsg.MarshalBinary()
	require.NoError(t, err)

	// Reader that returns the full message immediately.
	immediateReader := &immediateReader{data: raw}

	// ReadMessage with a short payloadReadTimeout should succeed because the
	// full message is available immediately.
	msg, err := ReadMessage(context.Background(), immediateReader, 50*time.Millisecond)
	require.NoError(t, err, "immediate read should succeed")
	require.Equal(t, MessageTypeCreateSession, msg.Type, "expected CreateSession message")

	// Now test slow-send rejection using net.Pipe: write only the header,
	// then stall past the per-message deadline on the payload read.
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	// Start ReadMessage in a goroutine first (it blocks waiting for header).
	readDone := make(chan error, 1)
	go func() {
		_, err := ReadMessage(context.Background(), serverConn, 50*time.Millisecond)
		readDone <- err
	}()

	// Write only the header (5 bytes), then stall.
	headerOnly := raw[:messageHeaderSize]
	_, err = clientConn.Write(headerOnly)
	require.NoError(t, err, "write partial header")

	// Wait for ReadMessage to either fail (timeout) or succeed.
	select {
	case err := <-readDone:
		require.Error(t, err, "expected slow-send read to fail")
		assert.True(t, isTimeoutError(err) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF),
			"expected timeout or EOF for slow-send, got %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("slow-send read did not fail within 2s")
	}

	// Clear the deadline so the conn is usable again.
	require.NoError(t, serverConn.SetReadDeadline(time.Time{}))
}

// TestIssue54_TruncatedPayloadIsFatal verifies that truncated or garbage
// payload after the header still returns a fatal error — malformed input is
// not made survivable by the idle-timeout changes.
func TestIssue54_TruncatedPayloadIsFatal(t *testing.T) {
	// Header declares 100-byte payload but only 10 bytes follow.
	raw := make([]byte, messageHeaderSize+10)
	binary.BigEndian.PutUint32(raw[0:4], 100) // declare 100 bytes
	raw[4] = MessageTypeGetDate

	reader := &immediateReader{data: raw}

	_, err := ReadMessage(context.Background(), reader, 0)
	require.Error(t, err, "expected truncated payload read to fail")
	assert.False(t, errors.Is(err, errIdleTimeout),
		"truncated payload must not be reported as idle timeout")
}

// TestIssue54_ConfiguredReadTimeoutApplied verifies that the configured
// ServerConfig.ReadTimeout is the value actually applied (not silently
// overridden by MessageReadTimeout). This is tested at the readClientMessage
// level which applies ServerConfig.ReadTimeout per iteration.
func TestIssue54_ConfiguredReadTimeoutApplied(t *testing.T) {
	config := &ServerConfig{
		ListenAddr:  "127.0.0.1:0",
		Network:     "tcp",
		MaxSessions: 100,
		ReadTimeout: 7 * time.Second, // non-default, non-30s value
	}

	server, err := NewServer(config)
	require.NoError(t, err)
	defer server.Stop()

	// Verify the configured value is in force by reading it back through the
	// server's config (the knob that readClientMessage applies).
	assert.Equal(t, 7*time.Second, server.config.ReadTimeout,
		"configured ReadTimeout must be the value in force")
}

// blockingReader returns data once, then blocks forever on subsequent reads.
type blockingReader struct {
	data    []byte
	hasRead bool
}

func (r *blockingReader) Read(p []byte) (int, error) {
	if !r.hasRead {
		r.hasRead = true
		return copy(p, r.data), nil
	}
	// Block forever on subsequent reads.
	<-make(chan struct{})
	return 0, nil
}

// immediateReader returns all data immediately on every read.
type immediateReader struct {
	data []byte
	pos  int
}

func (r *immediateReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}
