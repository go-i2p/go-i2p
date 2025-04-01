package ntcp

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/go-i2p/go-i2p/lib/crypto/curve25519"
	"github.com/go-i2p/go-i2p/lib/transport/messages"
)

// mockConn implements net.Conn for testing
type mockConn struct {
	readBuf  bytes.Buffer
	writeBuf bytes.Buffer
	closed   bool
	readErr  error
	writeErr error
	deadline time.Time
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	if m.readErr != nil {
		return 0, m.readErr
	}
	return m.readBuf.Read(b)
}

func (m *mockConn) Write(b []byte) (n int, err error) {
	if m.writeErr != nil {
		return 0, m.writeErr
	}
	return m.writeBuf.Write(b)
}

func (m *mockConn) Close() error {
	m.closed = true
	return nil
}

func (m *mockConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (m *mockConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (m *mockConn) SetDeadline(t time.Time) error      { m.deadline = t; return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { m.deadline = t; return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { m.deadline = t; return nil }

// mockSession implements portions of NTCP2Session needed for testing
type mockSession struct {
	NTCP2Session
	createRequestErr            error
	obfuscateEphemeralErr       error
	encryptSessionRequestErr    error
	requestData                 *messages.SessionRequest
	encryptedOptions            []byte
	obfuscatedX                 []byte
	deobfuscateEphemeralErr     error
	deobfuscatedEphemeralResult []byte
}

func (m *mockSession) CreateSessionRequest() (*messages.SessionRequest, error) {
	if m.createRequestErr != nil {
		return nil, m.createRequestErr
	}
	if m.requestData == nil {
		// Create default dummy request
		var xContent [32]byte
		xContent[0] = 5
		xContent[1] = 5

		m.requestData = &messages.SessionRequest{
			XContent: xContent,
			Options:  messages.RequestOptions{},
			Padding:  []byte{9, 10, 11, 12},
		}
	}
	return m.requestData, nil
}

func (m *mockSession) ObfuscateEphemeral(data []byte) ([]byte, error) {
	if m.obfuscateEphemeralErr != nil {
		return nil, m.obfuscateEphemeralErr
	}
	if m.obfuscatedX == nil {
		// Create default obfuscated data
		m.obfuscatedX = []byte{13, 14, 15, 16}
	}
	return m.obfuscatedX, nil
}

func (m *mockSession) encryptSessionRequestOptions(req *messages.SessionRequest, obfuscatedX []byte) ([]byte, error) {
	if m.encryptSessionRequestErr != nil {
		return nil, m.encryptSessionRequestErr
	}
	if m.encryptedOptions == nil {
		// Create default encrypted options
		m.encryptedOptions = []byte{17, 18, 19, 20}
	}
	return m.encryptedOptions, nil
}

func (m *mockSession) DeobfuscateEphemeral(data []byte) ([]byte, error) {
	if m.deobfuscateEphemeralErr != nil {
		return nil, m.deobfuscateEphemeralErr
	}
	if m.deobfuscatedEphemeralResult == nil {
		// Create default deobfuscated result
		m.deobfuscatedEphemeralResult = []byte{21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
			33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52}
	}
	return m.deobfuscatedEphemeralResult, nil
}

// TestSendSessionRequest tests the sendSessionRequest method
func TestSendSessionRequest(t *testing.T) {
	tests := []struct {
		name               string
		conn               *mockConn
		session            *mockSession
		expectErr          bool
		errorSubstring     string
		expectedWriteBytes []byte
	}{
		{
			name:           "successful send",
			conn:           &mockConn{},
			session:        &mockSession{},
			expectErr:      true, // Current implementation still returns "receiveSessionRequest not implemented"
			errorSubstring: "not yet implemented",
		},
		{
			name:           "error creating session request",
			conn:           &mockConn{},
			session:        &mockSession{createRequestErr: errors.New("create request error")},
			expectErr:      true,
			errorSubstring: "create session request",
		},
		{
			name:           "error setting deadline",
			conn:           &mockConn{writeErr: errors.New("deadline error")},
			session:        &mockSession{},
			expectErr:      true,
			errorSubstring: "set deadline",
		},
		{
			name:           "error obfuscating ephemeral",
			conn:           &mockConn{},
			session:        &mockSession{obfuscateEphemeralErr: errors.New("obfuscate error")},
			expectErr:      true,
			errorSubstring: "obfuscate ephemeral",
		},
		{
			name:           "error encrypting options",
			conn:           &mockConn{},
			session:        &mockSession{encryptSessionRequestErr: errors.New("encrypt options error")},
			expectErr:      true,
			errorSubstring: "encrypt options error",
		},
		{
			name:           "error writing to connection",
			conn:           &mockConn{writeErr: errors.New("write error")},
			session:        &mockSession{},
			expectErr:      true,
			errorSubstring: "send session request",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a handshake state for testing
			pubKey, privKey, _ := curve25519.GenerateKeyPair()
			hs := &HandshakeState{
				localEphemeral:  privKey,
				remoteStaticKey: pubKey,
			}

			err := tt.session.sendSessionRequest(tt.conn, hs)

			// Check error conditions
			if tt.expectErr {
				if err == nil {
					t.Errorf("Expected error but got nil")
				} else if tt.errorSubstring != "" && !bytes.Contains([]byte(err.Error()), []byte(tt.errorSubstring)) {
					t.Errorf("Expected error containing '%s', got: %v", tt.errorSubstring, err)
				}
			} else if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			// Check written data if specified
			if tt.expectedWriteBytes != nil && !bytes.Equal(tt.conn.writeBuf.Bytes(), tt.expectedWriteBytes) {
				t.Errorf("Expected write data %v, got %v", tt.expectedWriteBytes, tt.conn.writeBuf.Bytes())
			}
		})
	}
}

// TestReceiveSessionRequest tests the receiveSessionRequest method
func TestReceiveSessionRequest(t *testing.T) {
	// Sample valid request data - this would need to be adjusted based on real protocol data
	validRequest := []byte{
		// 32 bytes of X (ephemeral key)
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
		// 32 bytes of options block
		33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
		49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64,
		// 16 bytes of padding (arbitrary length)
		65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80,
	}

	tests := []struct {
		name           string
		conn           *mockConn
		session        *mockSession
		handshakeState *HandshakeState
		expectErr      bool
		errorSubstring string
	}{
		{
			name: "successful receive",
			conn: &mockConn{
				readBuf: *bytes.NewBuffer(validRequest),
			},
			session: &mockSession{},
			handshakeState: &HandshakeState{
				remotePaddingLen: 16, // Match padding length in valid request
			},
			expectErr: false,
		},
		{
			name: "error reading from connection",
			conn: &mockConn{
				readErr: errors.New("read error"),
			},
			session:        &mockSession{},
			handshakeState: &HandshakeState{},
			expectErr:      true,
			errorSubstring: "read session request",
		},
		{
			name: "error deobfuscating ephemeral key",
			conn: &mockConn{
				readBuf: *bytes.NewBuffer(validRequest),
			},
			session: &mockSession{
				deobfuscateEphemeralErr: errors.New("deobfuscate error"),
			},
			handshakeState: &HandshakeState{},
			expectErr:      true,
			errorSubstring: "de-obfuscate ephemeral",
		},
		{
			name: "invalid padding length",
			conn: &mockConn{
				readBuf: *bytes.NewBuffer(validRequest),
			},
			session: &mockSession{},
			handshakeState: &HandshakeState{
				remotePaddingLen: 32, // Larger than padding in valid request
			},
			expectErr:      true,
			errorSubstring: "invalid padding length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.session.receiveSessionRequest(tt.conn, tt.handshakeState)

			// Check error conditions
			if tt.expectErr {
				if err == nil {
					t.Errorf("Expected error but got nil")
				} else if tt.errorSubstring != "" && !bytes.Contains([]byte(err.Error()), []byte(tt.errorSubstring)) {
					t.Errorf("Expected error containing '%s', got: %v", tt.errorSubstring, err)
				}
			} else if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			// Additional verification could be done here
			// For example, check that the handshake state was updated correctly
			if !tt.expectErr && tt.handshakeState.remoteEphemeral == nil {
				t.Errorf("Expected remoteEphemeral to be set, but was nil")
			}
		})
	}
}

// TestHandshakeIntegration tests a complete handshake flow
func TestHandshakeIntegration(t *testing.T) {
	// This test would simulate a complete handshake
	// It's not fully implemented yet since we need both sides of the handshake
	t.Skip("Integration test not implemented yet")

	// Future implementation would:
	// 1. Create two NTCP2Sessions (client and server)
	// 2. Connect them with mock connections
	// 3. Execute the full handshake sequence
	// 4. Verify that both sides established a secure connection
}
