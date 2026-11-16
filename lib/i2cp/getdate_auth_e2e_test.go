package i2cp

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildGetDatePayloadWithAuth assembles a spec-conformant GetDate payload:
//
//	[version I2P String][authentication Mapping]
//
// The version is an I2P String (1-byte length + bytes); the mapping is the
// length-prefixed [Mapping]_ a conformant client (Java I2P 0.9.11+) sends with
// the i2cp.username / i2cp.password keys. The mapping is emitted in the order
// the pairs are given, so a caller can exercise the unsorted case the spec
// permits (i2cp.rst:888-889).
func buildGetDatePayloadWithAuth(version string, pairs [][2]string) []byte {
	payload := make([]byte, 0, len(version)+1+16)
	payload = append(payload, byte(len(version)))
	payload = append(payload, version...)

	var body []byte
	for _, kv := range pairs {
		body = append(body, byte(len(kv[0])))
		body = append(body, kv[0]...)
		body = append(body, '=')
		body = append(body, byte(len(kv[1])))
		body = append(body, kv[1]...)
		body = append(body, ';')
	}
	payload = append(payload, byte(len(body)>>8), byte(len(body)))
	return append(payload, body...)
}

// startAuthServer starts an I2CP server on an ephemeral loopback port with a
// user/pass password authenticator and returns a connected client socket.
func startAuthServer(t *testing.T) net.Conn {
	t.Helper()

	server, err := NewServer(&ServerConfig{
		ListenAddr:  "127.0.0.1:0",
		Network:     "tcp",
		MaxSessions: 10,
	})
	require.NoError(t, err, "NewServer() error")

	auth, err := NewPasswordAuthenticator("user", "pass")
	require.NoError(t, err, "NewPasswordAuthenticator() error")
	server.SetAuthenticator(auth)

	require.NoError(t, server.Start(), "Start() error")
	t.Cleanup(func() { server.Stop() })

	time.Sleep(10 * time.Millisecond)

	conn, err := dialI2CPClient(server.Addr().String())
	require.NoError(t, err, "dial error")
	t.Cleanup(func() { conn.Close() })
	return conn
}

// readSetDate drains the SetDate response that must follow a GetDate.
func readSetDate(t *testing.T, conn net.Conn) {
	t.Helper()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	resp, err := ReadMessage(context.Background(), conn, 0)
	require.NoError(t, err, "expected a SetDate reply to GetDate")
	require.Equal(t, MessageTypeSetDate, resp.Type, "GetDate must be answered with SetDate")
}

// TestGetDateAuth_EndToEnd_ConformantClientAuthenticated proves the I2P-G-1
// fix: a spec-conformant client that sends its credentials in the GetDate
// authentication [Mapping]_ (length-prefixed, unsorted) is authenticated, so a
// subsequent protected CreateSession succeeds. Before the fix the length byte
// was glued onto each key, the i2cp.username lookup never matched, and this
// CreateSession was rejected.
func TestGetDateAuth_EndToEnd_ConformantClientAuthenticated(t *testing.T) {
	conn := startAuthServer(t)

	// Unsorted mapping (password before username) to prove sort-independence.
	getDate := &Message{
		Type: MessageTypeGetDate,
		Payload: buildGetDatePayloadWithAuth("0.0.0", [][2]string{
			{"i2cp.password", "pass"},
			{"i2cp.username", "user"},
		}),
	}
	require.NoError(t, WriteMessage(conn, getDate), "WriteMessage(GetDate) error")
	readSetDate(t, conn)

	// Now that the connection is authenticated, the protected CreateSession
	// must be accepted rather than rejected for lack of authentication.
	id := generateTestIdentity(t)
	createMsg := &Message{
		Type:      MessageTypeCreateSession,
		SessionID: SessionIDReservedControl,
		Payload:   buildSignedCreateSessionPayload(t, id),
	}
	require.NoError(t, WriteMessage(conn, createMsg), "WriteMessage(CreateSession) error")

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	resp, err := ReadMessage(context.Background(), conn, 0)
	require.NoError(t, err, "authenticated CreateSession must get a SessionStatus reply, not a closed socket")
	require.Equal(t, MessageTypeSessionStatus, resp.Type, "expected SessionStatus for CreateSession")
	require.Equal(t, SessionStatusCreated, resp.Payload[2],
		"a GetDate-authenticated client's CreateSession must be Created, got status %d", resp.Payload[2])
}

// TestGetDateAuth_EndToEnd_WrongCredentialsRejected proves the fix does not
// simply disable authentication: a conformant client that sends the wrong
// password over GetDate is NOT authenticated, so its protected CreateSession
// is rejected (the connection is closed) instead of accepted.
func TestGetDateAuth_EndToEnd_WrongCredentialsRejected(t *testing.T) {
	conn := startAuthServer(t)

	getDate := &Message{
		Type: MessageTypeGetDate,
		Payload: buildGetDatePayloadWithAuth("0.0.0", [][2]string{
			{"i2cp.username", "user"},
			{"i2cp.password", "wrong-password"},
		}),
	}
	require.NoError(t, WriteMessage(conn, getDate), "WriteMessage(GetDate) error")
	readSetDate(t, conn)

	id := generateTestIdentity(t)
	createMsg := &Message{
		Type:      MessageTypeCreateSession,
		SessionID: SessionIDReservedControl,
		Payload:   buildSignedCreateSessionPayload(t, id),
	}
	require.NoError(t, WriteMessage(conn, createMsg), "WriteMessage(CreateSession) error")

	// An unauthenticated protected message closes the connection, so the client
	// must NOT receive a SessionStatusCreated reply.
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	resp, err := ReadMessage(context.Background(), conn, 0)
	if err == nil {
		assert.NotEqual(t, SessionStatusCreated, resp.Payload[2],
			"a wrong-password client must not get a created session")
	}
	// Either a closed socket (err != nil) or a non-created status is acceptable;
	// SessionStatusCreated above is the only failure mode.
}
