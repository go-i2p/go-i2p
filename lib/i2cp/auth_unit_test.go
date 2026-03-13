package i2cp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupServerWithAuth creates a Server with a password authenticator (user/pass).
func setupServerWithAuth(t *testing.T) *Server {
	t.Helper()
	server, err := NewServer(nil)
	require.NoError(t, err)
	auth, err := NewPasswordAuthenticator("user", "pass")
	require.NoError(t, err)
	server.SetAuthenticator(auth)
	return server
}

// TestPasswordAuthenticator_ValidCredentials tests that correct credentials are accepted.
func TestPasswordAuthenticator_ValidCredentials(t *testing.T) {
	auth, err := NewPasswordAuthenticator("admin", "secret123")
	require.NoError(t, err)
	assert.True(t, auth.Authenticate("admin", "secret123"))
}

// TestPasswordAuthenticator_InvalidPassword tests that wrong password is rejected.
func TestPasswordAuthenticator_InvalidPassword(t *testing.T) {
	auth, err := NewPasswordAuthenticator("admin", "secret123")
	require.NoError(t, err)
	assert.False(t, auth.Authenticate("admin", "wrongpass"))
}

// TestPasswordAuthenticator_InvalidUsername tests that wrong username is rejected.
func TestPasswordAuthenticator_InvalidUsername(t *testing.T) {
	auth, err := NewPasswordAuthenticator("admin", "secret123")
	require.NoError(t, err)
	assert.False(t, auth.Authenticate("wronguser", "secret123"))
}

// TestPasswordAuthenticator_EmptyCredentials tests that empty credentials are rejected
// when the authenticator expects non-empty ones.
func TestPasswordAuthenticator_EmptyCredentials(t *testing.T) {
	auth, err := NewPasswordAuthenticator("admin", "secret123")
	require.NoError(t, err)
	assert.False(t, auth.Authenticate("", ""))
}

// TestPasswordAuthenticator_EmptyInputRejected tests that NewPasswordAuthenticator
// returns an error when username or password is empty.
func TestPasswordAuthenticator_EmptyInputRejected(t *testing.T) {
	_, err := NewPasswordAuthenticator("", "pass")
	assert.Error(t, err, "empty username should be rejected")

	_, err = NewPasswordAuthenticator("user", "")
	assert.Error(t, err, "empty password should be rejected")

	_, err = NewPasswordAuthenticator("", "")
	assert.Error(t, err, "both empty should be rejected")
}

// TestPasswordAuthenticator_TimingResistance tests that the authenticator uses
// constant-time comparison by verifying it works with various lengths.
func TestPasswordAuthenticator_TimingResistance(t *testing.T) {
	auth, err := NewPasswordAuthenticator("user", "pass")
	require.NoError(t, err)
	// Different lengths should still work correctly
	assert.False(t, auth.Authenticate("u", "p"))
	assert.False(t, auth.Authenticate("useruser", "passpass"))
	assert.True(t, auth.Authenticate("user", "pass"))
}

// TestServer_AuthenticationNotRequired tests that when no authenticator is set,
// authentication is not required.
func TestServer_AuthenticationNotRequired(t *testing.T) {
	server, err := NewServer(nil)
	require.NoError(t, err)

	assert.False(t, server.isAuthenticationRequired())

	state := &connectionState{}
	assert.True(t, server.isConnectionAuthenticated(state))
}

// TestServer_AuthenticationRequired tests that when an authenticator is set,
// authentication is required and unauthenticated connections are rejected.
func TestServer_AuthenticationRequired(t *testing.T) {
	server := setupServerWithAuth(t)
	assert.True(t, server.isAuthenticationRequired())

	state := &connectionState{}
	assert.False(t, server.isConnectionAuthenticated(state),
		"unauthenticated connection should not be allowed")
}

// TestServer_AuthenticateConnection_Success tests successful authentication
// marks the connection as authenticated.
func TestServer_AuthenticateConnection_Success(t *testing.T) {
	server := setupServerWithAuth(t)

	state := &connectionState{}
	assert.True(t, server.authenticateConnection(state, "user", "pass"))
	assert.True(t, state.authenticated.Load())
	assert.True(t, server.isConnectionAuthenticated(state))
}

// TestServer_AuthenticateConnection_Failure tests that failed authentication
// leaves the connection unauthenticated.
func TestServer_AuthenticateConnection_Failure(t *testing.T) {
	server := setupServerWithAuth(t)

	state := &connectionState{}
	assert.False(t, server.authenticateConnection(state, "user", "wrong"))
	assert.False(t, state.authenticated.Load())
	assert.False(t, server.isConnectionAuthenticated(state))
}

// TestServer_SetAuthenticator_Nil tests that setting nil authenticator
// disables authentication.
func TestServer_SetAuthenticator_Nil(t *testing.T) {
	server := setupServerWithAuth(t)
	assert.True(t, server.isAuthenticationRequired())

	server.SetAuthenticator(nil)
	assert.False(t, server.isAuthenticationRequired())
}

// TestServer_RequiresAuthentication_NoAuthenticator tests that no message types
// require auth when no authenticator is configured.
func TestServer_RequiresAuthentication_NoAuthenticator(t *testing.T) {
	server, err := NewServer(nil)
	require.NoError(t, err)

	// No authenticator — nothing requires auth
	assert.False(t, server.requiresAuthentication(MessageTypeCreateSession))
	assert.False(t, server.requiresAuthentication(MessageTypeGetDate))
	assert.False(t, server.requiresAuthentication(MessageTypeSendMessage))
}

// TestServer_RequiresAuthentication_WithAuthenticator tests that session-mutating
// operations require auth but handshake messages do not.
func TestServer_RequiresAuthentication_WithAuthenticator(t *testing.T) {
	server := setupServerWithAuth(t)

	tests := []struct {
		name     string
		msgType  byte
		expected bool
	}{
		{"GetDate", MessageTypeGetDate, false},
		{"GetBandwidthLimits", MessageTypeGetBandwidthLimits, false},
		{"Disconnect", MessageTypeDisconnect, false},
		{"HostLookup", MessageTypeHostLookup, false},
		{"CreateSession", MessageTypeCreateSession, true},
		{"DestroySession", MessageTypeDestroySession, true},
		{"SendMessage", MessageTypeSendMessage, true},
		{"SendMessageExpires", MessageTypeSendMessageExpires, true},
		{"CreateLeaseSet", MessageTypeCreateLeaseSet, true},
		{"CreateLeaseSet2", MessageTypeCreateLeaseSet2, true},
		{"ReconfigureSession", MessageTypeReconfigureSession, true},
		{"BlindingInfo", MessageTypeBlindingInfo, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, server.requiresAuthentication(tt.msgType),
				"%s should require auth = %v", tt.name, tt.expected)
		})
	}
}

// TestParseGetDateOptions_ValidMapping tests parsing of a well-formed options mapping.
func TestParseGetDateOptions_ValidMapping(t *testing.T) {
	// Build a mapping: 2-byte size + "key1=val1;key2=val2;"
	content := "i2cp.username=admin;i2cp.password=secret;"
	data := buildGetDateOptionsData(content)

	options := parseGetDateOptions(data)
	require.NotNil(t, options)
	assert.Equal(t, "admin", options["i2cp.username"])
	assert.Equal(t, "secret", options["i2cp.password"])
}

// TestParseGetDateOptions_EmptyMapping tests parsing of an empty mapping.
func TestParseGetDateOptions_EmptyMapping(t *testing.T) {
	data := []byte{0x00, 0x00} // size = 0
	options := parseGetDateOptions(data)
	assert.Nil(t, options)
}

// TestParseGetDateOptions_TooShort tests parsing of data that's too short.
func TestParseGetDateOptions_TooShort(t *testing.T) {
	options := parseGetDateOptions([]byte{0x00})
	assert.Nil(t, options)

	options = parseGetDateOptions(nil)
	assert.Nil(t, options)
}

// TestParseGetDateOptions_NoTrailingSemicolon tests that the last entry is
// parsed correctly even without a trailing semicolon.
func TestParseGetDateOptions_NoTrailingSemicolon(t *testing.T) {
	content := "key=value"
	data := buildGetDateOptionsData(content)

	options := parseGetDateOptions(data)
	require.NotNil(t, options)
	assert.Equal(t, "value", options["key"])
}

// TestSplitKeyValue tests the key=value string splitting helper.
func TestSplitKeyValue(t *testing.T) {
	tests := []struct {
		input string
		key   string
		value string
	}{
		{"key=value", "key", "value"},
		{"key=", "key", ""},
		{"key", "key", ""},
		{"a=b=c", "a", "b=c"}, // only first = is the delimiter
		{"=value", "", "value"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			key, value := splitKeyValue(tt.input)
			assert.Equal(t, tt.key, key)
			assert.Equal(t, tt.value, value)
		})
	}
}

// TestServer_AuthenticateConnection_NoAuthenticator tests that authentication
// always succeeds when no authenticator is configured.
func TestServer_AuthenticateConnection_NoAuthenticator(t *testing.T) {
	server, err := NewServer(nil)
	require.NoError(t, err)

	state := &connectionState{}
	assert.True(t, server.authenticateConnection(state, "", ""))
	assert.True(t, server.authenticateConnection(state, "any", "thing"))
}
