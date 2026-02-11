package i2cp

import (
	"crypto/subtle"
	"encoding/binary"
	"net"

	"github.com/go-i2p/logger"
)

// Authenticator validates I2CP client credentials.
// Implementations must be safe for concurrent use.
type Authenticator interface {
	// Authenticate checks whether the provided username and password are valid.
	// Returns true if the credentials are accepted, false otherwise.
	Authenticate(username, password string) bool
}

// PasswordAuthenticator implements simple username/password authentication.
// It uses constant-time comparison to prevent timing attacks.
type PasswordAuthenticator struct {
	username string
	password string
}

// NewPasswordAuthenticator creates an authenticator that accepts a single
// username/password pair. Both fields are required and must be non-empty.
func NewPasswordAuthenticator(username, password string) *PasswordAuthenticator {
	return &PasswordAuthenticator{
		username: username,
		password: password,
	}
}

// Authenticate checks if the provided credentials match the configured pair.
// Uses constant-time comparison to prevent timing side-channel attacks.
func (a *PasswordAuthenticator) Authenticate(username, password string) bool {
	usernameMatch := subtle.ConstantTimeCompare([]byte(a.username), []byte(username)) == 1
	passwordMatch := subtle.ConstantTimeCompare([]byte(a.password), []byte(password)) == 1

	if usernameMatch && passwordMatch {
		log.WithField("username", username).Debug("i2cp_authentication_success")
		return true
	}

	log.WithFields(logger.Fields{
		"username": username,
		"reason":   "invalid_credentials",
	}).Warn("i2cp_authentication_failure")
	return false
}

// isAuthenticationRequired checks if the server has authentication enabled.
// Authentication is optional: if no authenticator is configured, all clients
// are allowed to create sessions (backward-compatible behavior).
func (s *Server) isAuthenticationRequired() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.authenticator != nil
}

// isConnectionAuthenticated checks if a connection has been authenticated.
// Returns true if authentication is not required or the connection has
// already been successfully authenticated.
func (s *Server) isConnectionAuthenticated(state *connectionState) bool {
	if !s.isAuthenticationRequired() {
		return true // No authenticator configured — allow all
	}
	return state.authenticated
}

// authenticateConnection validates credentials against the configured authenticator.
// Returns true if authentication succeeds. The connection state is updated
// so subsequent calls to isConnectionAuthenticated return true.
func (s *Server) authenticateConnection(state *connectionState, username, password string) bool {
	s.mu.RLock()
	auth := s.authenticator
	s.mu.RUnlock()

	if auth == nil {
		return true // No authenticator — always succeeds
	}

	if auth.Authenticate(username, password) {
		state.authenticated = true
		return true
	}
	return false
}

// SetAuthenticator configures the optional authenticator for I2CP connections.
// When set, clients must provide valid credentials before creating sessions.
// Pass nil to disable authentication (all clients accepted).
//
// This should be called before Start() and is not safe to call concurrently
// with active connections.
func (s *Server) SetAuthenticator(auth Authenticator) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authenticator = auth

	if auth != nil {
		log.Info("i2cp_authentication_enabled")
	} else {
		log.Info("i2cp_authentication_disabled")
	}
}

// requiresAuthentication returns true if the given message type requires
// the connection to be authenticated before processing.
// The following message types are allowed without authentication:
//   - GetDate (type 32): Needed for handshake; also carries auth credentials
//   - GetBandwidthLimits (type 8): Read-only informational query
//   - Disconnect (type 30): Graceful disconnection always allowed
//   - HostLookup (type 38): Read-only informational query
//
// All other message types (CreateSession, SendMessage, etc.) require auth.
func (s *Server) requiresAuthentication(msgType byte) bool {
	if !s.isAuthenticationRequired() {
		return false // No authenticator configured — nothing requires auth
	}

	switch msgType {
	case MessageTypeGetDate,
		MessageTypeGetBandwidthLimits,
		MessageTypeDisconnect,
		MessageTypeHostLookup:
		return false // Allowed without authentication
	default:
		return true // All other operations require authentication
	}
}

// attemptAuthFromGetDate extracts authentication credentials from a GetDate
// message payload and attempts to authenticate the connection.
//
// Per the I2CP specification, GetDate (type 32) payload format is:
//
//	[version_string_length:2][version_string:N][options_mapping...]
//
// The options mapping may contain "i2cp.username" and "i2cp.password" keys.
// If credentials are present and valid, the connection is marked as authenticated.
func (s *Server) attemptAuthFromGetDate(conn net.Conn, msg *Message) {
	if !s.isAuthenticationRequired() {
		return // No authentication configured — nothing to do
	}

	// Parse past the version string to find the options mapping
	payload := msg.Payload
	if len(payload) < 2 {
		return
	}

	// Skip version string: 2-byte length + string bytes
	versionLen := int(binary.BigEndian.Uint16(payload[0:2]))
	offset := 2 + versionLen
	if offset >= len(payload) {
		return // No options mapping after version string
	}

	// Parse options as key=value pairs separated by semicolons
	// The I2CP mapping format in GetDate options is a simple string mapping
	options := parseGetDateOptions(payload[offset:])
	if options == nil {
		return
	}

	username := options["i2cp.username"]
	password := options["i2cp.password"]

	if username == "" && password == "" {
		return // No credentials provided
	}

	state := s.getOrCreateConnectionState(conn)
	if s.authenticateConnection(state, username, password) {
		log.WithFields(logger.Fields{
			"remoteAddr": conn.RemoteAddr().String(),
			"username":   username,
		}).Info("i2cp_client_authenticated_via_getdate")
	}
}

// parseGetDateOptions parses the options portion of a GetDate payload.
// The format is an I2P Mapping: 2-byte total size, then pairs of
// length-prefixed strings (key=value encoded as individual strings).
// Returns nil if the data cannot be parsed.
func parseGetDateOptions(data []byte) map[string]string {
	if len(data) < 2 {
		return nil
	}

	// Read mapping size (2 bytes, big endian)
	mappingSize := int(binary.BigEndian.Uint16(data[0:2]))
	if mappingSize == 0 {
		return nil
	}

	data = data[2:]
	if len(data) < mappingSize {
		return nil
	}
	data = data[:mappingSize]

	options := make(map[string]string)

	// Parse key=value;key=value;... format
	// Each entry is: key=value followed by ;
	current := ""
	for i := 0; i < len(data); i++ {
		if data[i] == ';' {
			// Split on first '=' to get key=value
			key, value := splitKeyValue(current)
			if key != "" {
				options[key] = value
			}
			current = ""
		} else {
			current += string(data[i])
		}
	}
	// Handle last entry (may not end with ;)
	if current != "" {
		key, value := splitKeyValue(current)
		if key != "" {
			options[key] = value
		}
	}

	return options
}

// splitKeyValue splits a "key=value" string into its components.
func splitKeyValue(s string) (key, value string) {
	for i := 0; i < len(s); i++ {
		if s[i] == '=' {
			return s[:i], s[i+1:]
		}
	}
	return s, ""
}
