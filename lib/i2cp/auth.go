package i2cp

import (
	"crypto/subtle"
	"encoding/binary"
	"net"
	"strings"
	"unicode"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// sanitizeForLog removes control characters from user-controlled strings
// to prevent log injection attacks. Specifically, newlines and other
// control characters are replaced with spaces to prevent attackers from
// injecting fake log entries.
func sanitizeForLog(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
}

type connectionAuthenticator interface {
	AuthenticateConnection(conn net.Conn, username, password string) bool
}

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
// Returns an error if username or password is empty.
func NewPasswordAuthenticator(username, password string) (*PasswordAuthenticator, error) {
	if username == "" || password == "" {
		return nil, oops.Errorf("i2cp: NewPasswordAuthenticator requires non-empty username and password")
	}
	return &PasswordAuthenticator{
		username: username,
		password: password,
	}, nil
}

// Authenticate checks if the provided credentials match the configured pair.
// Uses constant-time comparison to prevent timing side-channel attacks.
func (a *PasswordAuthenticator) Authenticate(username, password string) bool {
	usernameMatch := subtle.ConstantTimeCompare([]byte(a.username), []byte(username)) == 1
	passwordMatch := subtle.ConstantTimeCompare([]byte(a.password), []byte(password)) == 1

	if usernameMatch && passwordMatch {
		log.WithField("username", sanitizeForLog(username)).Debug("i2cp_authentication_success")
		return true
	}

	log.WithFields(logger.Fields{
		"username": sanitizeForLog(username),
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
	return state.authenticated.Load()
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

	if connAuth, ok := auth.(connectionAuthenticator); ok {
		if connAuth.AuthenticateConnection(state.conn, username, password) {
			state.authenticated.Store(true)
			return true
		}
		return false
	}

	if auth.Authenticate(username, password) {
		state.authenticated.Store(true)
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
	// Wrap with rate-limiting unless the caller already supplied a
	// RateLimitedAuthenticator (avoids double-wrapping from tests or
	// callers that need to share lockout state). A nil authenticator
	// disables auth entirely.
	switch auth.(type) {
	case nil, *RateLimitedAuthenticator:
		s.authenticator = auth
	default:
		s.authenticator = NewRateLimitedAuthenticator(auth)
	}

	if auth != nil {
		log.WithFields(logger.Fields{"at": "SetAuthenticator"}).Info("i2cp_authentication_enabled")
	} else {
		log.WithFields(logger.Fields{"at": "SetAuthenticator"}).Info("i2cp_authentication_disabled")
	}
}

// enforceBindPolicy refuses to start the server when a non-loopback TCP bind
// has no authenticator installed. Loopback TCP binds retain the legacy
// behavior of permitting unauthenticated connections, matching the
// backward-compatibility constraint documented for other local control
// isPermittedUnauthenticatedBindHost returns nil if host is safe for an
// unauthenticated TCP listener, or a descriptive error otherwise.
// Loopback IPs and the literal string "localhost" are permitted; wildcard,
// non-loopback IPs, and unresolved hostnames are rejected.
func isPermittedUnauthenticatedBindHost(host, listenAddr string) error {
	if host == "" {
		return oops.Errorf("i2cp: refusing to start unauthenticated TCP listener on wildcard address %q; configure i2cp.username/password or bind to loopback", listenAddr)
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() {
			return nil
		}
		return oops.Errorf("i2cp: refusing to start unauthenticated TCP listener on non-loopback address %q; configure i2cp.username/password", listenAddr)
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	// Reject any non-literal-IP hostname that is not "localhost". Resolving
	// hostnames via DNS introduces a TOCTOU window: the address checked here
	// could differ from the address actually bound by net.Listen moments
	// later. Operators must supply a literal IP or a Unix socket.
	return oops.Errorf("i2cp: refusing to start unauthenticated TCP listener on hostname %q; use a literal loopback IP (127.0.0.1 / ::1) or configure i2cp.username/password", listenAddr)
}

// interfaces. Unix sockets are accepted because host-level access control is
// enforced through the socket's file-system permissions (see the
// corresponding chmod in Start()).
func (s *Server) enforceBindPolicy() error {
	if s.isAuthenticationRequired() {
		return s.enforceAuthenticatedBindPolicyWithWarning()
	}
	return s.enforceUnauthenticatedBindPolicy()
}

func (s *Server) enforceAuthenticatedBindPolicyWithWarning() error {
	if err := s.enforceAuthenticatedBindPolicy(); err != nil {
		return err
	}
	s.warnIfCleartextAuthOnNetwork()
	return nil
}

func (s *Server) enforceUnauthenticatedBindPolicy() error {
	if s.config.Network != "tcp" {
		return nil
	}
	host, _, err := net.SplitHostPort(s.config.ListenAddr)
	if err != nil {
		// Malformed address — let net.Listen produce the canonical error.
		return nil
	}
	return isPermittedUnauthenticatedBindHost(host, s.config.ListenAddr)
}

// enforceAuthenticatedBindPolicy rejects non-loopback cleartext TCP auth binds
// unless the explicit unsafe acknowledgment flag is set.
func (s *Server) enforceAuthenticatedBindPolicy() error {
	if s.config.Network != "tcp" {
		return nil
	}
	host, _, err := net.SplitHostPort(s.config.ListenAddr)
	if err != nil {
		return nil
	}

	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() {
			return nil
		}
	} else if strings.EqualFold(host, "localhost") {
		return nil
	}

	if s.config.AllowInsecureCleartextAuth {
		return nil
	}

	return oops.Errorf(
		"i2cp: refusing authenticated cleartext TCP listener on %q; set i2cp.allow_insecure_cleartext_auth=true only when protected by trusted TLS/front-proxy",
		s.config.ListenAddr,
	)
}

// warnIfCleartextAuthOnNetwork emits a warning when the server is configured
// to bind to a non-loopback TCP address with authentication enabled. I2CP
// sends credentials in cleartext as part of the GetDate message, which exposes
// them to network eavesdroppers on untrusted networks.
func (s *Server) warnIfCleartextAuthOnNetwork() {
	if s.config.Network != "tcp" {
		return
	}
	host, _, err := net.SplitHostPort(s.config.ListenAddr)
	if err != nil {
		return
	}
	if host == "" {
		// Wildcard bind with auth enabled
		log.WithFields(logger.Fields{
			"at":      "enforceBindPolicy",
			"address": s.config.ListenAddr,
		}).Warn("i2cp_security_warning: I2CP authentication credentials will transit in CLEARTEXT over the network. Wildcard bind with password authentication is NOT SECURE on untrusted networks. Use localhost bind or deploy TLS reverse proxy.")
		return
	}
	ip := net.ParseIP(host)
	if ip != nil && !ip.IsLoopback() {
		// Non-loopback IP with auth enabled
		log.WithFields(logger.Fields{
			"at":      "enforceBindPolicy",
			"address": s.config.ListenAddr,
		}).Warn("i2cp_security_warning: I2CP authentication credentials will transit in CLEARTEXT over the network. Non-loopback bind with password authentication is NOT SECURE on untrusted networks. Use localhost bind or deploy TLS reverse proxy.")
	}
}

// requiresAuthentication returns true if the given message type requires
// the connection to be authenticated before processing.
// The following message types are allowed without authentication:
//   - GetDate (type 32): Needed for handshake; also carries auth credentials
//   - GetBandwidthLimits (type 8): Read-only informational query
//   - Disconnect (type 30): Graceful disconnection always allowed
//
// All other message types (CreateSession, SendMessage, etc.) require auth.
func (s *Server) requiresAuthentication(msgType byte) bool {
	if !s.isAuthenticationRequired() {
		return false // No authenticator configured — nothing requires auth
	}

	switch msgType {
	case MessageTypeGetDate,
		MessageTypeGetBandwidthLimits,
		MessageTypeDisconnect:
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

	username, password := extractGetDateCredentials(msg.Payload)
	if username == "" && password == "" {
		return // No credentials provided
	}

	s.authenticateConnectionIfValid(conn, username, password)
}

// extractGetDateCredentials parses the GetDate payload and extracts credentials.
func extractGetDateCredentials(payload []byte) (username, password string) {
	optionsData := parseGetDatePayload(payload)
	if optionsData == nil {
		return "", ""
	}

	options := parseGetDateOptions(optionsData)
	if options == nil {
		return "", ""
	}

	return options["i2cp.username"], options["i2cp.password"]
}

// parseGetDatePayload parses past the version string to find the options mapping.
func parseGetDatePayload(payload []byte) []byte {
	if len(payload) < 2 {
		return nil
	}

	// Skip version string: 2-byte length + string bytes
	versionLen := int(binary.BigEndian.Uint16(payload[0:2]))
	offset := 2 + versionLen
	if offset >= len(payload) {
		return nil // No options mapping after version string
	}

	return payload[offset:]
}

// authenticateConnectionIfValid attempts to authenticate the connection with the given credentials.
func (s *Server) authenticateConnectionIfValid(conn net.Conn, username, password string) {
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
	mappingData := extractMappingData(data)
	if mappingData == nil {
		return nil
	}
	return parseOptionEntries(mappingData)
}

// extractMappingData reads the mapping size header and returns the mapping bytes.
func extractMappingData(data []byte) []byte {
	if len(data) < 2 {
		return nil
	}
	mappingSize := int(binary.BigEndian.Uint16(data[0:2]))
	if mappingSize == 0 {
		return nil
	}
	data = data[2:]
	if len(data) < mappingSize {
		return nil
	}
	return data[:mappingSize]
}

// parseOptionEntries parses key=value;key=value;... format into a map.
func parseOptionEntries(data []byte) map[string]string {
	options := make(map[string]string)
	entries := strings.Split(string(data), ";")
	for _, entry := range entries {
		if entry == "" {
			continue
		}
		key, value := splitKeyValue(entry)
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
