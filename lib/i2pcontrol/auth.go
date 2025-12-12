package i2pcontrol

import (
	"crypto/hmac"
	"github.com/go-i2p/crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"sync"
	"time"
)

// AuthManager handles token-based authentication for I2PControl RPC.
// It generates HMAC-SHA256 tokens for authenticated clients and validates
// tokens with expiration checking. Thread-safe for concurrent access.
//
// Authentication flow:
// 1. Client sends password via Authenticate method
// 2. Server validates password and generates token
// 3. Token stored with expiration timestamp
// 4. Client includes token in subsequent RPC requests
// 5. Server validates token before processing requests
type AuthManager struct {
	password string               // Configured password for authentication
	tokens   map[string]time.Time // Active tokens with expiration times
	mu       sync.RWMutex         // Protects tokens map
	secret   []byte               // HMAC secret key for token generation
}

// NewAuthManager creates a new authentication manager.
// The password is used to validate authentication requests.
// A random secret key is generated for HMAC token signing.
//
// Parameters:
//   - password: The authentication password clients must provide
//
// Returns:
//   - *AuthManager: Initialized auth manager
//   - error: If random secret generation fails
func NewAuthManager(password string) (*AuthManager, error) {
	// Generate a random 32-byte secret for HMAC signing
	// This ensures tokens are unique per server instance
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("failed to generate HMAC secret: %w", err)
	}

	return &AuthManager{
		password: password,
		tokens:   make(map[string]time.Time),
		secret:   secret,
	}, nil
}

// Authenticate validates a password and generates an access token.
// The token is a base64-encoded HMAC-SHA256 signature of the current
// timestamp, ensuring uniqueness and cryptographic security.
//
// Parameters:
//   - password: The password to authenticate
//   - expiration: How long the token should remain valid
//
// Returns:
//   - token: Base64-encoded authentication token
//   - error: If password is invalid or token generation fails
func (am *AuthManager) Authenticate(password string, expiration time.Duration) (string, error) {
	// Read password with lock to prevent race with ChangePassword
	am.mu.RLock()
	currentPassword := am.password
	am.mu.RUnlock()

	// Validate password using constant-time comparison to prevent timing attacks
	if !hmac.Equal([]byte(password), []byte(currentPassword)) {
		return "", fmt.Errorf("invalid password")
	}

	// Generate token from current timestamp
	// Using time ensures each token is unique even for rapid requests
	timestamp := time.Now().UnixNano()
	token := am.generateToken(timestamp)

	// Store token with expiration time
	am.mu.Lock()
	am.tokens[token] = time.Now().Add(expiration)
	am.mu.Unlock()

	log.WithField("at", "AuthManager.Authenticate").
		Debug("generated authentication token")

	return token, nil
}

// ValidateToken checks if a token is valid and not expired.
// Invalid or expired tokens are automatically removed from storage.
//
// Parameters:
//   - token: The token to validate
//
// Returns:
//   - bool: true if token is valid and not expired, false otherwise
func (am *AuthManager) ValidateToken(token string) bool {
	am.mu.RLock()
	expiration, exists := am.tokens[token]
	am.mu.RUnlock()

	if !exists {
		return false
	}

	// Check if token has expired
	if time.Now().After(expiration) {
		// Remove expired token
		am.mu.Lock()
		delete(am.tokens, token)
		am.mu.Unlock()

		log.WithField("at", "AuthManager.ValidateToken").
			Debug("token expired and removed")
		return false
	}

	return true
}

// RevokeToken removes a token from the valid token set.
// Used for explicit logout or token invalidation.
//
// Parameters:
//   - token: The token to revoke
func (am *AuthManager) RevokeToken(token string) {
	am.mu.Lock()
	delete(am.tokens, token)
	am.mu.Unlock()

	log.WithField("at", "AuthManager.RevokeToken").
		Debug("token revoked")
}

// CleanupExpiredTokens removes all expired tokens from storage.
// Should be called periodically (e.g., every 5 minutes) to prevent
// memory growth from expired tokens.
//
// Returns:
//   - int: Number of tokens removed
func (am *AuthManager) CleanupExpiredTokens() int {
	now := time.Now()
	removed := 0

	am.mu.Lock()
	for token, expiration := range am.tokens {
		if now.After(expiration) {
			delete(am.tokens, token)
			removed++
		}
	}
	am.mu.Unlock()

	if removed > 0 {
		log.WithFields(map[string]interface{}{
			"at":      "AuthManager.CleanupExpiredTokens",
			"removed": removed,
		}).Debug("cleaned up expired tokens")
	}

	return removed
}

// TokenCount returns the number of active tokens.
// Useful for monitoring and testing.
//
// Returns:
//   - int: Number of valid tokens currently stored
func (am *AuthManager) TokenCount() int {
	am.mu.RLock()
	defer am.mu.RUnlock()
	return len(am.tokens)
}

// ChangePassword updates the authentication password and revokes all existing tokens.
// This forces all clients to re-authenticate with the new password.
// Thread-safe for concurrent access.
//
// Parameters:
//   - newPassword: The new password to set
//
// Returns:
//   - int: Number of tokens revoked (clients that must re-authenticate)
func (am *AuthManager) ChangePassword(newPassword string) int {
	am.mu.Lock()
	defer am.mu.Unlock()

	// Update password
	am.password = newPassword

	// Count and revoke all existing tokens
	revokedCount := len(am.tokens)
	am.tokens = make(map[string]time.Time)

	log.WithFields(map[string]interface{}{
		"at":      "AuthManager.ChangePassword",
		"revoked": revokedCount,
	}).Info("password changed, all tokens revoked")

	return revokedCount
}

// generateToken creates a cryptographic token from a timestamp.
// Uses HMAC-SHA256 with the server's secret key to ensure tokens
// cannot be forged without knowing the secret.
//
// Parameters:
//   - timestamp: Unix nanosecond timestamp for uniqueness
//
// Returns:
//   - string: Base64-encoded HMAC signature
func (am *AuthManager) generateToken(timestamp int64) string {
	// Create HMAC hash of timestamp
	h := hmac.New(sha256.New, am.secret)
	h.Write([]byte(fmt.Sprintf("%d", timestamp)))
	signature := h.Sum(nil)

	// Encode as base64 for JSON transport
	return base64.StdEncoding.EncodeToString(signature)
}
