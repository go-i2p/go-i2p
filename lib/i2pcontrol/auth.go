package i2pcontrol

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"github.com/go-i2p/crypto/hmac"
	"github.com/go-i2p/crypto/rand"
	"github.com/samber/oops"
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
//
// Rate limiting: After maxFailedAttempts consecutive failures, authentication
// is locked out for failedAttemptLockout duration to prevent brute-force attacks.
type AuthManager struct {
	password string                 // Configured password for authentication
	tokens   map[[32]byte]time.Time // Active tokens with expiration times; key = SHA-256(token)
	mu       sync.RWMutex           // Protects tokens map
	secret   []byte                 // HMAC secret key for token generation
	randRead func([]byte) (int, error)

	// Rate limiting fields
	failedAttempts    int       // Consecutive failed authentication attempts
	lastFailedAttempt time.Time // Time of the last failed attempt
	lockoutUntil      time.Time // Time until which auth is locked out
	rateLimitMu       sync.Mutex
}

const (
	// maxFailedAttempts is the number of consecutive failed auth attempts
	// before a lockout is applied.
	maxFailedAttempts = 10
	// failedAttemptLockout is how long authentication is locked after
	// maxFailedAttempts consecutive failures.
	failedAttemptLockout = 5 * time.Minute
)

var errTokenEntropyFailure = errors.New("failed to read entropy for token generation")

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
		return nil, oops.Wrapf(err, "failed to generate HMAC secret")
	}

	return &AuthManager{
		password: password,
		tokens:   make(map[[32]byte]time.Time),
		secret:   secret,
		randRead: rand.Read,
	}, nil
}

// Authenticate validates a password and generates an access token.
// The token is a base64-encoded HMAC-SHA256 signature of the current
// timestamp, ensuring uniqueness and cryptographic security.
//
// Rate limiting: After maxFailedAttempts consecutive failures, authentication
// is locked out for failedAttemptLockout duration. Successful authentication
// resets the failure counter.
//
// Parameters:
//   - password: The password to authenticate
//   - expiration: How long the token should remain valid
//
// Returns:
//   - token: Base64-encoded authentication token
//   - error: If password is invalid, token generation fails, or rate limited
func (am *AuthManager) Authenticate(password string, expiration time.Duration) (string, error) {
	// Hold rateLimitMu across the lockout check AND password validation to
	// prevent a TOCTOU race where a concurrent goroutine could reset the
	// lockout between the check and the password comparison, allowing a
	// brute-force attempt to slip through.
	am.rateLimitMu.Lock()
	if !am.lockoutUntil.IsZero() && time.Now().Before(am.lockoutUntil) {
		remaining := time.Until(am.lockoutUntil).Round(time.Second)
		am.rateLimitMu.Unlock()
		log.WithFields(map[string]interface{}{
			"at":        "AuthManager.Authenticate",
			"remaining": remaining.String(),
		}).Warn("authentication rate limited")
		return "", oops.Errorf("too many failed attempts, locked out for %s", remaining)
	}

	// Read password with lock to prevent race with ChangePassword.
	// rateLimitMu is still held, ensuring the lockout state cannot change
	// between the check above and the password validation below.
	am.mu.RLock()
	currentPassword := am.password
	am.mu.RUnlock()

	// Validate password using constant-time comparison to prevent timing attacks
	if !hmac.Equal([]byte(password), []byte(currentPassword)) {
		// Track failed attempt for rate limiting (rateLimitMu already held)
		am.failedAttempts++
		am.lastFailedAttempt = time.Now()
		if am.failedAttempts >= maxFailedAttempts {
			am.lockoutUntil = time.Now().Add(failedAttemptLockout)
			log.WithFields(map[string]interface{}{
				"at":       "AuthManager.Authenticate",
				"attempts": am.failedAttempts,
				"lockout":  failedAttemptLockout.String(),
			}).Warn("authentication lockout triggered")
		}
		am.rateLimitMu.Unlock()
		return "", oops.Errorf("invalid password")
	}

	// Successful authentication — reset failure counter (rateLimitMu already held)
	am.failedAttempts = 0
	am.lockoutUntil = time.Time{}
	am.rateLimitMu.Unlock()

	// LOW-2 FIX: Use only a crypto/rand nonce for token uniqueness; the
	// timestamp was redundant (the nonce already ensures uniqueness) and
	// using UnixNano() as HMAC input adds no security benefit while
	// implying a relationship to wall time that could be abused.
	token, err := am.generateToken()
	if err != nil {
		return "", oops.Wrapf(err, "failed to generate authentication token")
	}

	// Store token with expiration time; key = SHA-256(token) for hardened
	// token comparison (MEDIUM-4 audit fix: prevents timing oracle on the
	// raw token string comparison in map lookups).
	am.mu.Lock()
	am.tokens[am.tokenKey(token)] = time.Now().Add(expiration)
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
	key := am.tokenKey(token)
	am.mu.RLock()
	expiration, exists := am.tokens[key]
	am.mu.RUnlock()

	if !exists {
		return false
	}

	// Check if token has expired
	if time.Now().After(expiration) {
		// Remove expired token
		am.mu.Lock()
		delete(am.tokens, key)
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
	delete(am.tokens, am.tokenKey(token))
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
	am.tokens = make(map[[32]byte]time.Time)

	log.WithFields(map[string]interface{}{
		"at":      "AuthManager.ChangePassword",
		"revoked": revokedCount,
	}).Info("password changed, all tokens revoked")

	return revokedCount
}

// tokenKey computes a SHA-256 hash of the raw token string.
// Tokens are stored and compared by hash rather than by the raw string to
// harden against timing-based side channels on the raw-string equality
// check inside Go's map lookup (MEDIUM-4 audit fix).
func (am *AuthManager) tokenKey(token string) [32]byte {
	return sha256.Sum256([]byte(token))
}

// generateToken creates a cryptographic token from a random nonce.
// Uses HMAC-SHA256 with the server's secret key to ensure tokens
// cannot be forged without knowing the secret.  A 32-byte random nonce
// provides uniqueness — no timestamp input is needed or used (LOW-2 audit fix).
//
// Returns:
//   - string: Base64-encoded HMAC signature
func (am *AuthManager) generateToken() (string, error) {
	// 32-byte nonce provides 256 bits of entropy — collision-resistant and
	// unpredictable, with no dependency on wall-clock time.
	nonce := make([]byte, 32)
	if _, err := am.randRead(nonce); err != nil {
		return "", oops.Wrapf(errTokenEntropyFailure, "crypto/rand.Read failed: %v", err)
	}

	h := hmac.New(sha256.New, am.secret)
	h.Write(nonce)
	signature := h.Sum(nil)

	// Encode as base64 for JSON transport
	return base64.StdEncoding.EncodeToString(signature), nil
}
