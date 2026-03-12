package i2pcontrol

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createAuthManagerWithToken creates an AuthManager, authenticates with the
// given password and token expiry, and returns both. Fails the test on error.
func createAuthManagerWithToken(t *testing.T, password string, expiry time.Duration) (*AuthManager, string) {
	t.Helper()
	am, err := NewAuthManager(password)
	require.NoError(t, err)
	token, err := am.Authenticate(password, expiry)
	require.NoError(t, err)
	return am, token
}

// TestNewAuthManager verifies AuthManager initialization
func TestNewAuthManager(t *testing.T) {
	password := "testpass"
	am, err := NewAuthManager(password)
	require.NoError(t, err)
	require.NotNil(t, am)

	assert.Equal(t, password, am.password)
	assert.NotNil(t, am.tokens, "tokens map not initialized")
	assert.Equal(t, 32, len(am.secret))
	assert.Equal(t, 0, am.TokenCount())
}

// TestAuthenticateSuccess verifies successful authentication
func TestAuthenticateSuccess(t *testing.T) {
	password := "correct_password"
	am, err := NewAuthManager(password)
	require.NoError(t, err)

	expiration := 10 * time.Minute
	token, err := am.Authenticate(password, expiration)
	require.NoError(t, err)

	assert.NotEmpty(t, token)
	assert.Equal(t, 1, am.TokenCount())
}

// TestAuthenticateInvalidPassword verifies password validation
func TestAuthenticateInvalidPassword(t *testing.T) {
	password := "correct_password"
	am, err := NewAuthManager(password)
	require.NoError(t, err)

	expiration := 10 * time.Minute
	token, err := am.Authenticate("wrong_password", expiration)

	assert.Error(t, err, "Authenticate should fail with wrong password")
	assert.Empty(t, token)
	assert.Equal(t, 0, am.TokenCount())
}

// TestAuthenticateEmptyPassword tests edge case with empty password
func TestAuthenticateEmptyPassword(t *testing.T) {
	// Test with empty configured password
	am, err := NewAuthManager("")
	require.NoError(t, err)

	// Should succeed with matching empty password
	token, err := am.Authenticate("", 10*time.Minute)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	// Should fail with non-empty password
	_, err = am.Authenticate("notEmpty", 10*time.Minute)
	assert.Error(t, err, "Authenticate should fail when password doesn't match")
}

// TestValidateTokenValid verifies valid token validation
func TestValidateTokenValid(t *testing.T) {
	am, err := NewAuthManager("password")
	require.NoError(t, err)

	token, err := am.Authenticate("password", 10*time.Minute)
	require.NoError(t, err)

	assert.True(t, am.ValidateToken(token), "ValidateToken should return true for valid token")
}

// TestValidateTokenInvalid verifies invalid token rejection
func TestValidateTokenInvalid(t *testing.T) {
	am, err := NewAuthManager("password")
	require.NoError(t, err)

	assert.False(t, am.ValidateToken("invalid_token"), "ValidateToken should return false for invalid token")
	assert.False(t, am.ValidateToken(""), "ValidateToken should return false for empty token")
}

// TestValidateTokenExpired verifies token expiration
func TestValidateTokenExpired(t *testing.T) {
	am, token := createAuthManagerWithToken(t, "password", 50*time.Millisecond)

	// Token should be valid immediately
	assert.True(t, am.ValidateToken(token), "ValidateToken should return true for fresh token")

	// Wait for expiration
	time.Sleep(100 * time.Millisecond)

	// Token should now be invalid and removed
	assert.False(t, am.ValidateToken(token), "ValidateToken should return false for expired token")

	// Token should be removed from storage
	assert.Equal(t, 0, am.TokenCount(), "expired token not removed")
}

// TestRevokeToken verifies token revocation
func TestRevokeToken(t *testing.T) {
	am, err := NewAuthManager("password")
	require.NoError(t, err)

	token, err := am.Authenticate("password", 10*time.Minute)
	require.NoError(t, err)

	assert.True(t, am.ValidateToken(token), "Token should be valid before revocation")

	am.RevokeToken(token)

	assert.False(t, am.ValidateToken(token), "Token should be invalid after revocation")
	assert.Equal(t, 0, am.TokenCount(), "revoked token not removed")
}

// TestRevokeNonexistentToken verifies revoking non-existent token doesn't panic
func TestRevokeNonexistentToken(t *testing.T) {
	am, err := NewAuthManager("password")
	require.NoError(t, err)

	// Should not panic
	am.RevokeToken("nonexistent")
	am.RevokeToken("")
}

// TestCleanupExpiredTokens verifies expired token cleanup
func TestCleanupExpiredTokens(t *testing.T) {
	am, err := NewAuthManager("password")
	require.NoError(t, err)

	// Create multiple tokens with different expirations
	token1, _ := am.Authenticate("password", 50*time.Millisecond)
	token2, _ := am.Authenticate("password", 10*time.Minute)
	token3, _ := am.Authenticate("password", 50*time.Millisecond)

	assert.Equal(t, 3, am.TokenCount())

	// Wait for short-lived tokens to expire
	time.Sleep(100 * time.Millisecond)

	// Cleanup expired tokens
	removed := am.CleanupExpiredTokens()

	assert.Equal(t, 2, removed)
	assert.Equal(t, 1, am.TokenCount())

	// Verify the long-lived token still works
	assert.True(t, am.ValidateToken(token2), "long-lived token should still be valid")

	// Verify expired tokens are invalid
	assert.False(t, am.ValidateToken(token1), "expired token1 should be invalid")
	assert.False(t, am.ValidateToken(token3), "expired token3 should be invalid")
}

// TestCleanupNoExpiredTokens verifies cleanup with no expired tokens
func TestCleanupNoExpiredTokens(t *testing.T) {
	am, err := NewAuthManager("password")
	if err != nil {
		t.Fatalf("NewAuthManager failed: %v", err)
	}

	// Create tokens that won't expire during test
	am.Authenticate("password", 10*time.Minute)
	am.Authenticate("password", 10*time.Minute)

	removed := am.CleanupExpiredTokens()

	assert.Equal(t, 0, removed)
	assert.Equal(t, 2, am.TokenCount())
}

// TestTokenUniqueness verifies each authentication generates a unique token
func TestTokenUniqueness(t *testing.T) {
	am, err := NewAuthManager("password")
	require.NoError(t, err)

	tokens := make(map[string]bool)
	numTokens := 10

	for i := 0; i < numTokens; i++ {
		token, err := am.Authenticate("password", 10*time.Minute)
		require.NoError(t, err)

		assert.False(t, tokens[token], "duplicate token generated: %q", token)
		tokens[token] = true

		time.Sleep(time.Millisecond)
	}

	assert.Equal(t, numTokens, len(tokens))
}

// TestConcurrentAuthenticate verifies thread-safe authentication
func TestConcurrentAuthenticate(t *testing.T) {
	am, err := NewAuthManager("password")
	require.NoError(t, err)

	numGoroutines := 50
	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines)
	tokens := make(chan string, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			token, err := am.Authenticate("password", 10*time.Minute)
			if err != nil {
				errors <- err
				return
			}
			tokens <- token
		}()
	}

	wg.Wait()
	close(errors)
	close(tokens)

	// Check for errors
	for err := range errors {
		assert.NoError(t, err, "concurrent authenticate error")
	}

	// Count tokens
	tokenCount := 0
	for range tokens {
		tokenCount++
	}

	assert.Equal(t, numGoroutines, tokenCount)
}

// TestConcurrentValidate verifies thread-safe validation
func TestConcurrentValidate(t *testing.T) {
	am, err := NewAuthManager("password")
	require.NoError(t, err)

	token, err := am.Authenticate("password", 10*time.Minute)
	require.NoError(t, err)

	numGoroutines := 100
	var wg sync.WaitGroup
	results := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- am.ValidateToken(token)
		}()
	}

	wg.Wait()
	close(results)

	// All validations should succeed
	for valid := range results {
		assert.True(t, valid, "ValidateToken should return true for valid token")
	}
}

// TestConcurrentCleanup verifies thread-safe cleanup
func TestConcurrentCleanup(t *testing.T) {
	am, err := NewAuthManager("password")
	require.NoError(t, err)

	// Create some expired tokens
	for i := 0; i < 10; i++ {
		am.Authenticate("password", 10*time.Millisecond)
	}

	time.Sleep(50 * time.Millisecond)

	// Run cleanup concurrently
	numGoroutines := 10
	var wg sync.WaitGroup

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			am.CleanupExpiredTokens()
		}()
	}

	wg.Wait()

	// All tokens should be cleaned up
	assert.Equal(t, 0, am.TokenCount(), "token count after cleanup")
}

// TestConcurrentMixedOperations verifies thread-safety with mixed operations
func TestConcurrentMixedOperations(t *testing.T) {
	am, err := NewAuthManager("password")
	require.NoError(t, err)

	var wg sync.WaitGroup
	numOps := 20

	// Concurrent authenticates
	for i := 0; i < numOps; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			token, err := am.Authenticate("password", 10*time.Minute)
			if err == nil {
				am.ValidateToken(token)
			}
		}()
	}

	// Concurrent validations
	for i := 0; i < numOps; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			am.ValidateToken("fake_token")
		}()
	}

	// Concurrent cleanups
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			am.CleanupExpiredTokens()
		}()
	}

	// Wait for all operations
	wg.Wait()

	// Should complete without panics or deadlocks
	// Token count should be reasonable (at most numOps authenticates)
	count := am.TokenCount()
	assert.LessOrEqual(t, count, numOps)
}

// BenchmarkAuthenticate measures authentication performance
func BenchmarkAuthenticate(b *testing.B) {
	am, err := NewAuthManager("password")
	if err != nil {
		b.Fatalf("NewAuthManager failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := am.Authenticate("password", 10*time.Minute)
		if err != nil {
			b.Fatalf("Authenticate failed: %v", err)
		}
	}
}

// BenchmarkValidateToken measures validation performance
func BenchmarkValidateToken(b *testing.B) {
	am, err := NewAuthManager("password")
	if err != nil {
		b.Fatalf("NewAuthManager failed: %v", err)
	}

	token, err := am.Authenticate("password", 10*time.Minute)
	if err != nil {
		b.Fatalf("Authenticate failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		am.ValidateToken(token)
	}
}

// BenchmarkCleanupExpiredTokens measures cleanup performance
func BenchmarkCleanupExpiredTokens(b *testing.B) {
	am, err := NewAuthManager("password")
	if err != nil {
		b.Fatalf("NewAuthManager failed: %v", err)
	}

	// Create 100 tokens
	for i := 0; i < 100; i++ {
		am.Authenticate("password", 10*time.Minute)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		am.CleanupExpiredTokens()
	}
}

// TestChangePassword verifies password change functionality
func TestChangePassword(t *testing.T) {
	am, err := NewAuthManager("oldpass")
	require.NoError(t, err)

	token1, err := am.Authenticate("oldpass", 10*time.Minute)
	require.NoError(t, err)

	token2, err := am.Authenticate("oldpass", 10*time.Minute)
	require.NoError(t, err)

	assert.True(t, am.ValidateToken(token1), "token1 should be valid before password change")
	assert.True(t, am.ValidateToken(token2), "token2 should be valid before password change")

	revokedCount := am.ChangePassword("newpass")
	assert.Equal(t, 2, revokedCount)

	assert.False(t, am.ValidateToken(token1), "token1 should be invalid after password change")
	assert.False(t, am.ValidateToken(token2), "token2 should be invalid after password change")

	_, err = am.Authenticate("oldpass", 10*time.Minute)
	assert.Error(t, err, "old password should not work after change")

	newToken, err := am.Authenticate("newpass", 10*time.Minute)
	require.NoError(t, err)
	assert.True(t, am.ValidateToken(newToken), "new token should be valid")
}

// TestChangePasswordNoTokens verifies password change with no active tokens
func TestChangePasswordNoTokens(t *testing.T) {
	am, err := NewAuthManager("oldpass")
	require.NoError(t, err)

	revokedCount := am.ChangePassword("newpass")
	assert.Equal(t, 0, revokedCount)

	token, err := am.Authenticate("newpass", 10*time.Minute)
	require.NoError(t, err)
	assert.True(t, am.ValidateToken(token), "new token should be valid")
}

// TestChangePasswordConcurrent verifies thread-safe password changes
func TestChangePasswordConcurrent(t *testing.T) {
	am, err := NewAuthManager("pass")
	require.NoError(t, err)

	// Create multiple tokens
	for i := 0; i < 10; i++ {
		_, err := am.Authenticate("pass", 10*time.Minute)
		require.NoError(t, err)
	}

	var wg sync.WaitGroup
	errors := make(chan error, 3)

	// Concurrent password change
	wg.Add(1)
	go func() {
		defer wg.Done()
		am.ChangePassword("newpass1")
	}()

	// Concurrent authentication attempts
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 5; i++ {
			_, err := am.Authenticate("pass", 10*time.Minute)
			if err != nil {
				// Expected to fail sometimes during password change
				continue
			}
		}
	}()

	// Concurrent token validation
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 5; i++ {
			// Create a token to validate
			token, err := am.Authenticate("pass", 10*time.Minute)
			if err != nil {
				continue
			}
			am.ValidateToken(token)
		}
	}()

	wg.Wait()
	close(errors)

	// Check for unexpected errors
	for err := range errors {
		assert.NoError(t, err, "unexpected error")
	}
}

// TestChangePasswordMultipleTimes verifies multiple password changes
func TestChangePasswordMultipleTimes(t *testing.T) {
	am, err := NewAuthManager("pass1")
	require.NoError(t, err)

	passwords := []string{"pass2", "pass3", "pass4", "pass5"}

	for _, newPass := range passwords {
		oldToken, err := am.Authenticate(am.password, 10*time.Minute)
		require.NoError(t, err)

		am.ChangePassword(newPass)

		assert.False(t, am.ValidateToken(oldToken), "token should be invalid after changing to %s", newPass)

		newToken, err := am.Authenticate(newPass, 10*time.Minute)
		require.NoError(t, err)
		assert.True(t, am.ValidateToken(newToken), "new token should be valid for %s", newPass)
	}
}

// BenchmarkChangePassword measures password change performance
func BenchmarkChangePassword(b *testing.B) {
	am, err := NewAuthManager("password")
	if err != nil {
		b.Fatalf("NewAuthManager failed: %v", err)
	}

	// Create some tokens
	for i := 0; i < 10; i++ {
		am.Authenticate("password", 10*time.Minute)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		am.ChangePassword("newpassword")
		// Restore original password for next iteration
		am.ChangePassword("password")
	}
}
