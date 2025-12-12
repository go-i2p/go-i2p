package i2pcontrol

import (
	"sync"
	"testing"
	"time"
)

// TestNewAuthManager verifies AuthManager initialization
func TestNewAuthManager(t *testing.T) {
	password := "testpass"
	am, err := NewAuthManager(password)
	if err != nil {
		t.Fatalf("NewAuthManager failed: %v", err)
	}

	if am == nil {
		t.Fatal("NewAuthManager returned nil")
	}

	if am.password != password {
		t.Errorf("password mismatch: got %q, want %q", am.password, password)
	}

	if am.tokens == nil {
		t.Error("tokens map not initialized")
	}

	if len(am.secret) != 32 {
		t.Errorf("secret length: got %d, want 32", len(am.secret))
	}

	if am.TokenCount() != 0 {
		t.Errorf("initial token count: got %d, want 0", am.TokenCount())
	}
}

// TestAuthenticateSuccess verifies successful authentication
func TestAuthenticateSuccess(t *testing.T) {
	password := "correct_password"
	am, err := NewAuthManager(password)
	if err != nil {
		t.Fatalf("NewAuthManager failed: %v", err)
	}

	expiration := 10 * time.Minute
	token, err := am.Authenticate(password, expiration)
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}

	if token == "" {
		t.Error("Authenticate returned empty token")
	}

	if am.TokenCount() != 1 {
		t.Errorf("token count after auth: got %d, want 1", am.TokenCount())
	}
}

// TestAuthenticateInvalidPassword verifies password validation
func TestAuthenticateInvalidPassword(t *testing.T) {
	password := "correct_password"
	am, err := NewAuthManager(password)
	if err != nil {
		t.Fatalf("NewAuthManager failed: %v", err)
	}

	expiration := 10 * time.Minute
	token, err := am.Authenticate("wrong_password", expiration)

	if err == nil {
		t.Error("Authenticate should fail with wrong password")
	}

	if token != "" {
		t.Errorf("Authenticate should return empty token on error, got %q", token)
	}

	if am.TokenCount() != 0 {
		t.Errorf("token count after failed auth: got %d, want 0", am.TokenCount())
	}
}

// TestAuthenticateEmptyPassword tests edge case with empty password
func TestAuthenticateEmptyPassword(t *testing.T) {
	// Test with empty configured password
	am, err := NewAuthManager("")
	if err != nil {
		t.Fatalf("NewAuthManager failed: %v", err)
	}

	// Should succeed with matching empty password
	token, err := am.Authenticate("", 10*time.Minute)
	if err != nil {
		t.Errorf("Authenticate with empty password failed: %v", err)
	}
	if token == "" {
		t.Error("Expected token for valid empty password")
	}

	// Should fail with non-empty password
	_, err = am.Authenticate("notEmpty", 10*time.Minute)
	if err == nil {
		t.Error("Authenticate should fail when password doesn't match")
	}
}

// TestValidateTokenValid verifies valid token validation
func TestValidateTokenValid(t *testing.T) {
	am, err := NewAuthManager("password")
	if err != nil {
		t.Fatalf("NewAuthManager failed: %v", err)
	}

	token, err := am.Authenticate("password", 10*time.Minute)
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}

	if !am.ValidateToken(token) {
		t.Error("ValidateToken should return true for valid token")
	}
}

// TestValidateTokenInvalid verifies invalid token rejection
func TestValidateTokenInvalid(t *testing.T) {
	am, err := NewAuthManager("password")
	if err != nil {
		t.Fatalf("NewAuthManager failed: %v", err)
	}

	// Test with completely invalid token
	if am.ValidateToken("invalid_token") {
		t.Error("ValidateToken should return false for invalid token")
	}

	// Test with empty token
	if am.ValidateToken("") {
		t.Error("ValidateToken should return false for empty token")
	}
}

// TestValidateTokenExpired verifies token expiration
func TestValidateTokenExpired(t *testing.T) {
	am, err := NewAuthManager("password")
	if err != nil {
		t.Fatalf("NewAuthManager failed: %v", err)
	}

	// Create token with very short expiration
	token, err := am.Authenticate("password", 50*time.Millisecond)
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}

	// Token should be valid immediately
	if !am.ValidateToken(token) {
		t.Error("ValidateToken should return true for fresh token")
	}

	// Wait for expiration
	time.Sleep(100 * time.Millisecond)

	// Token should now be invalid and removed
	if am.ValidateToken(token) {
		t.Error("ValidateToken should return false for expired token")
	}

	// Token should be removed from storage
	if am.TokenCount() != 0 {
		t.Errorf("expired token not removed: count = %d", am.TokenCount())
	}
}

// TestRevokeToken verifies token revocation
func TestRevokeToken(t *testing.T) {
	am, err := NewAuthManager("password")
	if err != nil {
		t.Fatalf("NewAuthManager failed: %v", err)
	}

	token, err := am.Authenticate("password", 10*time.Minute)
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}

	// Verify token is valid
	if !am.ValidateToken(token) {
		t.Error("Token should be valid before revocation")
	}

	// Revoke token
	am.RevokeToken(token)

	// Verify token is now invalid
	if am.ValidateToken(token) {
		t.Error("Token should be invalid after revocation")
	}

	// Verify token removed from storage
	if am.TokenCount() != 0 {
		t.Errorf("revoked token not removed: count = %d", am.TokenCount())
	}
}

// TestRevokeNonexistentToken verifies revoking non-existent token doesn't panic
func TestRevokeNonexistentToken(t *testing.T) {
	am, err := NewAuthManager("password")
	if err != nil {
		t.Fatalf("NewAuthManager failed: %v", err)
	}

	// Should not panic
	am.RevokeToken("nonexistent")
	am.RevokeToken("")
}

// TestCleanupExpiredTokens verifies expired token cleanup
func TestCleanupExpiredTokens(t *testing.T) {
	am, err := NewAuthManager("password")
	if err != nil {
		t.Fatalf("NewAuthManager failed: %v", err)
	}

	// Create multiple tokens with different expirations
	token1, _ := am.Authenticate("password", 50*time.Millisecond)
	token2, _ := am.Authenticate("password", 10*time.Minute)
	token3, _ := am.Authenticate("password", 50*time.Millisecond)

	if am.TokenCount() != 3 {
		t.Errorf("token count: got %d, want 3", am.TokenCount())
	}

	// Wait for short-lived tokens to expire
	time.Sleep(100 * time.Millisecond)

	// Cleanup expired tokens
	removed := am.CleanupExpiredTokens()

	if removed != 2 {
		t.Errorf("removed count: got %d, want 2", removed)
	}

	if am.TokenCount() != 1 {
		t.Errorf("remaining tokens: got %d, want 1", am.TokenCount())
	}

	// Verify the long-lived token still works
	if !am.ValidateToken(token2) {
		t.Error("long-lived token should still be valid")
	}

	// Verify expired tokens are invalid
	if am.ValidateToken(token1) {
		t.Error("expired token1 should be invalid")
	}
	if am.ValidateToken(token3) {
		t.Error("expired token3 should be invalid")
	}
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

	if removed != 0 {
		t.Errorf("removed count: got %d, want 0", removed)
	}

	if am.TokenCount() != 2 {
		t.Errorf("token count: got %d, want 2", am.TokenCount())
	}
}

// TestTokenUniqueness verifies each authentication generates a unique token
func TestTokenUniqueness(t *testing.T) {
	am, err := NewAuthManager("password")
	if err != nil {
		t.Fatalf("NewAuthManager failed: %v", err)
	}

	tokens := make(map[string]bool)
	numTokens := 10

	for i := 0; i < numTokens; i++ {
		token, err := am.Authenticate("password", 10*time.Minute)
		if err != nil {
			t.Fatalf("Authenticate failed: %v", err)
		}

		if tokens[token] {
			t.Errorf("duplicate token generated: %q", token)
		}
		tokens[token] = true

		// Small sleep to ensure different timestamps
		time.Sleep(time.Millisecond)
	}

	if len(tokens) != numTokens {
		t.Errorf("unique token count: got %d, want %d", len(tokens), numTokens)
	}
}

// TestConcurrentAuthenticate verifies thread-safe authentication
func TestConcurrentAuthenticate(t *testing.T) {
	am, err := NewAuthManager("password")
	if err != nil {
		t.Fatalf("NewAuthManager failed: %v", err)
	}

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
		t.Errorf("concurrent authenticate error: %v", err)
	}

	// Count tokens
	tokenCount := 0
	for range tokens {
		tokenCount++
	}

	if tokenCount != numGoroutines {
		t.Errorf("token count: got %d, want %d", tokenCount, numGoroutines)
	}
}

// TestConcurrentValidate verifies thread-safe validation
func TestConcurrentValidate(t *testing.T) {
	am, err := NewAuthManager("password")
	if err != nil {
		t.Fatalf("NewAuthManager failed: %v", err)
	}

	token, err := am.Authenticate("password", 10*time.Minute)
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}

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
		if !valid {
			t.Error("ValidateToken should return true for valid token")
		}
	}
}

// TestConcurrentCleanup verifies thread-safe cleanup
func TestConcurrentCleanup(t *testing.T) {
	am, err := NewAuthManager("password")
	if err != nil {
		t.Fatalf("NewAuthManager failed: %v", err)
	}

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
	if am.TokenCount() != 0 {
		t.Errorf("token count after cleanup: got %d, want 0", am.TokenCount())
	}
}

// TestConcurrentMixedOperations verifies thread-safety with mixed operations
func TestConcurrentMixedOperations(t *testing.T) {
	am, err := NewAuthManager("password")
	if err != nil {
		t.Fatalf("NewAuthManager failed: %v", err)
	}

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
	if count > numOps {
		t.Errorf("token count too high: got %d, max expected %d", count, numOps)
	}
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
