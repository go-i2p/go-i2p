package keys

import (
	"strings"
	"sync"
	"testing"

	"github.com/go-i2p/crypto/ed25519"
	"github.com/go-i2p/crypto/types"
)

// TestKeyID_ConsistencyOnError verifies that KeyID returns the same fallback value
// across multiple calls when privateKey.Public() fails. This test addresses
// AUDIT.md Issue #10: RouterInfoKeystore KeyID Race Condition on Error.
func TestKeyID_ConsistencyOnError(t *testing.T) {
	// Create a keystore with a nil private key to trigger the error path
	ks := &RouterInfoKeystore{
		privateKey: nil,
		name:       "", // Empty name to trigger KeyID generation from private key
	}

	// Call KeyID multiple times and verify we get the same value
	const iterations = 10
	keyIDs := make([]string, iterations)

	for i := 0; i < iterations; i++ {
		keyIDs[i] = ks.KeyID()
	}

	// All KeyIDs should be identical
	firstKeyID := keyIDs[0]
	for i := 1; i < iterations; i++ {
		if keyIDs[i] != firstKeyID {
			t.Errorf("KeyID returned inconsistent values: first=%s, iteration[%d]=%s",
				firstKeyID, i, keyIDs[i])
		}
	}

	// Verify it's a fallback ID (either "fallback-key" or "fallback-<hex>")
	if !strings.HasPrefix(firstKeyID, "fallback-") {
		t.Errorf("Expected fallback ID to start with 'fallback-', got: %s", firstKeyID)
	}

	t.Logf("Consistent fallback KeyID: %s", firstKeyID)
}

// TestKeyID_ConcurrentAccess verifies that KeyID is safe to call from multiple
// goroutines simultaneously and returns consistent values.
func TestKeyID_ConcurrentAccess(t *testing.T) {
	// Create a keystore with a nil private key to trigger the error path
	ks := &RouterInfoKeystore{
		privateKey: nil,
		name:       "",
	}

	const goroutines = 50
	const callsPerGoroutine = 20
	var wg sync.WaitGroup

	// Channel to collect all KeyIDs
	results := make(chan string, goroutines*callsPerGoroutine)

	// Launch multiple goroutines calling KeyID concurrently
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < callsPerGoroutine; j++ {
				results <- ks.KeyID()
			}
		}()
	}

	// Wait for all goroutines to complete
	wg.Wait()
	close(results)

	// Collect all results and verify they're all identical
	keyIDMap := make(map[string]int)
	for keyID := range results {
		keyIDMap[keyID]++
	}

	// Should only have one unique KeyID
	if len(keyIDMap) != 1 {
		t.Errorf("KeyID returned %d different values under concurrent access, expected 1", len(keyIDMap))
		for keyID, count := range keyIDMap {
			t.Logf("  KeyID: %s (count: %d)", keyID, count)
		}
	}

	// Get the single KeyID
	var singleKeyID string
	for keyID := range keyIDMap {
		singleKeyID = keyID
		break
	}

	// Verify it's a fallback ID
	if !strings.HasPrefix(singleKeyID, "fallback-") {
		t.Errorf("Expected fallback ID to start with 'fallback-', got: %s", singleKeyID)
	}

	t.Logf("All %d calls returned consistent KeyID: %s",
		goroutines*callsPerGoroutine, singleKeyID)
}

// TestKeyID_NormalOperationNotCached verifies that KeyID doesn't use cached
// value when privateKey.Public() succeeds. The cachedKeyID is only used
// when falling back due to errors.
func TestKeyID_NormalOperationNotCached(t *testing.T) {
	// Create a keystore with a valid private key
	privateKey, err := ed25519.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	ks := &RouterInfoKeystore{
		privateKey:  privateKey.(types.PrivateKey),
		name:        "",
		cachedKeyID: "", // Cache should not be used for valid keys
	}

	keyID := ks.KeyID()

	// Should not be a fallback ID
	if strings.HasPrefix(keyID, "fallback-") {
		t.Errorf("Normal operation should not return fallback ID, got: %s", keyID)
	}

	// Verify it's a valid hex string
	if len(keyID) == 0 {
		t.Error("KeyID should not be empty for valid private key")
	}

	// Call again to verify consistency (should get same value from public key)
	keyID2 := ks.KeyID()
	if keyID != keyID2 {
		t.Errorf("KeyID changed between calls with valid key: %s -> %s", keyID, keyID2)
	}

	t.Logf("Valid KeyID generated: %s", keyID)
}

// TestKeyID_NameTakesPrecedence verifies that when a name is set, it's always
// returned regardless of private key or cached values
func TestKeyID_NameTakesPrecedence(t *testing.T) {
	testCases := []struct {
		name        string
		expectedID  string
		privateKey  types.PrivateKey
		cachedKeyID string
	}{
		{
			name:        "test-router-1",
			expectedID:  "test-router-1",
			privateKey:  nil,
			cachedKeyID: "fallback-12345678",
		},
		{
			name:        "test-router-2",
			expectedID:  "test-router-2",
			privateKey:  nil,
			cachedKeyID: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ks := &RouterInfoKeystore{
				privateKey:  tc.privateKey,
				name:        tc.name,
				cachedKeyID: tc.cachedKeyID,
			}

			keyID := ks.KeyID()
			if keyID != tc.expectedID {
				t.Errorf("Expected KeyID=%s, got: %s", tc.expectedID, keyID)
			}
		})
	}
}

// TestKeyID_FallbackVariants verifies different fallback scenarios
func TestKeyID_FallbackVariants(t *testing.T) {
	// Test the "fallback-key" scenario (when random generation fails)
	// We can't easily force rand.Read to fail, but we can verify the cached behavior

	ks := &RouterInfoKeystore{
		privateKey:  nil,
		name:        "",
		cachedKeyID: "fallback-key", // Pre-set to simulate random failure scenario
	}

	keyID := ks.KeyID()
	if keyID != "fallback-key" {
		t.Errorf("Expected cached 'fallback-key', got: %s", keyID)
	}

	// Call again to verify consistency
	keyID2 := ks.KeyID()
	if keyID2 != keyID {
		t.Errorf("KeyID changed between calls: %s -> %s", keyID, keyID2)
	}
}

// BenchmarkKeyID_WithCache measures performance of KeyID with caching
func BenchmarkKeyID_WithCache(b *testing.B) {
	ks := &RouterInfoKeystore{
		privateKey:  nil,
		name:        "",
		cachedKeyID: "", // Will be populated on first call
	}

	// First call to populate cache
	_ = ks.KeyID()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ks.KeyID()
	}
}

// BenchmarkKeyID_NormalOperation measures performance with valid private key
func BenchmarkKeyID_NormalOperation(b *testing.B) {
	privateKey, err := ed25519.GenerateEd25519Key()
	if err != nil {
		b.Fatalf("Failed to generate private key: %v", err)
	}

	ks := &RouterInfoKeystore{
		privateKey: privateKey.(types.PrivateKey),
		name:       "",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ks.KeyID()
	}
}
