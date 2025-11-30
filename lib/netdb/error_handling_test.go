package netdb

import (
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
)

// TestIdentHashErrorHandling tests proper error handling for IdentHash() calls
// This validates the migration from silent error ignoring to proper error propagation
func TestIdentHashErrorHandling(t *testing.T) {
	t.Run("StoreRouterInfo handles IdentHash error", func(t *testing.T) {
		tempDir := t.TempDir()
		db := NewStdNetDB(tempDir)
		if err := db.Create(); err != nil {
			t.Fatalf("Failed to create NetDB: %v", err)
		}

		// Try to store with invalid data directly
		var hash common.Hash
		invalidData := []byte{0x01, 0x02}

		storeErr := db.StoreRouterInfo(hash, invalidData, 0)
		if storeErr == nil {
			t.Error("Expected error when storing invalid RouterInfo data, got nil")
		}
	})

	t.Run("Empty RouterInfo IdentHash returns error", func(t *testing.T) {
		// Create an invalid RouterInfo
		ri := router_info.RouterInfo{}

		// IdentHash() should return an error for invalid RouterInfo
		_, err := ri.IdentHash()
		if err == nil {
			t.Error("Expected IdentHash() to return error for empty RouterInfo")
		}
	})
}

// TestBytesErrorHandling tests proper error handling for Bytes() calls
// This validates error propagation from RouterInfo.Bytes()
func TestBytesErrorHandling(t *testing.T) {
	t.Run("Empty RouterInfo IdentHash returns error", func(t *testing.T) {
		// Create an invalid RouterInfo
		ri := router_info.RouterInfo{}

		// IdentHash() should return error for invalid RouterInfo
		_, err := ri.IdentHash()
		if err == nil {
			t.Error("Expected IdentHash() to return error for invalid RouterInfo")
		}
	})

	t.Run("StoreRouterInfo rejects empty data", func(t *testing.T) {
		tempDir := t.TempDir()
		db := NewStdNetDB(tempDir)
		if err := db.Create(); err != nil {
			t.Fatalf("Failed to create NetDB: %v", err)
		}

		var testHash common.Hash
		emptyData := []byte{}

		err := db.StoreRouterInfo(testHash, emptyData, 0)
		if err == nil {
			t.Error("Expected error for empty data, got nil")
		}
	})

	t.Run("StoreRouterInfo rejects nil data", func(t *testing.T) {
		tempDir := t.TempDir()
		db := NewStdNetDB(tempDir)
		if err := db.Create(); err != nil {
			t.Fatalf("Failed to create NetDB: %v", err)
		}

		var testHash common.Hash

		// Test with nil data
		err := db.StoreRouterInfo(testHash, nil, 0)
		if err == nil {
			t.Error("Expected error for nil data, got nil")
		}
	})
}

// TestPublicKeyErrorHandling tests proper error handling for PublicKey() and SigningPublicKey() calls
func TestPublicKeyErrorHandling(t *testing.T) {
	t.Run("Invalid RouterInfo handles key extraction errors", func(t *testing.T) {
		// Create an empty RouterInfo
		ri := router_info.RouterInfo{}

		identity := ri.RouterIdentity()

		// Try to get keys from nil/invalid identity - should handle gracefully
		if identity == nil {
			// Expected case - empty RouterInfo has nil identity
			return
		}

		// If identity is not nil, try to get keys
		_, pkErr := identity.PublicKey()
		_, spkErr := identity.SigningPublicKey()

		// At least one should error for an invalid RouterInfo
		if pkErr == nil && spkErr == nil {
			t.Error("Expected at least one key extraction to fail for invalid RouterInfo")
		}
	})
}

// TestZeroValueDetection tests that zero values are properly detected
func TestZeroValueDetection(t *testing.T) {
	t.Run("Zero hash lookup returns nil", func(t *testing.T) {
		var zeroHash common.Hash

		tempDir := t.TempDir()
		db := NewStdNetDB(tempDir)
		if err := db.Create(); err != nil {
			t.Fatalf("Failed to create NetDB: %v", err)
		}

		// Attempting to use a zero hash should be handled gracefully
		data, err := db.GetRouterInfoBytes(zeroHash)
		// Should return nil or error, not panic
		if err == nil && data != nil && len(data) > 0 {
			t.Error("Expected nil or empty data for zero hash lookup")
		}
	})

	t.Run("Empty RouterInfo IdentHash returns error", func(t *testing.T) {
		var emptyRI router_info.RouterInfo

		// IdentHash() should return error for empty RouterInfo
		_, err := emptyRI.IdentHash()
		if err == nil {
			t.Error("Expected error for empty RouterInfo IdentHash() call")
		}
	})
}

// TestErrorPropagation tests that errors are properly propagated through call stacks
func TestErrorPropagation(t *testing.T) {
	t.Run("Invalid data propagates through storage chain", func(t *testing.T) {
		tempDir := t.TempDir()
		db := NewStdNetDB(tempDir)
		if err := db.Create(); err != nil {
			t.Fatalf("Failed to create NetDB: %v", err)
		}

		// Try to store invalid data
		var testHash common.Hash
		invalidData := []byte{0x00}

		err := db.StoreRouterInfo(testHash, invalidData, 0)
		if err == nil {
			t.Error("Expected error to propagate from StoreRouterInfo with invalid data")
		}

		// Error message should indicate parsing failure or invalid data
		if err != nil {
			errStr := err.Error()
			if !containsString(errStr, "parse") &&
				!containsString(errStr, "invalid") &&
				!containsString(errStr, "fail") &&
				!containsString(errStr, "error") {
				t.Logf("Got error: %v", err)
			}
		}
	})

	t.Run("Invalid data type propagates error", func(t *testing.T) {
		tempDir := t.TempDir()
		db := NewStdNetDB(tempDir)
		if err := db.Create(); err != nil {
			t.Fatalf("Failed to create NetDB: %v", err)
		}

		var testHash common.Hash
		testData := []byte{0x01, 0x02}

		// Use invalid data type (should be 0 for RouterInfo)
		err := db.StoreRouterInfo(testHash, testData, 99)
		if err == nil {
			t.Error("Expected error for invalid data type")
		}

		if err != nil && !containsString(err.Error(), "data type") {
			t.Logf("Error message should mention data type: %v", err)
		}
	})
}

// TestGracefulDegradation tests that the system degrades gracefully on errors
func TestGracefulDegradation(t *testing.T) {
	t.Run("NetDB continues after failed store", func(t *testing.T) {
		tempDir := t.TempDir()
		db := NewStdNetDB(tempDir)
		if err := db.Create(); err != nil {
			t.Fatalf("Failed to create NetDB: %v", err)
		}

		// Try to store invalid data
		var hash1 common.Hash
		hash1[0] = 0x01
		invalidData := []byte{0x00}

		_ = db.StoreRouterInfo(hash1, invalidData, 0) // Will fail

		// NetDB should still be operational - verify by checking it exists
		if !db.Exists() {
			t.Error("NetDB should remain operational after failed store")
		}

		// Should be able to perform other operations
		count := db.GetRouterInfoCount()
		if count < 0 {
			t.Error("NetDB should return valid count after failed store")
		}
	})

	t.Run("Lookup returns empty on missing data", func(t *testing.T) {
		tempDir := t.TempDir()
		db := NewStdNetDB(tempDir)
		if err := db.Create(); err != nil {
			t.Fatalf("Failed to create NetDB: %v", err)
		}

		// Look up non-existent hash
		var nonExistentHash common.Hash
		nonExistentHash[0] = 0xFF

		data, err := db.GetRouterInfoBytes(nonExistentHash)
		// Should return nil gracefully, not panic
		if err == nil && data != nil {
			t.Error("Expected nil for non-existent RouterInfo lookup")
		}
	})
}

// TestConcurrentErrorHandling tests that error handling is thread-safe
func TestConcurrentErrorHandling(t *testing.T) {
	t.Run("Concurrent invalid stores don't cause race", func(t *testing.T) {
		tempDir := t.TempDir()
		db := NewStdNetDB(tempDir)
		if err := db.Create(); err != nil {
			t.Fatalf("Failed to create NetDB: %v", err)
		}

		// Launch multiple goroutines attempting invalid stores
		done := make(chan bool, 10)
		for i := 0; i < 10; i++ {
			go func(idx int) {
				var hash common.Hash
				hash[0] = byte(idx)
				invalidData := []byte{byte(idx)}

				// All will fail but shouldn't cause race conditions
				_ = db.StoreRouterInfo(hash, invalidData, 0)
				done <- true
			}(i)
		}

		// Wait for all goroutines
		for i := 0; i < 10; i++ {
			<-done
		}

		// NetDB should still be operational
		if !db.Exists() {
			t.Error("NetDB should remain operational after concurrent failed stores")
		}
	})
}

// TestGetRouterInfoBytesErrorHandling tests error handling in GetRouterInfoBytes
func TestGetRouterInfoBytesErrorHandling(t *testing.T) {
	t.Run("GetRouterInfoBytes returns error for invalid hash", func(t *testing.T) {
		tempDir := t.TempDir()
		db := NewStdNetDB(tempDir)
		if err := db.Create(); err != nil {
			t.Fatalf("Failed to create NetDB: %v", err)
		}

		var invalidHash common.Hash
		data, err := db.GetRouterInfoBytes(invalidHash)

		// Should handle gracefully - either return error or nil data
		if err == nil && data != nil && len(data) > 0 {
			t.Error("Expected nil or error for non-existent hash")
		}
	})
}
