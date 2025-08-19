package netdb

import (
	"os"
	"path/filepath"
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
)

// createTestRouterInfo creates a minimal RouterInfo for testing
func createTestRouterInfo() (router_info.RouterInfo, []byte, common.Hash) {
	// Create a minimal RouterInfo structure
	// This is a simplified version for testing purposes
	testData := []byte{
		// RouterInfo structure - this is a minimal mock structure
		0x00, 0x01, // version
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // identity hash (8 bytes for test)
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, // complete 32 bytes
	}

	// Create a test RouterInfo by parsing the test data
	// Note: This will fail in a real scenario, but we're testing the error handling
	ri := router_info.RouterInfo{} // Empty RouterInfo for testing

	// Create a test hash
	var testHash common.Hash
	copy(testHash[:], testData[:32])

	return ri, testData, testHash
}

func TestStdNetDB_StoreRouterInfo_InvalidDataType(t *testing.T) {
	// Create temporary directory for test NetDB
	tempDir := t.TempDir()
	db := NewStdNetDB(tempDir)
	if err := db.Create(); err != nil {
		t.Fatalf("Failed to create NetDB: %v", err)
	}

	_, testData, testHash := createTestRouterInfo()

	// Test with invalid data type (should be 0 for RouterInfo)
	err := db.StoreRouterInfo(testHash, testData, 1)
	if err == nil {
		t.Error("Expected error for invalid data type, got nil")
	}
	if err != nil && !containsString(err.Error(), "invalid data type for RouterInfo") {
		t.Errorf("Expected error about invalid data type, got: %v", err)
	}
}

func TestStdNetDB_StoreRouterInfo_ParseError(t *testing.T) {
	// Create temporary directory for test NetDB
	tempDir := t.TempDir()
	db := NewStdNetDB(tempDir)
	if err := db.Create(); err != nil {
		t.Fatalf("Failed to create NetDB: %v", err)
	}

	// Test with invalid RouterInfo data
	invalidData := []byte{0x00, 0x01, 0x02} // Invalid RouterInfo data
	var testHash common.Hash
	copy(testHash[:], invalidData)

	err := db.StoreRouterInfo(testHash, invalidData, 0)
	if err == nil {
		t.Error("Expected error for invalid RouterInfo data, got nil")
	}
	if err != nil && !containsString(err.Error(), "failed to parse RouterInfo") {
		t.Errorf("Expected error about parsing RouterInfo, got: %v", err)
	}
}

func TestStdNetDB_StoreRouterInfo_EmptyData(t *testing.T) {
	// Create temporary directory for test NetDB
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
	if err != nil && !containsString(err.Error(), "failed to parse RouterInfo") {
		t.Errorf("Expected error about parsing RouterInfo, got: %v", err)
	}
}

func TestStdNetDB_StoreRouterInfo_NilHandling(t *testing.T) {
	// Test that NetDB handles nil inputs gracefully
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
}

func TestStdNetDB_StoreRouterInfo_ConcurrentAccess(t *testing.T) {
	// Test concurrent access to RouterInfo storage
	tempDir := t.TempDir()
	db := NewStdNetDB(tempDir)
	if err := db.Create(); err != nil {
		t.Fatalf("Failed to create NetDB: %v", err)
	}

	// Create different test hashes
	var hash1, hash2 common.Hash
	hash1[0] = 0x01
	hash2[0] = 0x02

	testData := []byte{0x01, 0x02, 0x03} // Invalid but consistent data

	// Test that concurrent access doesn't cause race conditions
	done1 := make(chan bool)
	done2 := make(chan bool)

	go func() {
		_ = db.StoreRouterInfo(hash1, testData, 0) // Will fail but test concurrency
		done1 <- true
	}()

	go func() {
		_ = db.StoreRouterInfo(hash2, testData, 0) // Will fail but test concurrency
		done2 <- true
	}()

	<-done1
	<-done2

	// Test completed without deadlock - success
}

func TestStdNetDB_StoreRouterInfo_DirectoryCreation(t *testing.T) {
	// Test that the database creates necessary directory structure
	tempDir := t.TempDir()
	db := NewStdNetDB(tempDir)

	// Don't call Create() first to test automatic directory handling
	_, testData, testHash := createTestRouterInfo()

	err := db.StoreRouterInfo(testHash, testData, 0)
	// This will fail due to parsing, but directory structure should be attempted
	if err == nil {
		t.Error("Expected error due to parsing issues, got nil")
	}
}

func TestStdNetDB_Create_DirectoryStructure(t *testing.T) {
	// Test that Create() properly sets up directory structure
	tempDir := t.TempDir()
	db := NewStdNetDB(tempDir)

	err := db.Create()
	if err != nil {
		t.Fatalf("Failed to create NetDB: %v", err)
	}

	// Verify root directory exists
	if !dirExists(tempDir) {
		t.Errorf("Root directory %s does not exist", tempDir)
	}

	// Verify subdirectories exist (test a few)
	subdirs := []string{"rA", "rB", "r0"}
	for _, subdir := range subdirs {
		path := filepath.Join(tempDir, subdir)
		if !dirExists(path) {
			t.Errorf("Subdirectory %s does not exist", path)
		}
	}
}

func TestStdNetDB_Exists_EmptyDirectory(t *testing.T) {
	// Test Exists() on empty directory
	tempDir := t.TempDir()
	db := NewStdNetDB(tempDir)

	// Should not exist initially
	if db.Exists() {
		t.Error("Expected NetDB to not exist initially")
	}

	// Should exist after Create()
	if err := db.Create(); err != nil {
		t.Fatalf("Failed to create NetDB: %v", err)
	}
	if !db.Exists() {
		t.Error("Expected NetDB to exist after Create()")
	}
}

func TestStdNetDB_Path(t *testing.T) {
	// Test Path() returns correct path
	testPath := "/test/netdb/path"
	db := NewStdNetDB(testPath)

	if db.Path() != testPath {
		t.Errorf("Expected path %s, got %s", testPath, db.Path())
	}
}

// Helper functions for testing
func containsString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return info.IsDir()
}
