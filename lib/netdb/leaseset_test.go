package netdb

import (
	"path/filepath"
	"sync"
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Note: These tests focus on validation and error handling paths
// since creating valid LeaseSets requires complex setup with keys and certificates.
// The core storage/retrieval logic is tested with error cases to ensure proper behavior.

// TestStoreLeaseSetParseError tests handling of invalid LeaseSet data
func TestStoreLeaseSetParseError(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)
	require.NoError(t, db.Create())

	testHash := common.Hash{0x01, 0x02, 0x03}
	testData := []byte{0x01, 0x02, 0x03} // Invalid LeaseSet data

	// Store should fail due to parse error
	err := db.StoreLeaseSet(testHash, testData, 1)
	assert.Error(t, err, "StoreLeaseSet should fail with invalid data")
	assert.Contains(t, err.Error(), "failed to parse LeaseSet")
}

// TestStoreLeaseSetInvalidDataType tests validation of data type parameter
func TestStoreLeaseSetInvalidDataType(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)

	testHash := common.Hash{0x01, 0x02, 0x03}
	testData := []byte{0x01, 0x02, 0x03}

	// Try to store with invalid data type (should be 1 for LeaseSet)
	err := db.StoreLeaseSet(testHash, testData, 0)
	assert.Error(t, err, "StoreLeaseSet should fail with invalid data type")
	assert.Contains(t, err.Error(), "invalid data type", "Error message should mention invalid data type")

	// Try with another invalid data type
	err = db.StoreLeaseSet(testHash, testData, 2)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid data type")
}

// TestStoreLeaseSetEmptyData tests handling of empty data
func TestStoreLeaseSetEmptyData(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)

	testHash := common.Hash{}
	emptyData := []byte{}

	err := db.StoreLeaseSet(testHash, emptyData, 1)
	assert.Error(t, err, "StoreLeaseSet should fail with empty data")
	assert.Contains(t, err.Error(), "failed to parse LeaseSet")
}

// TestStoreLeaseSetNilData tests handling of nil data
func TestStoreLeaseSetNilData(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)

	testHash := common.Hash{}

	err := db.StoreLeaseSet(testHash, nil, 1)
	assert.Error(t, err, "StoreLeaseSet should fail with nil data")
}

// TestGetLeaseSetNotFound tests retrieval of non-existent LeaseSet
func TestGetLeaseSetNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)

	nonExistentHash := common.Hash{0xaa, 0xbb, 0xcc}

	chnl := db.GetLeaseSet(nonExistentHash)
	assert.Nil(t, chnl, "GetLeaseSet should return nil for non-existent LeaseSet")
}

// TestGetLeaseSetBytesNotFound tests byte retrieval of non-existent LeaseSet
func TestGetLeaseSetBytesNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)

	nonExistentHash := common.Hash{0x11, 0x22, 0x33}

	_, err := db.GetLeaseSetBytes(nonExistentHash)
	assert.Error(t, err, "GetLeaseSetBytes should fail for non-existent LeaseSet")
	assert.Contains(t, err.Error(), "not found", "Error message should indicate LeaseSet not found")
}

// TestSkiplistFileForLeaseSet tests file path generation
func TestSkiplistFileForLeaseSet(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)

	testHash := common.Hash{0xab, 0xcd, 0xef}
	fpath := db.SkiplistFileForLeaseSet(testHash)

	// Verify path structure: should use 'l' prefix instead of 'r'
	assert.Contains(t, fpath, tmpDir, "Path should include database directory")
	assert.Contains(t, fpath, "leaseSet-", "Path should contain 'leaseSet-' prefix")
	assert.NotContains(t, fpath, "routerInfo-", "Path should not contain 'routerInfo-' prefix")

	// Verify it starts with 'l' subdirectory (not 'r')
	dir := filepath.Dir(fpath)
	dirName := filepath.Base(dir)
	assert.True(t, dirName[0] == 'l', "LeaseSet directory should start with 'l' prefix")
}

// TestGetLeaseSetCount tests counting LeaseSets in memory
func TestGetLeaseSetCount(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)

	// Initially should be zero
	assert.Equal(t, 0, db.GetLeaseSetCount(), "Initial count should be zero")

	// Add test entries directly to cache
	for i := 0; i < 5; i++ {
		hash := common.Hash{}
		hash[0] = byte(i)
		db.lsMutex.Lock()
		db.LeaseSets[hash] = Entry{} // Empty entry for counting test
		db.lsMutex.Unlock()
	}

	assert.Equal(t, 5, db.GetLeaseSetCount(), "Should count all cached LeaseSets")
}

// TestLeaseSetThreadSafety tests concurrent access to LeaseSet methods
func TestLeaseSetThreadSafety(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)
	require.NoError(t, db.Create())

	const numGoroutines = 10
	const numOperations = 20

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Run concurrent operations - expect failures with invalid data but test thread safety
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()

			for j := 0; j < numOperations; j++ {
				hash := common.Hash{}
				hash[0] = byte(id)
				hash[1] = byte(j)
				testData := []byte{byte(id), byte(j)}

				// Store (will fail but tests thread safety)
				_ = db.StoreLeaseSet(hash, testData, 1)

				// Retrieve (will return nil but tests thread safety)
				_ = db.GetLeaseSet(hash)

				// Get bytes (will fail but tests thread safety)
				_, _ = db.GetLeaseSetBytes(hash)

				// Get count (tests mutex)
				_ = db.GetLeaseSetCount()
			}
		}(i)
	}

	wg.Wait()

	// Test completed without deadlock or race conditions
	t.Log("Thread safety test completed successfully")
}

// TestCreateLeaseSetDirectories tests that Create() makes LeaseSet directories
func TestCreateLeaseSetDirectories(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)

	err := db.Create()
	require.NoError(t, err, "Create should succeed")

	// Verify all 'l' prefix directories were created (sample a few)
	testChars := []byte{'A', 'Z', 'a', 'z', '0', '9', '-', '~'}
	for _, c := range testChars {
		dirPath := filepath.Join(tmpDir, "l"+string(c))
		assert.DirExists(t, dirPath, "LeaseSet directory should exist for character %c", c)
	}
}

// TestValidateLeaseSetDataType tests the validation function
func TestValidateLeaseSetDataType(t *testing.T) {
	tests := []struct {
		name     string
		dataType byte
		wantErr  bool
	}{
		{"valid type 1", 1, false},
		{"invalid type 0", 0, true},
		{"invalid type 2", 2, true},
		{"invalid type 255", 255, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateLeaseSetDataType(tt.dataType)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestLeaseSetConcurrentStoreAndRetrieve tests basic concurrent operations
func TestLeaseSetConcurrentStoreAndRetrieve(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)
	require.NoError(t, db.Create())

	var wg sync.WaitGroup
	wg.Add(2)

	hash1 := common.Hash{0x01}
	hash2 := common.Hash{0x02}

	// Goroutine 1: store and retrieve
	go func() {
		defer wg.Done()
		_ = db.StoreLeaseSet(hash1, []byte{0x01}, 1)
		_ = db.GetLeaseSet(hash1)
		_, _ = db.GetLeaseSetBytes(hash1)
	}()

	// Goroutine 2: store and retrieve different hash
	go func() {
		defer wg.Done()
		_ = db.StoreLeaseSet(hash2, []byte{0x02}, 1)
		_ = db.GetLeaseSet(hash2)
		_, _ = db.GetLeaseSetBytes(hash2)
	}()

	wg.Wait()
	// Test passes if no deadlock occurs
}
