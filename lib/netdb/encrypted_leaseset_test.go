package netdb

import (
	"sync"
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestStoreEncryptedLeaseSetInvalidDataType tests validation of data type parameter
func TestStoreEncryptedLeaseSetInvalidDataType(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)

	testHash := common.Hash{0x01, 0x02, 0x03}
	testData := []byte{0x01, 0x02, 0x03}

	// Try to store with invalid data type (should be 5 for EncryptedLeaseSet)
	err := db.StoreEncryptedLeaseSet(testHash, testData, 0)
	assert.Error(t, err, "StoreEncryptedLeaseSet should fail with invalid data type")
	assert.Contains(t, err.Error(), "invalid data type", "Error message should mention invalid data type")

	// Try with another invalid data type
	err = db.StoreEncryptedLeaseSet(testHash, testData, 3)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid data type")
}

// TestValidateEncryptedLeaseSetDataType tests the validation function
func TestValidateEncryptedLeaseSetDataType(t *testing.T) {
	tests := []struct {
		name     string
		dataType byte
		wantErr  bool
	}{
		{"valid type 5", 5, false},
		{"invalid type 0", 0, true},
		{"invalid type 1", 1, true},
		{"invalid type 3", 3, true},
		{"invalid type 7", 7, true},
		{"invalid type 255", 255, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateEncryptedLeaseSetDataType(tt.dataType)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestStoreEncryptedLeaseSetParseError tests handling of invalid EncryptedLeaseSet data
func TestStoreEncryptedLeaseSetParseError(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)
	require.NoError(t, db.Create())

	testHash := common.Hash{0x01, 0x02, 0x03}
	testData := []byte{0x01, 0x02, 0x03} // Invalid EncryptedLeaseSet data

	// Store should fail due to parse error
	err := db.StoreEncryptedLeaseSet(testHash, testData, 5)
	assert.Error(t, err, "StoreEncryptedLeaseSet should fail with invalid data")
	assert.Contains(t, err.Error(), "failed to parse EncryptedLeaseSet")
}

// TestStoreEncryptedLeaseSetEmptyData tests handling of empty data
func TestStoreEncryptedLeaseSetEmptyData(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)

	testHash := common.Hash{}
	emptyData := []byte{}

	err := db.StoreEncryptedLeaseSet(testHash, emptyData, 5)
	assert.Error(t, err, "StoreEncryptedLeaseSet should fail with empty data")
	assert.Contains(t, err.Error(), "failed to parse EncryptedLeaseSet")
}

// TestStoreEncryptedLeaseSetNilData tests handling of nil data
func TestStoreEncryptedLeaseSetNilData(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)

	testHash := common.Hash{}

	err := db.StoreEncryptedLeaseSet(testHash, nil, 5)
	assert.Error(t, err, "StoreEncryptedLeaseSet should fail with nil data")
}

// TestGetEncryptedLeaseSetNotFound tests retrieval of non-existent EncryptedLeaseSet
func TestGetEncryptedLeaseSetNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)

	nonExistentHash := common.Hash{0xaa, 0xbb, 0xcc}

	chnl := db.GetEncryptedLeaseSet(nonExistentHash)
	assert.NotNil(t, chnl, "GetEncryptedLeaseSet should return a closed channel for non-existent EncryptedLeaseSet")
	// The channel should be closed and immediately yield a zero value
	_, ok := <-chnl
	assert.False(t, ok, "Channel should be closed for non-existent EncryptedLeaseSet")
}

// TestGetEncryptedLeaseSetBytesNotFound tests byte retrieval of non-existent EncryptedLeaseSet
func TestGetEncryptedLeaseSetBytesNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)

	nonExistentHash := common.Hash{0x11, 0x22, 0x33}

	_, err := db.GetEncryptedLeaseSetBytes(nonExistentHash)
	assert.Error(t, err, "GetEncryptedLeaseSetBytes should fail for non-existent EncryptedLeaseSet")
	assert.Contains(t, err.Error(), "not found", "Error message should indicate EncryptedLeaseSet not found")
}

// TestEncryptedLeaseSetThreadSafety tests concurrent access to EncryptedLeaseSet methods
func TestEncryptedLeaseSetThreadSafety(t *testing.T) {
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
				_ = db.StoreEncryptedLeaseSet(hash, testData, 5)

				// Retrieve (will return nil but tests thread safety)
				chnl := db.GetEncryptedLeaseSet(hash)
				if chnl != nil {
					<-chnl
				}

				// Get bytes (will fail but tests thread safety)
				_, _ = db.GetEncryptedLeaseSetBytes(hash)
			}
		}(i)
	}

	wg.Wait()

	// Test completed without deadlock or race conditions
	t.Log("EncryptedLeaseSet thread safety test completed successfully")
}

// TestEncryptedLeaseSetConcurrentStoreAndRetrieve tests basic concurrent operations
func TestEncryptedLeaseSetConcurrentStoreAndRetrieve(t *testing.T) {
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
		_ = db.StoreEncryptedLeaseSet(hash1, []byte{0x01}, 5)
		chnl := db.GetEncryptedLeaseSet(hash1)
		if chnl != nil {
			<-chnl
		}
		_, _ = db.GetEncryptedLeaseSetBytes(hash1)
	}()

	// Goroutine 2: store and retrieve different hash
	go func() {
		defer wg.Done()
		_ = db.StoreEncryptedLeaseSet(hash2, []byte{0x02}, 5)
		chnl := db.GetEncryptedLeaseSet(hash2)
		if chnl != nil {
			<-chnl
		}
		_, _ = db.GetEncryptedLeaseSetBytes(hash2)
	}()

	wg.Wait()
	// Test passes if no deadlock occurs
}

// TestClientNetDBStoreEncryptedLeaseSet tests ClientNetDB wrapper method
func TestClientNetDBStoreEncryptedLeaseSet(t *testing.T) {
	tmpDir := t.TempDir()
	stdDB := NewStdNetDB(tmpDir)
	require.NoError(t, stdDB.Create())

	clientDB := NewClientNetDB(stdDB)

	testHash := common.Hash{0x01, 0x02, 0x03}
	testData := []byte{0x01, 0x02, 0x03}

	// Should fail with invalid data but test the wrapper
	err := clientDB.StoreEncryptedLeaseSet(testHash, testData, 5)
	assert.Error(t, err, "Should fail with invalid data")
	assert.Contains(t, err.Error(), "failed to parse")
}

// TestRouterNetDBStoreEncryptedLeaseSet tests RouterNetDB wrapper method
func TestRouterNetDBStoreEncryptedLeaseSet(t *testing.T) {
	tmpDir := t.TempDir()
	stdDB := NewStdNetDB(tmpDir)
	require.NoError(t, stdDB.Create())

	routerDB := NewRouterNetDB(stdDB)

	testHash := common.Hash{0x01, 0x02, 0x03}
	testData := []byte{0x01, 0x02, 0x03}

	// Should fail with invalid data but test the wrapper
	err := routerDB.StoreEncryptedLeaseSet(testHash, testData, 5)
	assert.Error(t, err, "Should fail with invalid data")
	assert.Contains(t, err.Error(), "failed to parse")
}
