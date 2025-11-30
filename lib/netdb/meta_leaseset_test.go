package netdb

import (
	"sync"
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestStoreMetaLeaseSetInvalidDataType tests validation of data type parameter
func TestStoreMetaLeaseSetInvalidDataType(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)

	testHash := common.Hash{0x01, 0x02, 0x03}
	testData := []byte{0x01, 0x02, 0x03}

	// Try to store with invalid data type (should be 7 for MetaLeaseSet)
	err := db.StoreMetaLeaseSet(testHash, testData, 0)
	assert.Error(t, err, "StoreMetaLeaseSet should fail with invalid data type")
	assert.Contains(t, err.Error(), "invalid data type", "Error message should mention invalid data type")

	// Try with another invalid data type
	err = db.StoreMetaLeaseSet(testHash, testData, 5)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid data type")
}

// TestValidateMetaLeaseSetDataType tests the validation function
func TestValidateMetaLeaseSetDataType(t *testing.T) {
	tests := []struct {
		name     string
		dataType byte
		wantErr  bool
	}{
		{"valid type 7", 7, false},
		{"invalid type 0", 0, true},
		{"invalid type 1", 1, true},
		{"invalid type 3", 3, true},
		{"invalid type 5", 5, true},
		{"invalid type 255", 255, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateMetaLeaseSetDataType(tt.dataType)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestStoreMetaLeaseSetParseError tests handling of invalid MetaLeaseSet data
func TestStoreMetaLeaseSetParseError(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)
	require.NoError(t, db.Create())

	testHash := common.Hash{0x01, 0x02, 0x03}
	testData := []byte{0x01, 0x02, 0x03} // Invalid MetaLeaseSet data

	// Store should fail due to parse error
	err := db.StoreMetaLeaseSet(testHash, testData, 7)
	assert.Error(t, err, "StoreMetaLeaseSet should fail with invalid data")
	assert.Contains(t, err.Error(), "failed to parse MetaLeaseSet")
}

// TestStoreMetaLeaseSetEmptyData tests handling of empty data
func TestStoreMetaLeaseSetEmptyData(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)

	testHash := common.Hash{}
	emptyData := []byte{}

	err := db.StoreMetaLeaseSet(testHash, emptyData, 7)
	assert.Error(t, err, "StoreMetaLeaseSet should fail with empty data")
	assert.Contains(t, err.Error(), "failed to parse MetaLeaseSet")
}

// TestStoreMetaLeaseSetNilData tests handling of nil data
func TestStoreMetaLeaseSetNilData(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)

	testHash := common.Hash{}

	err := db.StoreMetaLeaseSet(testHash, nil, 7)
	assert.Error(t, err, "StoreMetaLeaseSet should fail with nil data")
}

// TestGetMetaLeaseSetNotFound tests retrieval of non-existent MetaLeaseSet
func TestGetMetaLeaseSetNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)

	nonExistentHash := common.Hash{0xaa, 0xbb, 0xcc}

	chnl := db.GetMetaLeaseSet(nonExistentHash)
	assert.Nil(t, chnl, "GetMetaLeaseSet should return nil for non-existent MetaLeaseSet")
}

// TestGetMetaLeaseSetBytesNotFound tests byte retrieval of non-existent MetaLeaseSet
func TestGetMetaLeaseSetBytesNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)

	nonExistentHash := common.Hash{0x11, 0x22, 0x33}

	_, err := db.GetMetaLeaseSetBytes(nonExistentHash)
	assert.Error(t, err, "GetMetaLeaseSetBytes should fail for non-existent MetaLeaseSet")
	assert.Contains(t, err.Error(), "not found", "Error message should indicate MetaLeaseSet not found")
}

// TestMetaLeaseSetThreadSafety tests concurrent access to MetaLeaseSet methods
func TestMetaLeaseSetThreadSafety(t *testing.T) {
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
				_ = db.StoreMetaLeaseSet(hash, testData, 7)

				// Retrieve (will return nil but tests thread safety)
				chnl := db.GetMetaLeaseSet(hash)
				if chnl != nil {
					<-chnl
				}

				// Get bytes (will fail but tests thread safety)
				_, _ = db.GetMetaLeaseSetBytes(hash)
			}
		}(i)
	}

	wg.Wait()

	// Test completed without deadlock or race conditions
	t.Log("MetaLeaseSet thread safety test completed successfully")
}

// TestMetaLeaseSetConcurrentStoreAndRetrieve tests basic concurrent operations
func TestMetaLeaseSetConcurrentStoreAndRetrieve(t *testing.T) {
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
		_ = db.StoreMetaLeaseSet(hash1, []byte{0x01}, 7)
		chnl := db.GetMetaLeaseSet(hash1)
		if chnl != nil {
			<-chnl
		}
		_, _ = db.GetMetaLeaseSetBytes(hash1)
	}()

	// Goroutine 2: store and retrieve different hash
	go func() {
		defer wg.Done()
		_ = db.StoreMetaLeaseSet(hash2, []byte{0x02}, 7)
		chnl := db.GetMetaLeaseSet(hash2)
		if chnl != nil {
			<-chnl
		}
		_, _ = db.GetMetaLeaseSetBytes(hash2)
	}()

	wg.Wait()
	// Test passes if no deadlock occurs
}

// TestClientNetDBStoreMetaLeaseSet tests ClientNetDB wrapper method
func TestClientNetDBStoreMetaLeaseSet(t *testing.T) {
	tmpDir := t.TempDir()
	stdDB := NewStdNetDB(tmpDir)
	require.NoError(t, stdDB.Create())
	
	clientDB := NewClientNetDB(stdDB)
	
	testHash := common.Hash{0x01, 0x02, 0x03}
	testData := []byte{0x01, 0x02, 0x03}
	
	// Should fail with invalid data but test the wrapper
	err := clientDB.StoreMetaLeaseSet(testHash, testData, 7)
	assert.Error(t, err, "Should fail with invalid data")
	assert.Contains(t, err.Error(), "failed to parse")
}

// TestRouterNetDBStoreMetaLeaseSet tests RouterNetDB wrapper method
func TestRouterNetDBStoreMetaLeaseSet(t *testing.T) {
	tmpDir := t.TempDir()
	stdDB := NewStdNetDB(tmpDir)
	require.NoError(t, stdDB.Create())
	
	routerDB := NewRouterNetDB(stdDB)
	
	testHash := common.Hash{0x01, 0x02, 0x03}
	testData := []byte{0x01, 0x02, 0x03}
	
	// Should fail with invalid data but test the wrapper
	err := routerDB.StoreMetaLeaseSet(testHash, testData, 7)
	assert.Error(t, err, "Should fail with invalid data")
	assert.Contains(t, err.Error(), "failed to parse")
}

// TestLeaseSetTypeDifferentiation tests that different LeaseSet types are handled correctly
func TestLeaseSetTypeDifferentiation(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)
	require.NoError(t, db.Create())

	// Test that each type validates correctly
	testHash := common.Hash{0x01, 0x02, 0x03}
	testData := []byte{0x01, 0x02, 0x03}

	// Type 1 should only work with StoreLeaseSet
	err := db.StoreLeaseSet(testHash, testData, 1)
	assert.Error(t, err) // Will fail due to invalid data, but type is correct

	err = db.StoreLeaseSet(testHash, testData, 3)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid data type")

	// Type 3 should only work with StoreLeaseSet2
	err = db.StoreLeaseSet2(testHash, testData, 3)
	assert.Error(t, err) // Will fail due to invalid data, but type is correct

	err = db.StoreLeaseSet2(testHash, testData, 5)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid data type")

	// Type 5 should only work with StoreEncryptedLeaseSet
	err = db.StoreEncryptedLeaseSet(testHash, testData, 5)
	assert.Error(t, err) // Will fail due to invalid data, but type is correct

	err = db.StoreEncryptedLeaseSet(testHash, testData, 7)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid data type")

	// Type 7 should only work with StoreMetaLeaseSet
	err = db.StoreMetaLeaseSet(testHash, testData, 7)
	assert.Error(t, err) // Will fail due to invalid data, but type is correct

	err = db.StoreMetaLeaseSet(testHash, testData, 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid data type")
}
