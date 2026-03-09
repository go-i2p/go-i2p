package netdb

import (
	"path/filepath"
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// leaseSetConfig returns the shared test configuration for standard LeaseSet.
func leaseSetConfig() leaseSetTestConfig {
	return leaseSetTestConfig{
		typeName:       "LeaseSet",
		validDataType:  1,
		altInvalidType: 2,
		parseErrMsg:    "failed to parse LeaseSet",
		store: func(db *StdNetDB, hash common.Hash, data []byte, dt byte) error {
			return db.StoreLeaseSet(hash, data, dt)
		},
		getChannel: func(db *StdNetDB, hash common.Hash) (bool, bool) {
			chnl := db.GetLeaseSet(hash)
			if chnl == nil {
				return false, false
			}
			_, ok := <-chnl
			return true, ok
		},
		getBytes: func(db *StdNetDB, hash common.Hash) ([]byte, error) {
			return db.GetLeaseSetBytes(hash)
		},
		threadSafeOps: func(db *StdNetDB, hash common.Hash, data []byte) {
			_ = db.StoreLeaseSet(hash, data, 1)
			_ = db.GetLeaseSet(hash)
			_, _ = db.GetLeaseSetBytes(hash)
			_ = db.GetLeaseSetCount()
		},
		concurrentOps: func(db *StdNetDB, hash common.Hash, val byte) {
			_ = db.StoreLeaseSet(hash, []byte{val}, 1)
			_ = db.GetLeaseSet(hash)
			_, _ = db.GetLeaseSetBytes(hash)
		},
	}
}

// --- Shared tests delegated to helpers ---

func TestStoreLeaseSetParseError(t *testing.T)      { testStoreParseError(t, leaseSetConfig()) }
func TestStoreLeaseSetInvalidDataType(t *testing.T) { testStoreInvalidDataType(t, leaseSetConfig()) }
func TestStoreLeaseSetEmptyData(t *testing.T)       { testStoreEmptyData(t, leaseSetConfig()) }
func TestStoreLeaseSetNilData(t *testing.T)         { testStoreNilData(t, leaseSetConfig()) }
func TestGetLeaseSetNotFound(t *testing.T)          { testGetNotFound(t, leaseSetConfig()) }
func TestGetLeaseSetBytesNotFound(t *testing.T)     { testGetBytesNotFound(t, leaseSetConfig()) }
func TestLeaseSetThreadSafety(t *testing.T)         { testLeaseSetThreadSafety(t, leaseSetConfig()) }
func TestLeaseSetConcurrentStoreAndRetrieve(t *testing.T) {
	testConcurrentStoreAndRetrieve(t, leaseSetConfig())
}

// --- Tests unique to LeaseSet ---

// TestSkiplistFileForLeaseSet tests file path generation
func TestSkiplistFileForLeaseSet(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)

	testHash := common.Hash{0xab, 0xcd, 0xef}
	fpath := db.SkiplistFileForLeaseSet(testHash)

	assert.Contains(t, fpath, tmpDir, "Path should include database directory")
	assert.Contains(t, fpath, "leaseSet-", "Path should contain 'leaseSet-' prefix")
	assert.NotContains(t, fpath, "routerInfo-", "Path should not contain 'routerInfo-' prefix")

	dir := filepath.Dir(fpath)
	dirName := filepath.Base(dir)
	assert.True(t, dirName[0] == 'l', "LeaseSet directory should start with 'l' prefix")
}

// TestGetLeaseSetCount tests counting LeaseSets in memory
func TestGetLeaseSetCount(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)

	assert.Equal(t, 0, db.GetLeaseSetCount(), "Initial count should be zero")

	for i := 0; i < 5; i++ {
		hash := common.Hash{}
		hash[0] = byte(i)
		db.lsMutex.Lock()
		db.LeaseSets[hash] = Entry{}
		db.lsMutex.Unlock()
	}

	assert.Equal(t, 5, db.GetLeaseSetCount(), "Should count all cached LeaseSets")
}

// TestCreateLeaseSetDirectories tests that Create() makes LeaseSet directories
func TestCreateLeaseSetDirectories(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)

	require.NoError(t, db.Create(), "Create should succeed")

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
		{"valid type 1 (LeaseSet)", 1, false},
		{"valid type 3 (LeaseSet2)", 3, false},
		{"valid type 5 (EncryptedLeaseSet)", 5, false},
		{"valid type 7 (MetaLeaseSet)", 7, false},
		{"invalid type 0 (RouterInfo)", 0, true},
		{"invalid type 2", 2, true},
		{"invalid type 4", 4, true},
		{"invalid type 6", 6, true},
		{"invalid type 8", 8, true},
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
