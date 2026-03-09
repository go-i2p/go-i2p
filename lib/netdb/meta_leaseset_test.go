package netdb

import (
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// metaLeaseSetConfig returns the shared test configuration for MetaLeaseSet.
func metaLeaseSetConfig() leaseSetTestConfig {
	return leaseSetTestConfig{
		typeName:       "MetaLeaseSet",
		validDataType:  7,
		altInvalidType: 5,
		parseErrMsg:    "failed to parse MetaLeaseSet",
		store: func(db *StdNetDB, hash common.Hash, data []byte, dt byte) error {
			return db.StoreMetaLeaseSet(hash, data, dt)
		},
		getChannel: func(db *StdNetDB, hash common.Hash) (bool, bool) {
			chnl := db.GetMetaLeaseSet(hash)
			if chnl == nil {
				return false, false
			}
			_, ok := <-chnl
			return true, ok
		},
		getBytes: func(db *StdNetDB, hash common.Hash) ([]byte, error) {
			return db.GetMetaLeaseSetBytes(hash)
		},
		threadSafeOps: func(db *StdNetDB, hash common.Hash, data []byte) {
			_ = db.StoreMetaLeaseSet(hash, data, 7)
			chnl := db.GetMetaLeaseSet(hash)
			if chnl != nil {
				<-chnl
			}
			_, _ = db.GetMetaLeaseSetBytes(hash)
		},
		concurrentOps: func(db *StdNetDB, hash common.Hash, val byte) {
			_ = db.StoreMetaLeaseSet(hash, []byte{val}, 7)
			chnl := db.GetMetaLeaseSet(hash)
			if chnl != nil {
				<-chnl
			}
			_, _ = db.GetMetaLeaseSetBytes(hash)
		},
	}
}

// --- Shared tests delegated to helpers ---

func TestStoreMetaLeaseSetInvalidDataType(t *testing.T) {
	testStoreInvalidDataType(t, metaLeaseSetConfig())
}
func TestStoreMetaLeaseSetParseError(t *testing.T)  { testStoreParseError(t, metaLeaseSetConfig()) }
func TestStoreMetaLeaseSetEmptyData(t *testing.T)   { testStoreEmptyData(t, metaLeaseSetConfig()) }
func TestStoreMetaLeaseSetNilData(t *testing.T)     { testStoreNilData(t, metaLeaseSetConfig()) }
func TestGetMetaLeaseSetNotFound(t *testing.T)      { testGetNotFound(t, metaLeaseSetConfig()) }
func TestGetMetaLeaseSetBytesNotFound(t *testing.T) { testGetBytesNotFound(t, metaLeaseSetConfig()) }
func TestMetaLeaseSetThreadSafety(t *testing.T)     { testLeaseSetThreadSafety(t, metaLeaseSetConfig()) }
func TestMetaLeaseSetConcurrentStoreAndRetrieve(t *testing.T) {
	testConcurrentStoreAndRetrieve(t, metaLeaseSetConfig())
}

// --- Tests unique to MetaLeaseSet ---

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
			err := validateLeaseSetVariantDataType(tt.dataType, 7, "MetaLeaseSet")
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestNetDBStoreMetaLeaseSetWrappers tests ClientNetDB and RouterNetDB wrapper methods
func TestNetDBStoreMetaLeaseSetWrappers(t *testing.T) {
	tests := []struct {
		name  string
		newDB func(*StdNetDB) interface {
			StoreMetaLeaseSet(common.Hash, []byte, byte) error
		}
	}{
		{"ClientNetDB", func(s *StdNetDB) interface {
			StoreMetaLeaseSet(common.Hash, []byte, byte) error
		} {
			return NewClientNetDB(s)
		}},
		{"RouterNetDB", func(s *StdNetDB) interface {
			StoreMetaLeaseSet(common.Hash, []byte, byte) error
		} {
			return NewRouterNetDB(s)
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			stdDB := NewStdNetDB(tmpDir)
			require.NoError(t, stdDB.Create())

			db := tt.newDB(stdDB)

			testHash := common.Hash{0x01, 0x02, 0x03}
			testData := []byte{0x01, 0x02, 0x03}

			err := db.StoreMetaLeaseSet(testHash, testData, 7)
			assert.Error(t, err, "Should fail with invalid data")
			assert.Contains(t, err.Error(), "failed to parse")
		})
	}
}

// TestLeaseSetTypeDifferentiation tests that different LeaseSet types are handled correctly
func TestLeaseSetTypeDifferentiation(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)
	require.NoError(t, db.Create())

	testHash := common.Hash{0x01, 0x02, 0x03}
	testData := []byte{0x01, 0x02, 0x03}

	// StoreLeaseSet accepts all valid LeaseSet types (1, 3, 5, 7) and dispatches
	for _, validType := range []byte{1, 3, 5, 7} {
		err := db.StoreLeaseSet(testHash, testData, validType)
		assert.Error(t, err) // Will fail due to invalid data, but type is accepted
	}

	// Invalid types should be rejected by StoreLeaseSet
	for _, invalidType := range []byte{0, 2} {
		err := db.StoreLeaseSet(testHash, testData, invalidType)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid data type")
	}

	// Type-specific store methods enforce strict type matching
	typeMethodPairs := []struct {
		store     func(common.Hash, []byte, byte) error
		validType byte
		wrongType byte
	}{
		{db.StoreLeaseSet2, 3, 5},
		{db.StoreEncryptedLeaseSet, 5, 7},
		{db.StoreMetaLeaseSet, 7, 1},
	}
	for _, p := range typeMethodPairs {
		err := p.store(testHash, testData, p.validType)
		assert.Error(t, err) // parse error, but type is correct

		err = p.store(testHash, testData, p.wrongType)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid data type")
	}
}
