package netdb

import (
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// encryptedLeaseSetConfig returns the shared test configuration for EncryptedLeaseSet.
func encryptedLeaseSetConfig() leaseSetTestConfig {
	return leaseSetTestConfig{
		typeName:       "EncryptedLeaseSet",
		validDataType:  5,
		altInvalidType: 3,
		parseErrMsg:    "failed to parse EncryptedLeaseSet",
		store: func(db *StdNetDB, hash common.Hash, data []byte, dt byte) error {
			return db.StoreEncryptedLeaseSet(hash, data, dt)
		},
		getChannel: func(db *StdNetDB, hash common.Hash) (bool, bool) {
			chnl := db.GetEncryptedLeaseSet(hash)
			if chnl == nil {
				return false, false
			}
			_, ok := <-chnl
			return true, ok
		},
		getBytes: func(db *StdNetDB, hash common.Hash) ([]byte, error) {
			return db.GetEncryptedLeaseSetBytes(hash)
		},
		threadSafeOps: func(db *StdNetDB, hash common.Hash, data []byte) {
			_ = db.StoreEncryptedLeaseSet(hash, data, 5)
			chnl := db.GetEncryptedLeaseSet(hash)
			if chnl != nil {
				<-chnl
			}
			_, _ = db.GetEncryptedLeaseSetBytes(hash)
		},
		concurrentOps: func(db *StdNetDB, hash common.Hash, val byte) {
			_ = db.StoreEncryptedLeaseSet(hash, []byte{val}, 5)
			chnl := db.GetEncryptedLeaseSet(hash)
			if chnl != nil {
				<-chnl
			}
			_, _ = db.GetEncryptedLeaseSetBytes(hash)
		},
	}
}

// --- Shared tests delegated to helpers ---

func TestStoreEncryptedLeaseSetInvalidDataType(t *testing.T) {
	testStoreInvalidDataType(t, encryptedLeaseSetConfig())
}
func TestStoreEncryptedLeaseSetParseError(t *testing.T) {
	testStoreParseError(t, encryptedLeaseSetConfig())
}
func TestStoreEncryptedLeaseSetEmptyData(t *testing.T) {
	testStoreEmptyData(t, encryptedLeaseSetConfig())
}
func TestStoreEncryptedLeaseSetNilData(t *testing.T) { testStoreNilData(t, encryptedLeaseSetConfig()) }
func TestGetEncryptedLeaseSetNotFound(t *testing.T)  { testGetNotFound(t, encryptedLeaseSetConfig()) }
func TestGetEncryptedLeaseSetBytesNotFound(t *testing.T) {
	testGetBytesNotFound(t, encryptedLeaseSetConfig())
}
func TestEncryptedLeaseSetThreadSafety(t *testing.T) {
	testLeaseSetThreadSafety(t, encryptedLeaseSetConfig())
}
func TestEncryptedLeaseSetConcurrentStoreAndRetrieve(t *testing.T) {
	testConcurrentStoreAndRetrieve(t, encryptedLeaseSetConfig())
}

// --- Tests unique to EncryptedLeaseSet ---

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
			err := validateLeaseSetVariantDataType(tt.dataType, 5, "EncryptedLeaseSet")
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestNetDBStoreEncryptedLeaseSetWrappers tests ClientNetDB and RouterNetDB wrapper methods
func TestNetDBStoreEncryptedLeaseSetWrappers(t *testing.T) {
	tests := []struct {
		name  string
		newDB func(*StdNetDB) interface {
			StoreEncryptedLeaseSet(common.Hash, []byte, byte) error
		}
	}{
		{"ClientNetDB", func(s *StdNetDB) interface {
			StoreEncryptedLeaseSet(common.Hash, []byte, byte) error
		} {
			return NewClientNetDB(s)
		}},
		{"RouterNetDB", func(s *StdNetDB) interface {
			StoreEncryptedLeaseSet(common.Hash, []byte, byte) error
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

			err := db.StoreEncryptedLeaseSet(testHash, testData, 5)
			assert.Error(t, err, "Should fail with invalid data")
			assert.Contains(t, err.Error(), "failed to parse")
		})
	}
}
