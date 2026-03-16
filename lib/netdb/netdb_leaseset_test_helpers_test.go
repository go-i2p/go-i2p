package netdb

import (
	"sync"
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// leaseSetTestConfig parameterizes tests shared across LeaseSet, MetaLeaseSet,
// and EncryptedLeaseSet to eliminate near-identical test clones.
type leaseSetTestConfig struct {
	typeName       string // e.g. "LeaseSet"
	validDataType  byte   // e.g. 1, 5, 7
	altInvalidType byte   // a second invalid type to test (varies per variant)
	parseErrMsg    string // e.g. "failed to parse LeaseSet"

	// store calls the variant-specific Store method.
	store func(db *StdNetDB, hash common.Hash, data []byte, dataType byte) error
	// getChannel calls the variant-specific Get method and returns (notNil, chanOpen).
	getChannel func(db *StdNetDB, hash common.Hash) (notNil, chanOpen bool)
	// getBytes calls the variant-specific GetBytes method.
	getBytes func(db *StdNetDB, hash common.Hash) ([]byte, error)
	// threadSafeOps runs all ops for one hash during the thread-safety test.
	threadSafeOps func(db *StdNetDB, hash common.Hash, data []byte)
	// concurrentOps runs store+get+getBytes for the concurrent-pair test.
	concurrentOps func(db *StdNetDB, hash common.Hash, val byte)
}

// --- shared test helpers ---

func testStoreInvalidDataType(t *testing.T, cfg leaseSetTestConfig) {
	t.Helper()
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)

	testHash := common.Hash{0x01, 0x02, 0x03}
	testData := []byte{0x01, 0x02, 0x03}

	err := cfg.store(db, testHash, testData, 0)
	assert.Error(t, err, "Store%s should fail with invalid data type", cfg.typeName)
	assert.Contains(t, err.Error(), "invalid data type")

	err = cfg.store(db, testHash, testData, cfg.altInvalidType)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid data type")
}

func testStoreParseError(t *testing.T, cfg leaseSetTestConfig) {
	t.Helper()
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)
	require.NoError(t, db.Create())

	testHash := common.Hash{0x01, 0x02, 0x03}
	testData := []byte{0x01, 0x02, 0x03}

	err := cfg.store(db, testHash, testData, cfg.validDataType)
	assert.Error(t, err, "Store%s should fail with invalid data", cfg.typeName)
	assert.Contains(t, err.Error(), cfg.parseErrMsg)
}

func testStoreEmptyData(t *testing.T, cfg leaseSetTestConfig) {
	t.Helper()
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)

	err := cfg.store(db, common.Hash{}, []byte{}, cfg.validDataType)
	assert.Error(t, err, "Store%s should fail with empty data", cfg.typeName)
	assert.Contains(t, err.Error(), cfg.parseErrMsg)
}

func testStoreNilData(t *testing.T, cfg leaseSetTestConfig) {
	t.Helper()
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)

	err := cfg.store(db, common.Hash{}, nil, cfg.validDataType)
	assert.Error(t, err, "Store%s should fail with nil data", cfg.typeName)
}

func testGetNotFound(t *testing.T, cfg leaseSetTestConfig) {
	t.Helper()
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)

	notNil, chanOpen := cfg.getChannel(db, common.Hash{0xaa, 0xbb, 0xcc})
	assert.True(t, notNil, "Get%s should return a channel, not nil", cfg.typeName)
	assert.False(t, chanOpen, "Channel should be closed for non-existent %s", cfg.typeName)
}

func testGetBytesNotFound(t *testing.T, cfg leaseSetTestConfig) {
	t.Helper()
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)

	_, err := cfg.getBytes(db, common.Hash{0x11, 0x22, 0x33})
	assert.Error(t, err, "Get%sBytes should fail for non-existent %s", cfg.typeName, cfg.typeName)
	assert.Contains(t, err.Error(), "not found")
}

func testLeaseSetThreadSafety(t *testing.T, cfg leaseSetTestConfig) {
	t.Helper()
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)
	require.NoError(t, db.Create())

	const numGoroutines = 10
	const numOperations = 20

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				hash := common.Hash{}
				hash[0] = byte(id)
				hash[1] = byte(j)
				cfg.threadSafeOps(db, hash, []byte{byte(id), byte(j)})
			}
		}(i)
	}

	wg.Wait()
	t.Logf("%s thread safety test completed successfully", cfg.typeName)
}

func testConcurrentStoreAndRetrieve(t *testing.T, cfg leaseSetTestConfig) {
	t.Helper()
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)
	require.NoError(t, db.Create())

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		cfg.concurrentOps(db, common.Hash{0x01}, 0x01)
	}()
	go func() {
		defer wg.Done()
		cfg.concurrentOps(db, common.Hash{0x02}, 0x02)
	}()

	wg.Wait()
}
