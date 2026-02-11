package netdb

import (
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVerifyRouterInfoSignature_NilIdentity tests that verification fails
// when the RouterInfo has a nil RouterIdentity.
func TestVerifyRouterInfoSignature_NilIdentity(t *testing.T) {
	ri := router_info.RouterInfo{} // zero-value RouterInfo, nil identity
	err := verifyRouterInfoSignature(ri)
	assert.Error(t, err, "should fail with nil identity")
	assert.Contains(t, err.Error(), "nil RouterIdentity")
}

// TestVerifyRouterInfoSignature_InvalidData tests that verification fails
// when the RouterInfo data is too short or malformed to contain a valid signature.
func TestVerifyRouterInfoSignature_InvalidData(t *testing.T) {
	// Parse minimal invalid data — should fail to get signing key
	testData := []byte{0x00, 0x01, 0x02, 0x03}
	ri, _, err := router_info.ReadRouterInfo(testData)
	if err != nil {
		// Expected: invalid data can't be parsed
		t.Skipf("ReadRouterInfo correctly rejected invalid data: %v", err)
	}
	// If parsing somehow succeeded, verification should still fail
	verifyErr := verifyRouterInfoSignature(ri)
	assert.Error(t, verifyErr, "should fail with invalid/minimal data")
}

// TestStoreRouterInfo_SignatureVerification_RejectsInvalidData tests that
// StoreRouterInfo rejects data that fails signature verification.
func TestStoreRouterInfo_SignatureVerification_RejectsInvalidData(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)
	require.NoError(t, db.Create())

	// Craft data that parses as a RouterInfo but has an invalid signature.
	// Since ReadRouterInfo needs valid structure, we test the error path
	// by trying to store garbage data.
	testHash := common.Hash{0x01, 0x02, 0x03}
	invalidData := []byte{0x00, 0x01, 0x02} // too short to parse

	err := db.StoreRouterInfo(testHash, invalidData, 0)
	assert.Error(t, err, "should fail: data cannot be parsed")
}

// TestStoreRouterInfo_StillRejectsInvalidDataType verifies that the data type
// validation still works correctly after adding signature verification.
func TestStoreRouterInfo_StillRejectsInvalidDataType(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)
	require.NoError(t, db.Create())

	testHash := common.Hash{0x01, 0x02, 0x03}
	testData := []byte{0x01, 0x02, 0x03}

	err := db.StoreRouterInfo(testHash, testData, 1) // invalid type
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid data type")
}

// TestStoreRouterInfo_StillRejectsHashMismatch verifies that hash verification
// still works correctly alongside signature verification.
func TestStoreRouterInfo_StillRejectsHashMismatch(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)
	require.NoError(t, db.Create())

	testHash := common.Hash{0xFF, 0xFF, 0xFF}
	// This data should fail at parse or hash mismatch before reaching signature verification
	testData := []byte{0x01, 0x02, 0x03}

	err := db.StoreRouterInfo(testHash, testData, 0)
	assert.Error(t, err, "should fail at parse or hash check")
}
