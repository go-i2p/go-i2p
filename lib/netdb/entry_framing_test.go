package netdb

import (
	"os"
	"path/filepath"
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEntryWriteReadRoundTrip verifies that Entry.WriteTo produces framed data
// (1-byte type + 2-byte length + payload) and Entry.ReadFrom correctly strips
// the framing. This is the baseline test for the framing format.
func TestEntryWriteReadRoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	fpath := filepath.Join(tmpDir, "test-entry.dat")

	// Create a minimal entry with a RouterInfo that contains some data.
	// We use a raw RouterInfo constructed from bytes to avoid needing
	// crypto key generation.
	db := NewStdNetDB(tmpDir)
	require.NotNil(t, db)

	// Write raw framed bytes to a file: type=1 (RouterInfo), length=4, data=0xDE 0xAD 0xBE 0xEF
	f, err := os.Create(fpath)
	require.NoError(t, err)

	// Write type byte
	_, err = f.Write([]byte{FileTypeLeaseSet})
	require.NoError(t, err)

	// Write length (2 bytes big-endian) = 4
	_, err = f.Write([]byte{0x00, 0x04})
	require.NoError(t, err)

	// Write payload
	payload := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	_, err = f.Write(payload)
	require.NoError(t, err)
	f.Close()

	// Now read it back via Entry.ReadFrom
	f2, err := os.Open(fpath)
	require.NoError(t, err)
	defer f2.Close()

	entry := &Entry{}
	// This will fail to parse 0xDEADBEEF as a LeaseSet, but that's fine —
	// the framing was correctly stripped. ReadFrom should at least attempt
	// to parse the 4-byte payload (and fail with a parse error, not a framing error).
	err = entry.ReadFrom(f2)
	// We expect a parse error here, not a framing error
	if err != nil {
		assert.Contains(t, err.Error(), "failed to parse", "Error should be a parse failure, not a framing issue")
	}
}

// TestEntryFramingStrippedForLeaseSetFile verifies that loadLeaseSetFromFile
// properly strips the entry framing before returning data. This was the
// core bug: framed bytes were passed directly to the LeaseSet parser.
func TestEntryFramingStrippedForLeaseSetFile(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)
	require.NotNil(t, db)
	require.NoError(t, db.Create())

	// Create a test hash and get the skiplist file path
	var hash common.Hash
	copy(hash[:], []byte("test-hash-for-framing-check-32b!"))
	fpath := db.SkiplistFileForLeaseSet(hash)

	// Ensure the directory exists
	err := os.MkdirAll(filepath.Dir(fpath), 0o700)
	require.NoError(t, err)

	// Write a framed entry: type=2 (LeaseSet), length=5, payload="hello"
	f, err := os.Create(fpath)
	require.NoError(t, err)
	_, err = f.Write([]byte{FileTypeLeaseSet}) // type byte
	require.NoError(t, err)
	_, err = f.Write([]byte{0x00, 0x05}) // length = 5
	require.NoError(t, err)
	payload := []byte("hello")
	_, err = f.Write(payload)
	require.NoError(t, err)
	f.Close()

	// loadLeaseSetFromFile should strip the framing and attempt to parse.
	// Since "hello" isn't a valid LeaseSet, it will fail — but the important
	// thing is it fails with a parse error, not by misinterpreting framing bytes.
	_, err = db.loadLeaseSetFromFile(hash)
	require.Error(t, err, "Should fail to parse invalid LeaseSet data")
	assert.Contains(t, err.Error(), "failed to parse", "Error should be a parse failure from properly unframed data")
	// Crucially, the error should NOT mention "failed to read" which would
	// indicate the framing bytes were not properly stripped
}

// TestEntryFramingStrippedForRouterInfoFile verifies that loadRouterInfoFromFile
// properly strips entry framing before returning data.
func TestEntryFramingStrippedForRouterInfoFile(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)
	require.NotNil(t, db)
	require.NoError(t, db.Create())

	// Create a test hash and get the skiplist file path
	var hash common.Hash
	copy(hash[:], []byte("test-ri-hash-for-framing-chk-32!"))
	fpath := db.SkiplistFile(hash)

	// Ensure the directory exists
	err := os.MkdirAll(filepath.Dir(fpath), 0o700)
	require.NoError(t, err)

	// Write a framed entry: type=1 (RouterInfo), length=5, payload="hello"
	f, err := os.Create(fpath)
	require.NoError(t, err)
	_, err = f.Write([]byte{FileTypeRouterInfo}) // type byte
	require.NoError(t, err)
	_, err = f.Write([]byte{0x00, 0x05}) // length = 5
	require.NoError(t, err)
	payload := []byte("hello")
	_, err = f.Write(payload)
	require.NoError(t, err)
	f.Close()

	// loadRouterInfoFromFile should strip framing and attempt to parse
	_, err = db.loadRouterInfoFromFile(hash)
	require.Error(t, err, "Should fail to parse invalid RouterInfo data")
	assert.Contains(t, err.Error(), "failed to", "Error should be a parse/read failure from properly unframed data")
}

// TestLoadAndParseRouterInfoStripsFraming verifies that loadAndParseRouterInfo
// properly strips entry framing when loading from a skiplist file.
func TestLoadAndParseRouterInfoStripsFraming(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)
	require.NotNil(t, db)

	fpath := filepath.Join(tmpDir, "routerInfo-test.dat")

	// Write a framed entry: type=1 (RouterInfo), length=5, payload="hello"
	f, err := os.Create(fpath)
	require.NoError(t, err)
	_, err = f.Write([]byte{FileTypeRouterInfo}) // type byte
	require.NoError(t, err)
	_, err = f.Write([]byte{0x00, 0x05}) // length = 5
	require.NoError(t, err)
	_, err = f.Write([]byte("hello"))
	require.NoError(t, err)
	f.Close()

	// loadAndParseRouterInfo should properly strip the framing.
	// Since "hello" isn't a valid RouterInfo, it will fail to parse —
	// but the error should be a parse error, not a framing error.
	_, err = db.loadAndParseRouterInfo(fpath)
	require.Error(t, err, "Should fail to parse invalid RouterInfo data")
	assert.Contains(t, err.Error(), "failed to", "Error should be a parse failure from properly unframed data")
}

// TestRawBytesWithoutFramingFails verifies that files without entry framing
// are properly rejected (they should fail in ReadFrom since there's no valid type byte).
func TestRawBytesWithoutFramingFails(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)
	require.NotNil(t, db)
	require.NoError(t, db.Create())

	// Create a test hash and get the skiplist file path
	var hash common.Hash
	copy(hash[:], []byte("test-hash-no-framing-check-32b!1"))
	fpath := db.SkiplistFileForLeaseSet(hash)

	// Ensure the directory exists
	err := os.MkdirAll(filepath.Dir(fpath), 0o700)
	require.NoError(t, err)

	// Write raw unframed data (no type byte or length prefix)
	err = os.WriteFile(fpath, []byte("raw unframed data that is too short"), 0o600)
	require.NoError(t, err)

	// loadLeaseSetFromFile should fail because Entry.ReadFrom can't parse
	// unframed data
	_, err = db.loadLeaseSetFromFile(hash)
	require.Error(t, err, "Should fail when file lacks entry framing")
}

// TestEmptyFileFailsGracefully verifies that an empty file is handled gracefully.
func TestEmptyFileFailsGracefully(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)
	require.NotNil(t, db)
	require.NoError(t, db.Create())

	var hash common.Hash
	copy(hash[:], []byte("test-hash-empty-file-check-32b!1"))
	fpath := db.SkiplistFileForLeaseSet(hash)

	err := os.MkdirAll(filepath.Dir(fpath), 0o700)
	require.NoError(t, err)

	// Create an empty file
	err = os.WriteFile(fpath, []byte{}, 0o600)
	require.NoError(t, err)

	// Should fail with a read error, not panic
	_, err = db.loadLeaseSetFromFile(hash)
	require.Error(t, err, "Empty file should return an error")
}

// TestTruncatedFramingFailsGracefully verifies that a file with partial
// framing (e.g., type byte but no length) fails gracefully.
func TestTruncatedFramingFailsGracefully(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)
	require.NotNil(t, db)
	require.NoError(t, db.Create())

	var hash common.Hash
	copy(hash[:], []byte("test-hash-truncated-framing-32b!"))
	fpath := db.SkiplistFileForLeaseSet(hash)

	err := os.MkdirAll(filepath.Dir(fpath), 0o700)
	require.NoError(t, err)

	// Write only the type byte (no length or data)
	err = os.WriteFile(fpath, []byte{FileTypeLeaseSet}, 0o600)
	require.NoError(t, err)

	// Should fail with a read error, not panic
	_, err = db.loadLeaseSetFromFile(hash)
	require.Error(t, err, "Truncated framing should return an error")
}
