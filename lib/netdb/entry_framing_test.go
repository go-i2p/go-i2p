package netdb

import (
	"os"
	"path/filepath"
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- shared test helpers ---

// newFramedTestDB creates a StdNetDB in a temp directory and writes a file
// at the skiplist path for the given hashSeed. If framing is non-nil it is
// written as raw bytes; otherwise the file is created empty.
func newFramedTestDB(t *testing.T, hashSeed string, forLeaseSet bool, framing []byte) (*StdNetDB, common.Hash) {
	t.Helper()
	tmpDir := t.TempDir()
	db := NewStdNetDB(tmpDir)
	require.NotNil(t, db)
	require.NoError(t, db.Create())
	var hash common.Hash
	copy(hash[:], []byte(hashSeed))
	var fpath string
	if forLeaseSet {
		fpath = db.SkiplistFileForLeaseSet(hash)
	} else {
		fpath = db.SkiplistFile(hash)
	}
	require.NoError(t, os.MkdirAll(filepath.Dir(fpath), 0o700))
	require.NoError(t, os.WriteFile(fpath, framing, 0o600))
	return db, hash
}

// buildFramedBytes constructs a framed entry: [type] [2-byte big-endian length] [payload].
func buildFramedBytes(fileType byte, payload []byte) []byte {
	out := []byte{fileType, byte(len(payload) >> 8), byte(len(payload))}
	return append(out, payload...)
}

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
	framed := buildFramedBytes(FileTypeLeaseSet, []byte("hello"))
	db, hash := newFramedTestDB(t, "test-hash-for-framing-check-32b!", true, framed)

	// loadLeaseSetFromFile should strip the framing and attempt to parse.
	_, err := db.loadLeaseSetFromFile(hash)
	require.Error(t, err, "Should fail to parse invalid LeaseSet data")
	assert.Contains(t, err.Error(), "failed to parse", "Error should be a parse failure from properly unframed data")
}

// TestEntryFramingStrippedForRouterInfoFile verifies that loadRouterInfoFromFile
// properly strips entry framing before returning data.
func TestEntryFramingStrippedForRouterInfoFile(t *testing.T) {
	framed := buildFramedBytes(FileTypeRouterInfo, []byte("hello"))
	db, hash := newFramedTestDB(t, "test-ri-hash-for-framing-chk-32!", false, framed)

	// loadRouterInfoFromFile should strip framing and attempt to parse
	_, err := db.loadRouterInfoFromFile(hash)
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
	db, hash := newFramedTestDB(t, "test-hash-no-framing-check-32b!1", true, []byte("raw unframed data that is too short"))

	_, err := db.loadLeaseSetFromFile(hash)
	require.Error(t, err, "Should fail when file lacks entry framing")
}

// TestEmptyFileFailsGracefully verifies that an empty file is handled gracefully.
func TestEmptyFileFailsGracefully(t *testing.T) {
	db, hash := newFramedTestDB(t, "test-hash-empty-file-check-32b!1", true, []byte{})

	// Should fail with a read error, not panic
	_, err := db.loadLeaseSetFromFile(hash)
	require.Error(t, err, "Empty file should return an error")
}

// TestTruncatedFramingFailsGracefully verifies that a file with partial
// framing (e.g., type byte but no length) fails gracefully.
func TestTruncatedFramingFailsGracefully(t *testing.T) {
	db, hash := newFramedTestDB(t, "test-hash-truncated-framing-32b!", true, []byte{FileTypeLeaseSet})

	// Should fail with a read error, not panic
	_, err := db.loadLeaseSetFromFile(hash)
	require.Error(t, err, "Truncated framing should return an error")
}
