package naming

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHostsTxtResolver(t *testing.T) {
	r, err := NewHostsTxtResolver()
	require.NoError(t, err)
	require.NotNil(t, r)
	assert.Equal(t, 68, r.Size(), "expected 68 entries from default hosts.txt")
}

func TestResolveKnownHostname(t *testing.T) {
	r, err := NewHostsTxtResolver()
	require.NoError(t, err)

	dest, err := r.ResolveHostname("zzz.i2p")
	require.NoError(t, err)
	assert.NotEmpty(t, dest, "zzz.i2p should resolve to non-empty bytes")
}

func TestResolveUnknownHostname(t *testing.T) {
	r, err := NewHostsTxtResolver()
	require.NoError(t, err)

	dest, err := r.ResolveHostname("nonexistent.i2p")
	assert.Error(t, err)
	assert.Nil(t, dest)
}

func TestResolveReturnsCopy(t *testing.T) {
	r, err := NewHostsTxtResolver()
	require.NoError(t, err)

	dest1, err := r.ResolveHostname("stats.i2p")
	require.NoError(t, err)

	dest2, err := r.ResolveHostname("stats.i2p")
	require.NoError(t, err)

	// Mutate the first result
	dest1[0] ^= 0xFF

	// Second result should be unaffected
	assert.NotEqual(t, dest1[0], dest2[0], "ResolveHostname should return independent copies")
}

func TestParseHostsLineValid(t *testing.T) {
	line := "test.i2p=AAAA"
	hostname, dest, err := parseHostsLine(line)
	require.NoError(t, err)
	assert.Equal(t, "test.i2p", hostname)
	assert.NotEmpty(t, dest)
}

func TestParseHostsLineInvalid(t *testing.T) {
	tests := []struct {
		name string
		line string
	}{
		{"no separator", "nohostname"},
		{"empty hostname", "=AAAA"},
		{"empty destination", "test.i2p="},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := parseHostsLine(tt.line)
			assert.Error(t, err)
		})
	}
}

func TestResolverFromDataWithComments(t *testing.T) {
	data := []byte("# comment line\n\ntest.i2p=AAAA\n# another comment\n")
	r, err := newResolverFromData(data)
	require.NoError(t, err)
	assert.Equal(t, 1, r.Size())
}

func TestAllDefaultHostsResolve(t *testing.T) {
	r, err := NewHostsTxtResolver()
	require.NoError(t, err)

	knownHosts := []string{
		"smtp.postman.i2p",
		"pop.postman.i2p",
		"zzz.i2p",
		"i2p-projekt.i2p",
		"stats.i2p",
		"echelon.i2p",
		"idk.i2p",
		"stormycloud.i2p",
		"ramble.i2p",
		"skank.i2p",
	}

	for _, host := range knownHosts {
		dest, err := r.ResolveHostname(host)
		assert.NoError(t, err, "should resolve %s", host)
		assert.NotEmpty(t, dest, "%s should have non-empty destination", host)
	}
}

// --- B32 address resolution tests ---

func TestResolveB32Address_Valid(t *testing.T) {
	// Valid 52-character base32 address (lowercase, no padding)
	b32Addr := "ukeu3k5oycgaauneqgtnvselmt4yemvoilkln7jpvamvfx7dnkdq.b32.i2p"

	hash, err := ResolveB32Address(b32Addr)
	require.NoError(t, err)
	assert.Len(t, hash, 32, "decoded hash should be 32 bytes")
}

func TestResolveB32Address_WithoutSuffix(t *testing.T) {
	// Just the hash part without .b32.i2p suffix
	b32Hash := "ukeu3k5oycgaauneqgtnvselmt4yemvoilkln7jpvamvfx7dnkdq"

	hash, err := ResolveB32Address(b32Hash)
	require.NoError(t, err)
	assert.Len(t, hash, 32, "decoded hash should be 32 bytes")
}

func TestResolveB32Address_InvalidLength(t *testing.T) {
	// Too short
	_, err := ResolveB32Address("abc.b32.i2p")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid b32 address length")
}

func TestResolveB32Address_InvalidEncoding(t *testing.T) {
	// Invalid characters (1, 0, 8, 9 are not in I2P's base32 alphabet)
	_, err := ResolveB32Address("0000000000000000000000000000000000000000000000000000.b32.i2p")
	assert.Error(t, err)
}

func TestDestinationToB32(t *testing.T) {
	// Create some test destination bytes
	destBytes := make([]byte, 387) // Typical destination size
	for i := range destBytes {
		destBytes[i] = byte(i)
	}

	b32Addr := DestinationToB32(destBytes)

	// Should end with .b32.i2p
	assert.True(t, strings.HasSuffix(b32Addr, ".b32.i2p"))

	// Should be 52 chars + ".b32.i2p" = 60 chars total
	assert.Len(t, b32Addr, 60)

	// Should be lowercase
	assert.Equal(t, strings.ToLower(b32Addr), b32Addr)
}

func TestResolve_B32Address(t *testing.T) {
	r, err := NewHostsTxtResolver()
	require.NoError(t, err)

	// Resolve a b32 address
	hash, isHash, err := r.Resolve("ukeu3k5oycgaauneqgtnvselmt4yemvoilkln7jpvamvfx7dnkdq.b32.i2p")
	require.NoError(t, err)
	assert.True(t, isHash, "b32 address should return isHash=true")
	assert.Len(t, hash, 32)
}

func TestResolve_Hostname(t *testing.T) {
	r, err := NewHostsTxtResolver()
	require.NoError(t, err)

	// Resolve a regular hostname
	dest, isHash, err := r.Resolve("zzz.i2p")
	require.NoError(t, err)
	assert.False(t, isHash, "hostname should return isHash=false")
	assert.NotEmpty(t, dest)
}

func TestResolve_UnknownHostname(t *testing.T) {
	r, err := NewHostsTxtResolver()
	require.NoError(t, err)

	_, _, err = r.Resolve("nonexistent.i2p")
	assert.Error(t, err)
}

// --- Address book loading tests ---

func TestAddHostsFile_Success(t *testing.T) {
	r, err := NewHostsTxtResolver()
	require.NoError(t, err)

	initialSize := r.Size()

	// Create a temporary hosts file
	tmpFile := t.TempDir() + "/custom-hosts.txt"
	customHosts := "custom1.i2p=AAAA\ncustom2.i2p=BBBB\n"
	err = os.WriteFile(tmpFile, []byte(customHosts), 0o644)
	require.NoError(t, err)

	err = r.AddHostsFile(tmpFile)
	require.NoError(t, err)

	assert.Equal(t, initialSize+2, r.Size(), "should have added 2 entries")

	// Verify custom entries are resolvable
	_, err = r.ResolveHostname("custom1.i2p")
	assert.NoError(t, err)
}

func TestAddHostsFile_NotFound(t *testing.T) {
	r, err := NewHostsTxtResolver()
	require.NoError(t, err)

	err = r.AddHostsFile("/nonexistent/path/hosts.txt")
	assert.Error(t, err)
}

func TestLoadAddressBooksFromDir(t *testing.T) {
	r, err := NewHostsTxtResolver()
	require.NoError(t, err)

	initialSize := r.Size()

	// Create a temp directory with multiple hosts files
	tmpDir := t.TempDir()

	// First file
	err = os.WriteFile(tmpDir+"/hosts1.txt", []byte("host1.i2p=AAAA\n"), 0o644)
	require.NoError(t, err)

	// Second file
	err = os.WriteFile(tmpDir+"/hosts2.txt", []byte("host2.i2p=BBBB\n"), 0o644)
	require.NoError(t, err)

	// Non-.txt file (should be ignored)
	err = os.WriteFile(tmpDir+"/readme.md", []byte("not a hosts file"), 0o644)
	require.NoError(t, err)

	err = r.LoadAddressBooksFromDir(tmpDir)
	require.NoError(t, err)

	assert.Equal(t, initialSize+2, r.Size(), "should have added 2 entries from .txt files")
}

func TestLoadAddressBooksFromDir_NonexistentDir(t *testing.T) {
	r, err := NewHostsTxtResolver()
	require.NoError(t, err)

	// Should not error for nonexistent directory
	err = r.LoadAddressBooksFromDir("/nonexistent/directory")
	assert.NoError(t, err)
}
