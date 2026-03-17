package naming

import (
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
