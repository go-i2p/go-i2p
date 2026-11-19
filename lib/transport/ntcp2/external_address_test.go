package ntcp2

import (
	"testing"

	ntcp2noise "github.com/go-i2p/go-noise/ntcp2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseExternalOverride pins the override grammar: bare IP, host:port,
// bracketed IPv6, and rejection of non-IP hosts.
func TestParseExternalOverride(t *testing.T) {
	cases := []struct {
		in       string
		wantHost string
		wantPort string
		wantOK   bool
	}{
		{"203.0.113.7", "203.0.113.7", "", true},
		{"203.0.113.7:8888", "203.0.113.7", "8888", true},
		{"[2001:db8::1]:9001", "2001:db8::1", "9001", true},
		{"2001:db8::1", "2001:db8::1", "", true},
		{"not-an-ip", "", "", false},
		{"", "", "", false},
	}
	for _, c := range cases {
		h, p, ok := parseExternalOverride(c.in)
		assert.Equal(t, c.wantOK, ok, "input %q ok", c.in)
		if c.wantOK {
			assert.Equal(t, c.wantHost, h, "input %q host", c.in)
			assert.Equal(t, c.wantPort, p, "input %q port", c.in)
		}
	}
}

// TestApplyExternalOverride covers the three override states: empty (no-op),
// host-only (keeps bound port), and host:port (replaces both).
func TestApplyExternalOverride(t *testing.T) {
	// Empty override: auto-detection preserved, not forced.
	h, p, forced := applyExternalOverride("", "172.17.0.2", "42069")
	assert.Equal(t, "172.17.0.2", h)
	assert.Equal(t, "42069", p)
	assert.False(t, forced)

	// Host-only override: host replaced, bound port kept, forced.
	h, p, forced = applyExternalOverride("203.0.113.7", "172.17.0.2", "42069")
	assert.Equal(t, "203.0.113.7", h)
	assert.Equal(t, "42069", p)
	assert.True(t, forced)

	// Host:port override: both replaced, forced.
	h, p, forced = applyExternalOverride("203.0.113.7:8888", "172.17.0.2", "42069")
	assert.Equal(t, "203.0.113.7", h)
	assert.Equal(t, "8888", p)
	assert.True(t, forced)

	// Invalid override: ignored, not forced.
	h, p, forced = applyExternalOverride("garbage", "172.17.0.2", "42069")
	assert.Equal(t, "172.17.0.2", h)
	assert.Equal(t, "42069", p)
	assert.False(t, forced)
}

// TestBuildRouterAddressOptions_ForcedPublishesPrivateHost is the core of the
// Gap C fix: a private/unspecified host that would otherwise produce a
// caps-only address must publish host=/port= when forced=true.
func TestBuildRouterAddressOptions_ForcedPublishesPrivateHost(t *testing.T) {
	cfg := &ntcp2noise.Config{ObfuscationIV: make([]byte, 16)}

	// Without forcing, a private host yields caps-only (no host/port).
	capsOnly, err := buildRouterAddressOptions("172.17.0.2", "42069", "statickey", cfg, false)
	require.NoError(t, err)
	_, hasHost := capsOnly["host"]
	assert.False(t, hasHost, "private host must be caps-only when not forced")

	// With forcing, the same host publishes host=/port=.
	pub, err := buildRouterAddressOptions("203.0.113.7", "42069", "statickey", cfg, true)
	require.NoError(t, err)
	assert.Equal(t, "203.0.113.7", pub["host"])
	assert.Equal(t, "42069", pub["port"])
	assert.NotEmpty(t, pub["i"], "published address must carry the IV")
}
