package ssu2

import (
	"testing"

	"github.com/go-i2p/common/router_address"
	ssu2noise "github.com/go-i2p/go-noise/ssu2"
	"github.com/stretchr/testify/assert"
)

// TestParseExternalOverride pins the override grammar shared with NTCP2:
// bare IP, host:port, bracketed IPv6, and rejection of non-IP hosts.
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

// TestApplyExternalOverride covers empty (no-op), host-only (keeps bound port),
// host:port (replaces both), and invalid (ignored) override states.
func TestApplyExternalOverride(t *testing.T) {
	h, p, forced := applyExternalOverride("", "172.17.0.2", "9002")
	assert.Equal(t, "172.17.0.2", h)
	assert.Equal(t, "9002", p)
	assert.False(t, forced)

	h, p, forced = applyExternalOverride("203.0.113.7", "172.17.0.2", "9002")
	assert.Equal(t, "203.0.113.7", h)
	assert.Equal(t, "9002", p)
	assert.True(t, forced)

	h, p, forced = applyExternalOverride("203.0.113.7:8888", "172.17.0.2", "9002")
	assert.Equal(t, "203.0.113.7", h)
	assert.Equal(t, "8888", p)
	assert.True(t, forced)

	h, p, forced = applyExternalOverride("garbage", "172.17.0.2", "9002")
	assert.Equal(t, "172.17.0.2", h)
	assert.Equal(t, "9002", p)
	assert.False(t, forced)
}

// TestBuildSSU2Options_ForcedBypassesIntroducerBranch is the SSU2 half of the
// Gap C fix: a private host with a usable introducer would normally publish
// introducer-only (no host/port); when forced=true it must publish host=/port=
// directly instead.
func TestBuildSSU2Options_ForcedBypassesIntroducerBranch(t *testing.T) {
	tr := emptyIntroducerTransport(t)
	intros := []*ssu2noise.RegisteredIntroducer{makeUsableIntroducer(t, 7)}

	// Not forced: private host + introducer => introducer-only, no host.
	introOnly := buildSSU2Options("10.0.0.5", "9002", tr, intros, false)
	assert.NotContains(t, introOnly, router_address.HOST_OPTION_KEY,
		"private host with introducer must be introducer-only when not forced")

	// Forced: same host publishes host=/port= directly.
	pub := buildSSU2Options("203.0.113.7", "9002", tr, intros, true)
	assert.Equal(t, "203.0.113.7", pub[router_address.HOST_OPTION_KEY])
	assert.Equal(t, "9002", pub[router_address.PORT_OPTION_KEY])
}
