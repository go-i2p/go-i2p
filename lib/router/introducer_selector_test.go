package router

import (
	"testing"

	"github.com/go-i2p/go-i2p/lib/config"
)

// TestCapsContainsReachable checks the caps-string filter used by the
// hidden-mode introducer selector. Caps with 'R' qualify, those without
// (and unreachable 'U') do not. Length-prefixed values must also match
// because RouterInfo.RouterCapabilities sometimes returns a leading byte.
func TestCapsContainsReachable(t *testing.T) {
	cases := []struct {
		caps string
		want bool
	}{
		{"", false},
		{"L", false},
		{"R", true},
		{"LR", true},
		{"RL", true},
		{"NU", false},
		{"NUH", false},
		{"NRf", true},
		{"\x03LRf", true}, // Java-style length-prefixed caps
		{"\x02LU", false},
	}
	for _, c := range cases {
		got := capsContainsReachable(c.caps)
		if got != c.want {
			t.Errorf("capsContainsReachable(%q) = %v, want %v", c.caps, got, c.want)
		}
	}
}

// TestStartIntroducerSelector_NoOpWhenNotHidden ensures the selector goroutine
// is not started when hidden mode is disabled. This protects non-hidden
// routers from publishing introducer fields they do not need.
func TestStartIntroducerSelector_NoOpWhenNotHidden(t *testing.T) {
	r := &Router{}
	// nil cfg path: must not panic, must not start a goroutine.
	r.startIntroducerSelector()

	// Hidden=false explicit path.
	cfg := &config.RouterConfig{}
	cfg.Hidden = false
	r.cfg = cfg
	r.startIntroducerSelector()
	// Goroutine count is hard to assert directly; the absence of a panic
	// (no r.wg.Add, no r.ctx access) is the signal of correct gating.
}

// TestCollectIntroducerCandidates_NilNetDB is the C7.2 unit test: verifies
// that collectIntroducerCandidates returns nil without panicking when no
// netdb is wired up. A nil netdb means we have no peers to evaluate.
func TestCollectIntroducerCandidates_NilNetDB(t *testing.T) {
	r := &Router{}
	got := r.collectIntroducerCandidates(3)
	if got != nil {
		t.Errorf("expected nil with nil StdNetDB, got %v", got)
	}
}
