package router

import (
	"sync"
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/go-i2p/lib/transport"
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

// TestSnapshotConnectedHashes verifies the helper returns the current
// peer-hash set under the session mutex without mutating activeSessions.
func TestSnapshotConnectedHashes(t *testing.T) {
	var h1, h2 common.Hash
	h1[0] = 1
	h2[0] = 2

	r := &Router{
		sessionMutex:   sync.RWMutex{},
		activeSessions: map[common.Hash]transport.TransportSession{h1: nil, h2: nil},
	}

	snap := r.snapshotConnectedHashes()
	if len(snap) != 2 {
		t.Fatalf("snapshot size = %d, want 2", len(snap))
	}
	if _, ok := snap[h1]; !ok {
		t.Errorf("snapshot missing h1")
	}
	if _, ok := snap[h2]; !ok {
		t.Errorf("snapshot missing h2")
	}
	// Mutating snap must not touch activeSessions.
	delete(snap, h1)
	if len(r.activeSessions) != 2 {
		t.Errorf("activeSessions mutated by snapshot consumer")
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

// TestIsIntroducerCandidate_RejectsNonR verifies that isIntroducerCandidate
// rejects a zero-value RouterInfo (hash lookup fails → not a candidate). The
// caps filter (capsContainsReachable) is exercised by TestCapsContainsReachable;
// HasDialableSSU2Address is exercised by TestHasDialableSSU2Address_*.
// This test confirms the early-return on hash error.
func TestIsIntroducerCandidate_RejectsNonR(t *testing.T) {
	r := &Router{}
	var emptyHash common.Hash
	var ri router_info.RouterInfo
	// Zero-value RouterInfo has no signing key, so ri.IdentHash() returns an
	// error and isIntroducerCandidate returns false immediately.
	if r.isIntroducerCandidate(ri, emptyHash, nil, nil) {
		t.Error("expected false for zero-value RouterInfo (hash error path)")
	}
}
