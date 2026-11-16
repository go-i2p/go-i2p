package i2np

import (
	"testing"
)

// TestBuildMessageID_IsRandomNotUniform is the C4 guard for I2P-B-4: build
// request message IDs must be cryptographically random, not uniform/constant.
// A constant or sequential ID is a cheap observer correlation marker on tunnel
// builds. generateMessageID does not use its receiver, so a nil *TunnelManager
// is a valid caller.
func TestBuildMessageID_IsRandomNotUniform(t *testing.T) {
	var tm *TunnelManager

	const n = 1000
	seen := make(map[int]struct{}, n)
	first, err := tm.generateMessageID()
	if err != nil {
		t.Fatalf("generateMessageID error: %v", err)
	}
	seen[first] = struct{}{}

	allSame := true
	for i := 0; i < n; i++ {
		id, err := tm.generateMessageID()
		if err != nil {
			t.Fatalf("generateMessageID error: %v", err)
		}
		if id != first {
			allSame = false
		}
		seen[id] = struct{}{}
	}

	if allSame {
		t.Fatal("all build message IDs are identical — uniform IDs are a correlation marker (I2P-B-4)")
	}

	// With a 32-bit crypto/rand space, 1000 draws should be essentially all
	// distinct. A tiny unique count would indicate a weak/sequential source.
	if len(seen) < n*9/10 {
		t.Fatalf("only %d/%d distinct message IDs — source looks non-random", len(seen), n+1)
	}
}

// TestBuildMessageID_ConsecutiveDiffer verifies consecutive calls return
// different IDs, which is what guarantees a retried build (a fresh
// generateMessageID call) is not self-suppressed by ID reuse.
func TestBuildMessageID_ConsecutiveDiffer(t *testing.T) {
	var tm *TunnelManager

	prev, err := tm.generateMessageID()
	if err != nil {
		t.Fatalf("generateMessageID error: %v", err)
	}
	for i := 0; i < 100; i++ {
		next, err := tm.generateMessageID()
		if err != nil {
			t.Fatalf("generateMessageID error: %v", err)
		}
		if next == prev {
			t.Fatalf("consecutive build message IDs collided at iteration %d (id=%d)", i, next)
		}
		prev = next
	}
}
