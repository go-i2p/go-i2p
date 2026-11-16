package router

import (
	"runtime"
	"testing"
	"time"
)

// TestRestartNoGoroutineLeak is the I2P-A-1 regression guard: a full
// CreateRouter -> Start -> Stop -> Close cycle must not leak goroutines.
// Before the fix, each cycle leaked one goroutine — the background NS-replay-
// cache cleanup goroutine owned by the go-noise ratchet SessionManager inside
// the router's GarlicSessionManager, which was never Close()d. The leak was
// +1 per restart, which kills embedded / restart-heavy deployments over time.
//
// The assertion is deliberately loose (a small fixed tolerance) because the Go
// runtime spawns transient goroutines (timers, GC assists) that settle over a
// few hundred milliseconds; what must NOT happen is monotonic growth across
// successive cycles.
func TestRestartNoGoroutineLeak(t *testing.T) {
	if testing.Short() {
		t.Skip("restart leak probe is slow; skipped under -short")
	}

	settle := func() int {
		for i := 0; i < 10; i++ {
			time.Sleep(50 * time.Millisecond)
			runtime.GC()
		}
		return runtime.NumGoroutine()
	}

	// Warm up one full cycle so lazily-created runtime pools exist before we
	// take the baseline.
	warm := createTestRouterConfig(t.TempDir())
	w, err := CreateRouter(warm)
	if err != nil {
		t.Fatalf("warm CreateRouter: %v", err)
	}
	_ = w.Start()
	w.Stop()
	_ = w.Close()

	base := settle()
	t.Logf("baseline goroutines: %d", base)

	// A per-cycle leak accumulates linearly (delta == round+1 after each round),
	// whereas transient runtime goroutines (timers, GC assists) settle back to
	// ~0 after the settle() GC loop. So the discriminating signal is the FINAL
	// round's delta: with the fix it returns to ~0; without it, it equals the
	// number of rounds. A loose per-round tolerance would miss a +1/cycle leak
	// (it stays under the bound until the very end), so we assert on the last
	// round with a tight bound.
	const rounds = 4
	const finalTolerance = 1
	var lastDelta int
	for round := 0; round < rounds; round++ {
		cfg := createTestRouterConfig(t.TempDir())
		r, err := CreateRouter(cfg)
		if err != nil {
			t.Fatalf("round %d CreateRouter: %v", round, err)
		}
		if err := r.Start(); err != nil {
			t.Fatalf("round %d Start: %v", round, err)
		}
		r.Stop()
		if err := r.Close(); err != nil {
			t.Fatalf("round %d Close: %v", round, err)
		}
		after := settle()
		lastDelta = after - base
		t.Logf("after round %d: %d goroutines (delta %d)", round, after, lastDelta)
	}

	if lastDelta > finalTolerance {
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		t.Fatalf("goroutine leak across %d restart cycles: final delta %d > tolerance %d (a per-cycle leak accumulates to ~%d)\n=== goroutine dump ===\n%s",
			rounds, lastDelta, finalTolerance, rounds, string(buf[:n]))
	}
}
