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

	// A full Start/Stop/Close cycle tears down the router's bootstrap, which
	// spawns hundreds of goroutines that drain over a few seconds after Close()
	// returns (the count is still ~280 at 500 ms but ~2 once fully settled). A
	// fixed short settle window therefore samples a still-drifting count and the
	// per-round delta is dominated by drain noise, so the test flakes.
	//
	// settleStable establishes the baseline: it polls until the count is stable
	// for several consecutive readings (or a deadline passes). The baseline is
	// the genuinely stable low floor (the test goroutine plus GC), so a
	// stability check is the right signal there.
	settleStable := func() int {
		const (
			maxWait      = 15 * time.Second
			stableNeeded = 3 // consecutive equal readings
		)
		deadline := time.Now().Add(maxWait)
		prev := -1
		stable := 0
		count := runtime.NumGoroutine()
		for time.Now().Before(deadline) {
			time.Sleep(100 * time.Millisecond)
			runtime.GC()
			count = runtime.NumGoroutine()
			if count == prev {
				stable++
				if stable >= stableNeeded {
					return count
				}
			} else {
				stable = 0
			}
			prev = count
		}
		return count
	}

	// settleTo polls until the count has drained back to target (or a deadline
	// passes). Unlike a stability check, it does NOT return early on a transient
	// plateau: under CPU starvation a goroutine blocked in a select on a timer /
	// context becomes runnable when its deadline fires but may not be scheduled
	// to observe it immediately, so the count can sit at base+2 for a moment
	// before draining. Waiting for the count to actually reach the baseline
	// distinguishes "fully drained" (delta 0) from "stuck elevated" (a real
	// leak, which never reaches the baseline and so waits out the deadline).
	settleTo := func(target int) int {
		const maxWait = 20 * time.Second
		deadline := time.Now().Add(maxWait)
		count := runtime.NumGoroutine()
		for time.Now().Before(deadline) {
			if count <= target {
				return count
			}
			time.Sleep(100 * time.Millisecond)
			runtime.GC()
			count = runtime.NumGoroutine()
		}
		return count
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

	base := settleStable()
	t.Logf("baseline goroutines: %d", base)

	// A per-cycle leak accumulates linearly (delta == round+1 after each round),
	// whereas transient runtime goroutines (timers, GC assists) settle back to
	// ~0 after the settle() GC loop. So the discriminating signal is the FINAL
	// round's delta: with the fix it returns to ~0; without it, it equals the
	// number of rounds. A loose per-round tolerance would miss a +1/cycle leak
	// (it stays under the bound until the very end), so we assert on the last
	// round with a tight bound.
	//
	// rounds is kept low (2) deliberately: each Start/Stop/Close cycle runs full
	// network bootstrap and is ~30s, and this test dominates the lib/router
	// package's wall-clock. Two rounds still discriminate a per-cycle leak
	// (final delta 2 > tolerance 1) from no leak (delta ~0), while leaving the
	// package ample headroom under the 10m per-package test timeout on loaded
	// CI runners (the package otherwise sits close to the limit and flakes).
	const rounds = 2
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
		after := settleTo(base)
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
