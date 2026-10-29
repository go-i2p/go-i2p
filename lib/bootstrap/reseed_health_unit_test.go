// Copyright (c) 2026, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
// COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
// TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package bootstrap

import (
	"math"
	"reflect"
	"testing"
	"time"
)

// approxEqual reports whether a and b are within tol of each other.
func approxEqual(a, b, tol float64) bool {
	return math.Abs(a-b) <= tol
}

func TestReseedHealthScoreUnknownServer(t *testing.T) {
	tr := newReseedHealthTracker()
	if got := tr.score("https://unknown/"); got != healthBaselineScore {
		t.Errorf("score(unknown) = %v, want baseline %v", got, healthBaselineScore)
	}
}

func TestReseedHealthScoreFastSuccess(t *testing.T) {
	tr := newReseedHealthTracker()
	tr.recordSuccess("https://fast/", time.Second)
	// successRate=1, latencyFactor=1 (1s <= target), penalty=0 -> 1.0
	if got := tr.score("https://fast/"); !approxEqual(got, 1.0, 1e-9) {
		t.Errorf("score(fast success) = %v, want 1.0", got)
	}
}

func TestReseedHealthScoreSlowSuccess(t *testing.T) {
	tr := newReseedHealthTracker()
	// 25s is beyond 2x the 10s target, so latency credit is 0.
	tr.recordSuccess("https://slow/", 25*time.Second)
	// successRate=1, latencyFactor=0 -> base=0.75, penalty=0 -> 0.75
	if got := tr.score("https://slow/"); !approxEqual(got, 0.75, 1e-9) {
		t.Errorf("score(slow success) = %v, want 0.75", got)
	}
}

func TestReseedHealthScoreFailure(t *testing.T) {
	tr := newReseedHealthTracker()
	tr.recordFailure("https://bad/")
	// successRate=0, latencyFactor=1 (no duration recorded), base=0.25, penalty=0.25 -> 0.0
	if got := tr.score("https://bad/"); !approxEqual(got, 0.0, 1e-9) {
		t.Errorf("score(failure) = %v, want 0.0", got)
	}
}

func TestReseedHealthScoreConsecutiveFailuresCapped(t *testing.T) {
	tr := newReseedHealthTracker()
	for i := 0; i < 10; i++ {
		tr.recordFailure("https://dead/")
	}
	// Penalty is capped at 0.75, so the score floors at 0 rather than going negative.
	if got := tr.score("https://dead/"); got < 0 || got > 1 {
		t.Errorf("score after many failures = %v, want within [0,1]", got)
	}
	if got := tr.score("https://dead/"); !approxEqual(got, 0.0, 1e-9) {
		t.Errorf("score after many failures = %v, want 0.0", got)
	}
}

func TestReseedHealthScoreMixed(t *testing.T) {
	tr := newReseedHealthTracker()
	// 3 fast successes then 1 failure.
	tr.recordSuccess("https://mixed/", time.Second)
	tr.recordSuccess("https://mixed/", time.Second)
	tr.recordSuccess("https://mixed/", time.Second)
	tr.recordFailure("https://mixed/")
	// successRate=3/4=0.75, latencyFactor=1, base=0.75*0.75+0.25*1=0.8125, penalty=0.25 -> 0.5625
	if got := tr.score("https://mixed/"); !approxEqual(got, 0.5625, 1e-9) {
		t.Errorf("score(mixed) = %v, want 0.5625", got)
	}
}

func TestReseedHealthScoreRecoversAfterFailure(t *testing.T) {
	tr := newReseedHealthTracker()
	tr.recordFailure("https://flaky/")
	tr.recordSuccess("https://flaky/", time.Second)
	// A success resets the consecutive-failure streak, so the penalty disappears.
	// successRate=1/2=0.5, latencyFactor=1, base=0.75*0.5+0.25*1=0.625, penalty=0 -> 0.625
	if got := tr.score("https://flaky/"); !approxEqual(got, 0.625, 1e-9) {
		t.Errorf("score(recovered) = %v, want 0.625", got)
	}
}

func TestReseedHealthRankOrdersByScore(t *testing.T) {
	tr := newReseedHealthTracker()
	tr.recordSuccess("https://good/", time.Second) // 1.0
	tr.recordFailure("https://bad/")               // 0.0
	// https://unknown/ has no history -> 0.5

	// Input order is arbitrary; ranking must be by score regardless.
	got := tr.rank([]string{"https://bad/", "https://unknown/", "https://good/"})
	want := []string{"https://good/", "https://unknown/", "https://bad/"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("rank() = %v, want %v", got, want)
	}
}

func TestReseedHealthRankPreservesOrderForEqualScores(t *testing.T) {
	tr := newReseedHealthTracker()
	// No history: all scores equal (baseline), so the stable sort preserves input order.
	input := []string{"https://a/", "https://b/", "https://c/"}
	got := tr.rank(input)
	if !reflect.DeepEqual(got, input) {
		t.Errorf("rank() with equal scores = %v, want input order preserved %v", got, input)
	}
	// Input must not be mutated.
	if !reflect.DeepEqual(input, []string{"https://a/", "https://b/", "https://c/"}) {
		t.Errorf("rank() mutated its input: %v", input)
	}
}

func TestReseedHealthSnapshot(t *testing.T) {
	tr := newReseedHealthTracker()
	tr.recordSuccess("https://a/", time.Second)
	tr.recordFailure("https://b/")

	snap := tr.snapshot()
	if len(snap) != 2 {
		t.Fatalf("snapshot() has %d entries, want 2", len(snap))
	}
	if snap["https://a/"].successes != 1 || snap["https://a/"].attempts != 1 {
		t.Errorf("snapshot[a] = %+v, want 1 success / 1 attempt", snap["https://a/"])
	}
	if snap["https://b/"].consecutiveFails != 1 {
		t.Errorf("snapshot[b].consecutiveFails = %d, want 1", snap["https://b/"].consecutiveFails)
	}

	// Mutating the snapshot must not affect the tracker.
	mutated := snap["https://a/"]
	mutated.successes = 99
	snap["https://a/"] = mutated
	if got := tr.score("https://a/"); !approxEqual(got, 1.0, 1e-9) {
		t.Errorf("score changed after snapshot mutation: %v", got)
	}
}

func TestLatencyCredit(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want float64
	}{
		{0, 1.0},                       // unknown duration -> full credit
		{time.Second, 1.0},             // at/below target -> full credit
		{healthLatencyTarget, 1.0},     // exactly at target -> full credit
		{15 * time.Second, 0.5},        // halfway to 2x target
		{20 * time.Second, 0.0},        // at 2x target -> no credit
		{100 * time.Second, 0.0},       // beyond 2x target -> no credit
	}
	for _, c := range cases {
		if got := latencyCredit(c.d); !approxEqual(got, c.want, 1e-9) {
			t.Errorf("latencyCredit(%v) = %v, want %v", c.d, got, c.want)
		}
	}
}

func TestUpdateDurationEMA(t *testing.T) {
	// First sample returns the sample directly.
	if got := updateDurationEMA(0, 2*time.Second); got != 2*time.Second {
		t.Errorf("updateDurationEMA(0, 2s) = %v, want 2s", got)
	}
	// Subsequent samples blend: 0.7*prev + 0.3*sample.
	if got := updateDurationEMA(10*time.Second, 20*time.Second); got != 13*time.Second {
		t.Errorf("updateDurationEMA(10s, 20s) = %v, want 13s", got)
	}
}

func TestClampScore(t *testing.T) {
	if got := clampScore(-1); got != 0 {
		t.Errorf("clampScore(-1) = %v, want 0", got)
	}
	if got := clampScore(2); got != 1 {
		t.Errorf("clampScore(2) = %v, want 1", got)
	}
	if got := clampScore(0.42); got != 0.42 {
		t.Errorf("clampScore(0.42) = %v, want 0.42", got)
	}
}