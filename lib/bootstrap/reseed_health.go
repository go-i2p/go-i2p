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
//
// This file implements per-reseed-server health tracking. It records the outcome and
// latency of each reseed attempt against a server and exposes a score that lets the
// multi-server reseed path prefer servers that have historically been fast and reliable.
// The tracker is intentionally dependency-free and thread-safe so it can be shared across
// concurrent reseed attempts and reused across reseed cycles.

package bootstrap

import (
	"sort"
	"sync"
	"time"
)

// Tunables for the reseed server health score. They are chosen so that:
//   - a server with no history scores a neutral baseline (it is neither preferred nor
//     avoided),
//   - a fast, always-successful server scores near 1.0,
//   - a repeatedly failing server scores near 0.0.
const (
	// healthBaselineScore is the score assigned to a server with no recorded history.
	healthBaselineScore = 0.5

	// healthLatencyTarget is the response time at or below which a server earns full
	// latency credit. Slower responses earn proportionally less credit.
	healthLatencyTarget = 10 * time.Second

	// healthFailurePenalty is subtracted from the score for each consecutive failure.
	healthFailurePenalty = 0.25

	// healthFailurePenaltyMax caps the total penalty from consecutive failures so a
	// single bad streak cannot drive the score below zero.
	healthFailurePenaltyMax = 0.75

	// healthLatencyWeight is the fraction of the score contributed by latency. The
	// remainder is contributed by the success rate, so reliability dominates.
	healthLatencyWeight = 0.25
)

// reseedServerHealth holds the rolling health statistics for a single reseed server.
type reseedServerHealth struct {
	attempts           int
	successes          int
	consecutiveFails   int
	avgDuration        time.Duration // exponential moving average of successful response times
	lastAttempt        time.Time
}

// reseedHealthTracker is a thread-safe registry of per-server reseed health.
type reseedHealthTracker struct {
	mu      sync.RWMutex
	servers map[string]*reseedServerHealth
}

// newReseedHealthTracker returns an empty health tracker.
func newReseedHealthTracker() *reseedHealthTracker {
	return &reseedHealthTracker{
		servers: make(map[string]*reseedServerHealth),
	}
}

// recordSuccess records a successful reseed from the server, resetting its consecutive
// failure streak and updating the latency moving average.
func (t *reseedHealthTracker) recordSuccess(url string, duration time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()

	h := t.entry(url)
	h.attempts++
	h.successes++
	h.consecutiveFails = 0
	h.lastAttempt = time.Now()
	h.avgDuration = updateDurationEMA(h.avgDuration, duration)
}

// recordFailure records a failed reseed from the server, incrementing its consecutive
// failure streak.
func (t *reseedHealthTracker) recordFailure(url string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	h := t.entry(url)
	h.attempts++
	h.consecutiveFails++
	h.lastAttempt = time.Now()
}

// entry returns the health record for url, creating it if necessary. Callers must hold
// the write lock.
func (t *reseedHealthTracker) entry(url string) *reseedServerHealth {
	h, ok := t.servers[url]
	if !ok {
		h = &reseedServerHealth{}
		t.servers[url] = h
	}
	return h
}

// score returns the current health score for url in [0, 1]. Servers with no history
// receive the neutral baseline score.
func (t *reseedHealthTracker) score(url string) float64 {
	t.mu.RLock()
	defer t.mu.RUnlock()

	h, ok := t.servers[url]
	if !ok || h.attempts == 0 {
		return healthBaselineScore
	}

	successRate := float64(h.successes) / float64(h.attempts)
	latencyFactor := latencyCredit(h.avgDuration)

	// Reliability dominates; latency is a secondary signal.
	base := (1-healthLatencyWeight)*successRate + healthLatencyWeight*latencyFactor

	penalty := float64(h.consecutiveFails) * healthFailurePenalty
	if penalty > healthFailurePenaltyMax {
		penalty = healthFailurePenaltyMax
	}

	return clampScore(base - penalty)
}

// rank returns a copy of urls stably sorted by descending health score, so healthy
// servers are tried first. Because the sort is stable, the relative order of
// equal-scored servers (including all servers with no history) is preserved — callers
// should pass an already-shuffled slice so that ties are still rotated, keeping the
// privacy property of not always contacting the same servers first. The input slice is
// not mutated.
func (t *reseedHealthTracker) rank(urls []string) []string {
	ranked := make([]string, len(urls))
	copy(ranked, urls)

	sort.SliceStable(ranked, func(i, j int) bool {
		return t.score(ranked[i]) > t.score(ranked[j])
	})

	return ranked
}

// snapshot returns a copy of the current health records for observability and testing.
func (t *reseedHealthTracker) snapshot() map[string]reseedServerHealth {
	t.mu.RLock()
	defer t.mu.RUnlock()

	out := make(map[string]reseedServerHealth, len(t.servers))
	for url, h := range t.servers {
		out[url] = *h
	}
	return out
}

// latencyCredit maps a response time to a [0, 1] credit: 1.0 at or below
// healthLatencyTarget, decreasing linearly to 0.0 at 2x the target. Unknown durations
// (zero) earn full credit.
func latencyCredit(d time.Duration) float64 {
	if d <= 0 {
		return 1.0
	}
	if d <= healthLatencyTarget {
		return 1.0
	}
	credit := 1.0 - float64(d-healthLatencyTarget)/float64(healthLatencyTarget)
	if credit < 0 {
		return 0.0
	}
	return credit
}

// updateDurationEMA blends a new sample into an exponential moving average. A zero
// previous value (first sample) returns the sample directly.
func updateDurationEMA(prev, sample time.Duration) time.Duration {
	if prev <= 0 {
		return sample
	}
	return time.Duration(0.7*float64(prev) + 0.3*float64(sample))
}

// clampScore constrains a score to [0, 1].
func clampScore(s float64) float64 {
	if s < 0 {
		return 0
	}
	if s > 1 {
		return 1
	}
	return s
}
