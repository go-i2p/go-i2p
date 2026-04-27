package i2np

import (
	"sync"
	"time"
)

// buildEventSample is a single timestamped build event or duration measurement.
type buildEventSample struct {
	at      time.Time
	valueMs float64
}

// buildEventWindow is a thread-safe sliding window for tunnel build events.
// It tracks discrete events (success/reject/expire) and duration measurements
// for computing windowed counts and averages.
type buildEventWindow struct {
	mu      sync.Mutex
	samples []buildEventSample
	maxAge  time.Duration
}

// newBuildEventWindow creates a window retaining samples up to maxAge old.
func newBuildEventWindow(maxAge time.Duration) *buildEventWindow {
	return &buildEventWindow{maxAge: maxAge}
}

// recordEvent appends a discrete event (value 1) with the current timestamp.
func (w *buildEventWindow) recordEvent() {
	now := time.Now()
	w.mu.Lock()
	defer w.mu.Unlock()
	w.samples = append(w.samples, buildEventSample{at: now, valueMs: 1})
	w.pruneOldLocked(now)
}

// recordDuration appends a duration measurement in milliseconds.
func (w *buildEventWindow) recordDuration(ms float64) {
	now := time.Now()
	w.mu.Lock()
	defer w.mu.Unlock()
	w.samples = append(w.samples, buildEventSample{at: now, valueMs: ms})
	w.pruneOldLocked(now)
}

// countInWindow returns the total event count within windowMs milliseconds.
func (w *buildEventWindow) countInWindow(windowMs int64) float64 {
	cutoff := time.Now().Add(-time.Duration(windowMs) * time.Millisecond)
	w.mu.Lock()
	defer w.mu.Unlock()
	var total float64
	for _, s := range w.samples {
		if !s.at.Before(cutoff) {
			total += s.valueMs
		}
	}
	return total
}

// avgInWindow returns the mean of sample values within windowMs milliseconds.
// Returns 0 if no samples fall in the window.
func (w *buildEventWindow) avgInWindow(windowMs int64) float64 {
	cutoff := time.Now().Add(-time.Duration(windowMs) * time.Millisecond)
	w.mu.Lock()
	defer w.mu.Unlock()
	var sum float64
	var n int
	for _, s := range w.samples {
		if !s.at.Before(cutoff) {
			sum += s.valueMs
			n++
		}
	}
	if n == 0 {
		return 0
	}
	return sum / float64(n)
}

// pruneOldLocked removes samples older than maxAge. Caller must hold w.mu.
func (w *buildEventWindow) pruneOldLocked(now time.Time) {
	cutoff := now.Add(-w.maxAge)
	i := 0
	for i < len(w.samples) && w.samples[i].at.Before(cutoff) {
		i++
	}
	if i > 0 {
		w.samples = w.samples[i:]
	}
}
