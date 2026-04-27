package i2pcontrol

import (
	"sync"
	"time"
)

// rateSample is a single timestamped measurement for sliding-window statistics.
type rateSample struct {
	at    time.Time
	value float64
}

// RateWindow stores time-series samples and computes windowed statistics.
// It is safe for concurrent use.
type RateWindow struct {
	mu      sync.Mutex
	samples []rateSample
	maxAge  time.Duration
}

// newRateWindow returns a RateWindow that retains samples up to maxAge old.
func newRateWindow(maxAge time.Duration) *RateWindow {
	return &RateWindow{maxAge: maxAge}
}

// Record appends a sample with the current timestamp.
func (w *RateWindow) Record(value float64) {
	now := time.Now()
	w.mu.Lock()
	defer w.mu.Unlock()
	w.samples = append(w.samples, rateSample{at: now, value: value})
	w.pruneOldLocked(now)
}

// Average returns the arithmetic mean of all samples within windowMs milliseconds.
// Returns 0 if no samples fall within the window.
func (w *RateWindow) Average(windowMs int64) float64 {
	cutoff := time.Now().Add(-time.Duration(windowMs) * time.Millisecond)
	w.mu.Lock()
	defer w.mu.Unlock()
	var sum float64
	var n int
	for _, s := range w.samples {
		if !s.at.Before(cutoff) {
			sum += s.value
			n++
		}
	}
	if n == 0 {
		return 0
	}
	return sum / float64(n)
}

// Count returns the sum of sample values within windowMs milliseconds.
// When each sample has value 1.0, this counts discrete events in the window.
func (w *RateWindow) Count(windowMs int64) float64 {
	cutoff := time.Now().Add(-time.Duration(windowMs) * time.Millisecond)
	w.mu.Lock()
	defer w.mu.Unlock()
	var total float64
	for _, s := range w.samples {
		if !s.at.Before(cutoff) {
			total += s.value
		}
	}
	return total
}

// pruneOldLocked removes samples older than maxAge. Caller must hold w.mu.
func (w *RateWindow) pruneOldLocked(now time.Time) {
	cutoff := now.Add(-w.maxAge)
	i := 0
	for i < len(w.samples) && w.samples[i].at.Before(cutoff) {
		i++
	}
	if i > 0 {
		w.samples = w.samples[i:]
	}
}
