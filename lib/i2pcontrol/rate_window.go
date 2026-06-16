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
// samplesInWindow returns all samples that fall within the specified window (relative to now).
// windowMs is the window duration in milliseconds. Uses Lock for thread-safety.
func (w *RateWindow) samplesInWindow(windowMs int64) []rateSample {
	cutoff := time.Now().Add(-time.Duration(windowMs) * time.Millisecond)
	w.mu.Lock()
	defer w.mu.Unlock()
	var result []rateSample
	for _, s := range w.samples {
		if !s.at.Before(cutoff) {
			result = append(result, s)
		}
	}
	return result
}

// Average returns the mean of sample values within windowMs milliseconds.
func (w *RateWindow) Average(windowMs int64) float64 {
	samples := w.samplesInWindow(windowMs)
	if len(samples) == 0 {
		return 0
	}
	var sum float64
	for _, s := range samples {
		sum += s.value
	}
	return sum / float64(len(samples))
}

// Len returns the number of samples within windowMs milliseconds.
// Used to detect the warm-up period (< 2 samples) and avoid misleading fallbacks.
func (w *RateWindow) Len(windowMs int64) int {
	return len(w.samplesInWindow(windowMs))
}

// Count returns the sum of sample values within windowMs milliseconds.
// When each sample has value 1.0, this counts discrete events in the window.
func (w *RateWindow) Count(windowMs int64) float64 {
	samples := w.samplesInWindow(windowMs)
	var total float64
	for _, s := range samples {
		total += s.value
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
