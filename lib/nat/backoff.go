package nat

import (
	"context"
	"time"
)

// BackoffConfig configures exponential backoff calculation.
type BackoffConfig struct {
	Initial time.Duration // Initial backoff duration
	Max     time.Duration // Maximum backoff duration (cap)
	Factor  float64       // Multiplier per retry (default: 2.0 for doubling)
}

// DefaultBackoffConfig returns a BackoffConfig with sensible defaults:
// Initial 30s, Max 30min, Factor 2.0 (doubling).
func DefaultBackoffConfig() *BackoffConfig {
	return &BackoffConfig{
		Initial: 30 * time.Second,
		Max:     30 * time.Minute,
		Factor:  2.0,
	}
}

// CalculateNextBackoff computes the next backoff duration given the current value.
// Applies Factor multiplication and caps at Max.
func (bc *BackoffConfig) CalculateNextBackoff(current time.Duration) time.Duration {
	if current >= bc.Max {
		return bc.Max
	}

	// Apply factor multiplication
	next := time.Duration(float64(current) * bc.Factor)

	// Cap at maximum
	if next > bc.Max {
		return bc.Max
	}

	return next
}

// WaitWithContext waits for duration or context cancellation, whichever comes first.
// Returns true if wait completed, false if context was cancelled.
func WaitWithContext(ctx context.Context, duration time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(duration):
		return true
	}
}
