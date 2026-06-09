package nat

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestBackoffConfig_CalculateNextBackoff_Doubling(t *testing.T) {
	cfg := &BackoffConfig{
		Initial: 10 * time.Second,
		Max:     5 * time.Minute,
		Factor:  2.0,
	}

	// Test doubling behavior
	current := 10 * time.Second
	next := cfg.CalculateNextBackoff(current)
	assert.Equal(t, 20*time.Second, next, "should double from 10s to 20s")

	current = 20 * time.Second
	next = cfg.CalculateNextBackoff(current)
	assert.Equal(t, 40*time.Second, next, "should double from 20s to 40s")

	current = 40 * time.Second
	next = cfg.CalculateNextBackoff(current)
	assert.Equal(t, 80*time.Second, next, "should double from 40s to 80s")
}

func TestBackoffConfig_CalculateNextBackoff_Capped(t *testing.T) {
	cfg := &BackoffConfig{
		Initial: 30 * time.Second,
		Max:     2 * time.Minute,
		Factor:  2.0,
	}

	// Test capping at max
	current := 90 * time.Second // 90s * 2 = 180s = 3min, but max is 2min
	next := cfg.CalculateNextBackoff(current)
	assert.Equal(t, 2*time.Minute, next, "should cap at 2min")

	// Test already at max
	current = 2 * time.Minute
	next = cfg.CalculateNextBackoff(current)
	assert.Equal(t, 2*time.Minute, next, "should stay at max")

	// Test above max
	current = 5 * time.Minute
	next = cfg.CalculateNextBackoff(current)
	assert.Equal(t, 2*time.Minute, next, "should return max when current > max")
}

func TestBackoffConfig_CalculateNextBackoff_CustomFactor(t *testing.T) {
	cfg := &BackoffConfig{
		Initial: 10 * time.Second,
		Max:     10 * time.Minute,
		Factor:  1.5, // 1.5x growth instead of 2x
	}

	current := 10 * time.Second
	next := cfg.CalculateNextBackoff(current)
	assert.Equal(t, 15*time.Second, next, "should multiply by 1.5 from 10s to 15s")

	current = 15 * time.Second
	next = cfg.CalculateNextBackoff(current)
	expected := time.Duration(float64(15*time.Second) * 1.5)
	assert.Equal(t, expected, next, "should multiply by 1.5 from 15s")
}

func TestDefaultBackoffConfig(t *testing.T) {
	cfg := DefaultBackoffConfig()

	assert.Equal(t, 30*time.Second, cfg.Initial, "default initial should be 30s")
	assert.Equal(t, 30*time.Minute, cfg.Max, "default max should be 30min")
	assert.Equal(t, 2.0, cfg.Factor, "default factor should be 2.0")
}

func TestWaitWithContext_Completed(t *testing.T) {
	ctx := context.Background()
	duration := 10 * time.Millisecond

	start := time.Now()
	completed := WaitWithContext(ctx, duration)
	elapsed := time.Since(start)

	assert.True(t, completed, "wait should complete")
	assert.GreaterOrEqual(t, elapsed, duration, "should wait at least the duration")
	assert.Less(t, elapsed, duration+50*time.Millisecond, "should not wait too long")
}

func TestWaitWithContext_Cancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	duration := 5 * time.Second // Long duration

	// Cancel immediately
	cancel()

	start := time.Now()
	completed := WaitWithContext(ctx, duration)
	elapsed := time.Since(start)

	assert.False(t, completed, "wait should be cancelled")
	assert.Less(t, elapsed, 100*time.Millisecond, "should return quickly when cancelled")
}

func TestWaitWithContext_CancelledDuringWait(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	duration := 500 * time.Millisecond

	// Cancel after 100ms
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	completed := WaitWithContext(ctx, duration)
	elapsed := time.Since(start)

	assert.False(t, completed, "wait should be cancelled")
	assert.GreaterOrEqual(t, elapsed, 100*time.Millisecond, "should wait at least 100ms before cancellation")
	assert.Less(t, elapsed, 300*time.Millisecond, "should return shortly after cancellation")
}
