package nat

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestBackoffConfig_CalculateNextBackoff(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *BackoffConfig
		current time.Duration
		want    time.Duration
	}{
		{
			name: "doubling_from_10s",
			cfg: &BackoffConfig{
				Initial: 10 * time.Second,
				Max:     5 * time.Minute,
				Factor:  2.0,
			},
			current: 10 * time.Second,
			want:    20 * time.Second,
		},
		{
			name: "doubling_from_20s",
			cfg: &BackoffConfig{
				Initial: 10 * time.Second,
				Max:     5 * time.Minute,
				Factor:  2.0,
			},
			current: 20 * time.Second,
			want:    40 * time.Second,
		},
		{
			name: "doubling_from_40s",
			cfg: &BackoffConfig{
				Initial: 10 * time.Second,
				Max:     5 * time.Minute,
				Factor:  2.0,
			},
			current: 40 * time.Second,
			want:    80 * time.Second,
		},
		{
			name: "capped_when_growth_exceeds_max",
			cfg: &BackoffConfig{
				Initial: 30 * time.Second,
				Max:     2 * time.Minute,
				Factor:  2.0,
			},
			current: 90 * time.Second,
			want:    2 * time.Minute,
		},
		{
			name: "stays_at_max",
			cfg: &BackoffConfig{
				Initial: 30 * time.Second,
				Max:     2 * time.Minute,
				Factor:  2.0,
			},
			current: 2 * time.Minute,
			want:    2 * time.Minute,
		},
		{
			name: "above_max_returns_max",
			cfg: &BackoffConfig{
				Initial: 30 * time.Second,
				Max:     2 * time.Minute,
				Factor:  2.0,
			},
			current: 5 * time.Minute,
			want:    2 * time.Minute,
		},
		{
			name: "custom_factor_from_10s",
			cfg: &BackoffConfig{
				Initial: 10 * time.Second,
				Max:     10 * time.Minute,
				Factor:  1.5,
			},
			current: 10 * time.Second,
			want:    15 * time.Second,
		},
		{
			name: "custom_factor_from_15s",
			cfg: &BackoffConfig{
				Initial: 10 * time.Second,
				Max:     10 * time.Minute,
				Factor:  1.5,
			},
			current: 15 * time.Second,
			want:    time.Duration(float64(15*time.Second) * 1.5),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.cfg.CalculateNextBackoff(tt.current))
		})
	}
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
