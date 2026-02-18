package monotonic

import (
	"testing"
	"time"
)

// =============================================================================
// Clock Tests
// =============================================================================

// TestNewClock verifies a new Clock has zero offset.
func TestNewClock(t *testing.T) {
	c := NewClock()
	if c.Offset() != 0 {
		t.Errorf("expected zero offset, got %s", c.Offset())
	}
}

// TestClock_Now_WithoutOffset verifies Now() returns approximately time.Now()
// when offset is zero.
func TestClock_Now_WithoutOffset(t *testing.T) {
	c := NewClock()
	before := time.Now()
	now := c.Now()
	after := time.Now()

	if now.Before(before) || now.After(after) {
		t.Errorf("Clock.Now() = %v, expected between %v and %v", now, before, after)
	}
}

// TestClock_Now_WithOffset verifies Now() applies the configured offset.
func TestClock_Now_WithOffset(t *testing.T) {
	c := NewClock()
	c.SetOffset(5 * time.Second)

	before := time.Now().Add(5 * time.Second)
	now := c.Now()
	after := time.Now().Add(5 * time.Second)

	if now.Before(before.Add(-10*time.Millisecond)) || now.After(after.Add(10*time.Millisecond)) {
		t.Errorf("Clock.Now() with offset = %v, expected ~%v", now, before)
	}
}

// TestClock_SetOffset verifies offset can be updated.
func TestClock_SetOffset(t *testing.T) {
	c := NewClock()

	c.SetOffset(1 * time.Second)
	if c.Offset() != 1*time.Second {
		t.Errorf("expected 1s offset, got %s", c.Offset())
	}

	c.SetOffset(-500 * time.Millisecond)
	if c.Offset() != -500*time.Millisecond {
		t.Errorf("expected -500ms offset, got %s", c.Offset())
	}
}

// =============================================================================
// Deadline Tests
// =============================================================================

// TestNewDeadline_NotExpiredImmediately verifies a new deadline is not expired.
func TestNewDeadline_NotExpiredImmediately(t *testing.T) {
	d := NewDeadline(1 * time.Hour)
	if d.IsExpired() {
		t.Error("expected new deadline to not be expired")
	}
}

// TestNewDeadline_ZeroLifetime verifies a zero-lifetime deadline expires immediately.
func TestNewDeadline_ZeroLifetime(t *testing.T) {
	d := NewDeadline(0)
	// Zero lifetime: IsExpired when time.Since(createdAt) >= 0, which is always true
	if !d.IsExpired() {
		t.Error("expected zero-lifetime deadline to be expired immediately")
	}
}

// TestNewDeadline_NegativeLifetimePanics verifies negative lifetime causes a panic.
func TestNewDeadline_NegativeLifetimePanics(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Error("expected panic for negative lifetime")
		}
	}()
	NewDeadline(-1 * time.Second)
}

// TestNewDeadlineAt verifies creation from a specific start time.
func TestNewDeadlineAt(t *testing.T) {
	start := time.Now().Add(-5 * time.Minute)
	d := NewDeadlineAt(start, 10*time.Minute)

	if d.IsExpired() {
		t.Error("expected deadline starting 5min ago with 10min lifetime to not be expired")
	}
	if d.CreatedAt() != start {
		t.Errorf("expected CreatedAt = %v, got %v", start, d.CreatedAt())
	}
}

// TestNewDeadlineAt_AlreadyExpired verifies detection of already-expired start times.
func TestNewDeadlineAt_AlreadyExpired(t *testing.T) {
	start := time.Now().Add(-15 * time.Minute)
	d := NewDeadlineAt(start, 10*time.Minute)

	if !d.IsExpired() {
		t.Error("expected deadline starting 15min ago with 10min lifetime to be expired")
	}
}

// TestNewDeadlineAt_NegativeLifetimePanics verifies negative lifetime causes a panic.
func TestNewDeadlineAt_NegativeLifetimePanics(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Error("expected panic for negative lifetime")
		}
	}()
	NewDeadlineAt(time.Now(), -1*time.Second)
}

// TestDeadline_Remaining_NotExpired verifies Remaining returns positive value before expiry.
func TestDeadline_Remaining_NotExpired(t *testing.T) {
	d := NewDeadline(1 * time.Hour)
	remaining := d.Remaining()

	// Should be close to 1 hour (within a second)
	if remaining < 59*time.Minute || remaining > 1*time.Hour {
		t.Errorf("expected remaining ~1h, got %s", remaining)
	}
}

// TestDeadline_Remaining_Expired verifies Remaining returns zero after expiry.
func TestDeadline_Remaining_Expired(t *testing.T) {
	start := time.Now().Add(-10 * time.Minute)
	d := NewDeadlineAt(start, 5*time.Minute)

	if d.Remaining() != 0 {
		t.Errorf("expected zero remaining for expired deadline, got %s", d.Remaining())
	}
}

// TestDeadline_Elapsed verifies Elapsed tracks time since creation.
func TestDeadline_Elapsed(t *testing.T) {
	start := time.Now().Add(-5 * time.Minute)
	d := NewDeadlineAt(start, 10*time.Minute)

	elapsed := d.Elapsed()
	// Should be close to 5 minutes
	if elapsed < 4*time.Minute+50*time.Second || elapsed > 5*time.Minute+10*time.Second {
		t.Errorf("expected elapsed ~5min, got %s", elapsed)
	}
}

// TestDeadline_Lifetime verifies Lifetime returns the configured value.
func TestDeadline_Lifetime(t *testing.T) {
	d := NewDeadline(42 * time.Second)
	if d.Lifetime() != 42*time.Second {
		t.Errorf("expected lifetime 42s, got %s", d.Lifetime())
	}
}

// TestDeadline_CreatedAt verifies CreatedAt returns approximately the creation time.
func TestDeadline_CreatedAt(t *testing.T) {
	before := time.Now()
	d := NewDeadline(1 * time.Hour)
	after := time.Now()

	if d.CreatedAt().Before(before) || d.CreatedAt().After(after) {
		t.Errorf("CreatedAt = %v, expected between %v and %v", d.CreatedAt(), before, after)
	}
}

// TestDeadline_Extend verifies lifetime extension works.
func TestDeadline_Extend(t *testing.T) {
	d := NewDeadline(5 * time.Minute)
	if d.Lifetime() != 5*time.Minute {
		t.Fatalf("initial lifetime should be 5min, got %s", d.Lifetime())
	}

	d.Extend(3 * time.Minute)
	if d.Lifetime() != 8*time.Minute {
		t.Errorf("extended lifetime should be 8min, got %s", d.Lifetime())
	}
}

// TestDeadline_Extend_ZeroDuration verifies extending by zero is a no-op.
func TestDeadline_Extend_ZeroDuration(t *testing.T) {
	d := NewDeadline(5 * time.Minute)
	d.Extend(0)
	if d.Lifetime() != 5*time.Minute {
		t.Errorf("lifetime should remain 5min after zero extension, got %s", d.Lifetime())
	}
}

// TestDeadline_Extend_NegativePanics verifies negative extension causes a panic.
func TestDeadline_Extend_NegativePanics(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Error("expected panic for negative extension")
		}
	}()
	d := NewDeadline(5 * time.Minute)
	d.Extend(-1 * time.Second)
}

// TestDeadline_Extend_RescuesExpired verifies extension can rescue an expired deadline.
func TestDeadline_Extend_RescuesExpired(t *testing.T) {
	start := time.Now().Add(-10 * time.Minute)
	d := NewDeadlineAt(start, 5*time.Minute)

	if !d.IsExpired() {
		t.Fatal("deadline should be expired before extension")
	}

	d.Extend(10 * time.Minute)
	if d.IsExpired() {
		t.Error("deadline should not be expired after 10min extension (total 15min, elapsed ~10min)")
	}
}

// =============================================================================
// Standalone Helper Tests
// =============================================================================

// TestTimeSinceCreation verifies the standalone duration helper.
func TestTimeSinceCreation(t *testing.T) {
	created := time.Now().Add(-3 * time.Second)
	elapsed := TimeSinceCreation(created)

	if elapsed < 2*time.Second || elapsed > 4*time.Second {
		t.Errorf("expected ~3s elapsed, got %s", elapsed)
	}
}

// TestIsExpiredAt_NotExpired verifies stateless expiration check when not expired.
func TestIsExpiredAt_NotExpired(t *testing.T) {
	start := time.Now()
	if IsExpiredAt(start, 1*time.Hour) {
		t.Error("expected not expired for start=now, lifetime=1h")
	}
}

// TestIsExpiredAt_Expired verifies stateless expiration check when expired.
func TestIsExpiredAt_Expired(t *testing.T) {
	start := time.Now().Add(-10 * time.Minute)
	if !IsExpiredAt(start, 5*time.Minute) {
		t.Error("expected expired for start=10min ago, lifetime=5min")
	}
}

// =============================================================================
// Concurrency Tests
// =============================================================================

// TestClock_ConcurrentAccess verifies Clock is safe for concurrent use.
func TestClock_ConcurrentAccess(t *testing.T) {
	c := NewClock()
	done := make(chan struct{})

	// Concurrent readers
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				_ = c.Now()
				_ = c.Offset()
			}
			done <- struct{}{}
		}()
	}

	// Concurrent writers
	for i := 0; i < 5; i++ {
		go func(i int) {
			for j := 0; j < 100; j++ {
				c.SetOffset(time.Duration(i*j) * time.Millisecond)
			}
			done <- struct{}{}
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 15; i++ {
		<-done
	}
}

// TestDeadline_ConcurrentExtendAndRead verifies Deadline is safe for concurrent
// Extend and read operations (BUG #3 fix verification).
func TestDeadline_ConcurrentExtendAndRead(t *testing.T) {
	d := NewDeadline(1 * time.Hour)
	done := make(chan struct{})

	// Concurrent readers (IsExpired, Remaining, Lifetime)
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 200; j++ {
				_ = d.IsExpired()
				_ = d.Remaining()
				_ = d.Lifetime()
				_ = d.Elapsed()
			}
			done <- struct{}{}
		}()
	}

	// Concurrent writers (Extend)
	for i := 0; i < 5; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				d.Extend(1 * time.Millisecond)
			}
			done <- struct{}{}
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 15; i++ {
		<-done
	}

	// Verify: lifetime should be 1h + (5*100*1ms) = 1h + 500ms
	expected := 1*time.Hour + 500*time.Millisecond
	if d.Lifetime() != expected {
		t.Errorf("expected lifetime %s after concurrent extends, got %s", expected, d.Lifetime())
	}
}
