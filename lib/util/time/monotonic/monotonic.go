package monotonic

import (
	"sync"
	"time"
)

// Clock provides monotonic-safe time operations for the I2P router.
// It uses time.Now() internally, which includes a monotonic clock reading
// in Go, ensuring that duration calculations are immune to wall clock jumps.
type Clock struct {
	// offset is added to time.Now() to account for NTP synchronization.
	// Protected by mu.
	offset time.Duration
	mu     sync.RWMutex
}

// NewClock creates a new monotonic Clock with zero offset.
func NewClock() *Clock {
	return &Clock{}
}

// Now returns the current time adjusted by any NTP offset. The returned
// time.Time retains Go's monotonic clock reading, so time.Since(clock.Now())
// will use the monotonic clock for the duration calculation.
func (c *Clock) Now() time.Time {
	c.mu.RLock()
	offset := c.offset
	c.mu.RUnlock()
	return time.Now().Add(offset)
}

// SetOffset updates the NTP time offset. This is called when the SNTP
// subsystem determines a new clock correction.
func (c *Clock) SetOffset(offset time.Duration) {
	c.mu.Lock()
	c.offset = offset
	c.mu.Unlock()
}

// Offset returns the current NTP time offset.
func (c *Clock) Offset() time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.offset
}

// Deadline represents a point in time after which something has expired.
// It captures the creation time using time.Now() (which includes a monotonic
// reading) and checks expiration using time.Since(), ensuring that NTP clock
// jumps cannot cause premature or delayed expiration.
//
// Deadline is safe for concurrent use by multiple goroutines.
//
// This is the recommended way to track tunnel lifetime, lease expiration,
// and any other time-bounded operation in the I2P router.
type Deadline struct {
	mu        sync.RWMutex
	createdAt time.Time
	lifetime  time.Duration
}

// NewDeadline creates a Deadline that expires after the given lifetime.
// The creation time is captured immediately using time.Now(), which
// includes a monotonic clock reading.
//
// Panics if lifetime is negative.
func NewDeadline(lifetime time.Duration) *Deadline {
	if lifetime < 0 {
		panic("monotonic: negative lifetime")
	}
	return &Deadline{
		createdAt: time.Now(),
		lifetime:  lifetime,
	}
}

// NewDeadlineAt creates a Deadline that expires after the given lifetime,
// starting from a specific time. The startTime should be a value obtained
// from time.Now() to preserve the monotonic clock reading.
//
// This is useful when the creation time was captured earlier (e.g., when
// a tunnel build request was sent, not when the response arrived).
//
// Panics if lifetime is negative.
func NewDeadlineAt(startTime time.Time, lifetime time.Duration) *Deadline {
	if lifetime < 0 {
		panic("monotonic: negative lifetime")
	}
	return &Deadline{
		createdAt: startTime,
		lifetime:  lifetime,
	}
}

// IsExpired returns true if the deadline has passed. It uses time.Since()
// which relies on the monotonic clock reading, making it safe from NTP jumps.
func (d *Deadline) IsExpired() bool {
	d.mu.RLock()
	lifetime := d.lifetime
	d.mu.RUnlock()
	return time.Since(d.createdAt) >= lifetime
}

// Remaining returns the time remaining until the deadline expires.
// Returns zero if already expired. Uses time.Since() for monotonic safety.
func (d *Deadline) Remaining() time.Duration {
	d.mu.RLock()
	lifetime := d.lifetime
	d.mu.RUnlock()
	elapsed := time.Since(d.createdAt)
	remaining := lifetime - elapsed
	if remaining < 0 {
		return 0
	}
	return remaining
}

// Elapsed returns how much time has passed since the deadline was created.
// Uses time.Since() for monotonic safety.
func (d *Deadline) Elapsed() time.Duration {
	return time.Since(d.createdAt)
}

// Lifetime returns the total lifetime configured for this deadline.
func (d *Deadline) Lifetime() time.Duration {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.lifetime
}

// CreatedAt returns the wall clock time when this deadline was created.
// Note: for duration calculations, always use Elapsed() or Remaining()
// instead of computing time.Since(d.CreatedAt()), as the returned time
// may have its monotonic reading stripped in some contexts.
func (d *Deadline) CreatedAt() time.Time {
	return d.createdAt
}

// Extend adds additional time to the deadline's lifetime. This is useful
// for lease renewal or tunnel lifetime extension. The extension must be
// non-negative. This method is safe for concurrent use.
func (d *Deadline) Extend(additional time.Duration) {
	if additional < 0 {
		panic("monotonic: negative extension")
	}
	d.mu.Lock()
	d.lifetime += additional
	d.mu.Unlock()
}

// TimeSinceCreation is a standalone helper that computes the elapsed duration
// from a time.Time captured via time.Now(). It is equivalent to time.Since(t)
// and exists to document the intent: using the monotonic clock for the
// calculation.
func TimeSinceCreation(created time.Time) time.Duration {
	return time.Since(created)
}

// IsExpiredAt checks if a deadline created at startTime with the given lifetime
// has expired. This is a stateless alternative to the Deadline type, useful
// when the start time and lifetime are stored separately (e.g., in a database).
//
// The startTime MUST have been captured via time.Now() within the same process
// lifetime for the monotonic clock guarantee to hold. For timestamps loaded
// from disk or network, use wall clock comparison instead.
func IsExpiredAt(startTime time.Time, lifetime time.Duration) bool {
	return time.Since(startTime) >= lifetime
}
