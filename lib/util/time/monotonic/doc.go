// Package monotonic provides time utilities that are safe against NTP clock
// jumps.
//
// # What is this for?
//
// The I2P router tracks many time-based expirations: tunnel lifetimes, lease
// expirations, and so on. If the system clock jumps (for example, when NTP
// synchronizes the clock), wall-clock-based expiration checks can fire too
// early or too late, breaking the router's timing guarantees.
//
// # Why does this matter?
//
// A router that expires a tunnel a few seconds early drops traffic that
// should still be flowing. One that keeps a dead tunnel alive wastes
// bandwidth and can leak state. Both failures come from the same root cause:
// measuring time with a clock that can be adjusted at any moment.
//
// # How it works
//
// Go's time.Now() returns a time.Time that carries a hidden monotonic clock
// reading alongside the wall-clock time. Duration calculations built from
// such values (time.Since, time.Until, and time.Time.Sub) use the monotonic
// reading, so they are immune to wall-clock adjustments.
//
// This only works when both times were captured within the same process
// lifetime using time.Now(). Timestamps loaded from disk or received over the
// network do NOT carry a monotonic reading, so comparing them with time.Now()
// falls back to wall-clock comparison, which can be wrong if the system clock
// jumps.
//
// This package wraps the monotonic behavior in a small API:
//
//   - [Clock] returns the current time (with an optional NTP offset applied)
//     while preserving the monotonic reading.
//   - [Deadline] captures a creation time and a lifetime, and reports whether
//     the deadline has passed using monotonic-safe arithmetic.
//
// # Usage
//
//	// Track a tunnel that lives for 10 minutes.
//	deadline := monotonic.NewDeadline(10 * time.Minute)
//	// ... later ...
//	if deadline.IsExpired() {
//		// Tunnel has expired, safe from NTP jumps
//	}
//
//	// Track a lease and see how long is left.
//	leaseDeadline := monotonic.NewDeadline(leaseSet.GetExpiration())
//	if remaining := leaseDeadline.Remaining(); remaining < rebuildThreshold {
//		// Time to rebuild
//	}
//
// # Thread safety
//
// [Clock] and [Deadline] are safe for concurrent use by multiple goroutines.
package monotonic
