// Package monotonic provides NTP-jump-safe time utilities for I2P router operations.
//
// Go's time.Now() includes a monotonic clock reading that is immune to wall clock
// adjustments (NTP corrections, manual time changes). The time.Since() and
// time.Until() functions use this monotonic reading when available. However, this
// only works when both times were captured within the same process lifetime using
// time.Now().
//
// Timestamps loaded from disk or received over the network do NOT have monotonic
// readings, so comparing them with time.Now() falls back to wall clock comparison,
// which can produce incorrect results if the system clock jumps.
//
// This package provides a Deadline type that captures the creation time via
// time.Now() and checks expiration using time.Since(), ensuring monotonic safety.
// It also provides a Clock interface for consistent monotonic time access
// throughout the router.
//
// Usage for tunnel expiration:
//
//	deadline := monotonic.NewDeadline(10 * time.Minute)
//	// ... later ...
//	if deadline.IsExpired() {
//	    // Tunnel has expired, safe from NTP jumps
//	}
//
// Usage for lease expiration:
//
//	deadline := monotonic.NewDeadline(leaseSet.GetExpiration())
//	if remaining := deadline.Remaining(); remaining < rebuildThreshold {
//	    // Time to rebuild
//	}
package monotonic
