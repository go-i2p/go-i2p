package nat

import "net"

// IsLoopbackAddress returns true if host is a loopback IP literal or resolves
// entirely to loopback addresses. Empty host (wildcard binding) returns false.
//
// Hostname resolution is performed via net.LookupIP for non-literal hosts.
// Resolution failure or empty result returns false (fail-open for reachability).
//
// Examples:
//   - IsLoopbackAddress("127.0.0.1") → true
//   - IsLoopbackAddress("::1") → true
//   - IsLoopbackAddress("localhost") → true (after resolution)
//   - IsLoopbackAddress("") → false (wildcard binding)
//   - IsLoopbackAddress("192.168.1.5") → false
//
// Thread-safe: Resolution via net.LookupIP is goroutine-safe.
func IsLoopbackAddress(host string) bool {
	if host == "" {
		// Empty host means wildcard binding (not loopback)
		return false
	}
	// Try parsing as IP first (fast path)
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	// Not a literal IP — resolve the hostname
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		// Resolution failed or empty — assume non-loopback (fail open for reachability)
		return false
	}
	// Return true only if *all* resolved IPs are loopback
	for _, ip := range ips {
		if !ip.IsLoopback() {
			return false
		}
	}
	return true
}
