package nat

import "net"

// IsSpecialUseIPv4 returns true for non-routable special-use IPv4 ranges that
// must never be treated as publicly reachable, direct-connection endpoints.
//
// Covered ranges:
//   - 100.64.0.0/10  carrier-grade NAT (CGNAT)
//   - 192.0.0.0/24   IETF protocol assignments
//   - 192.0.2.0/24   TEST-NET-1
//   - 198.51.100.0/24 TEST-NET-2
//   - 203.0.113.0/24 TEST-NET-3
//   - 224.0.0.0/3    multicast and reserved classes (>= 224)
//
// Non-IPv4 input returns false. RFC 1918 private ranges are intentionally NOT
// reported here (callers detect those via net.IP.IsPrivate); this function only
// covers the special-use ranges Go's stdlib does not classify as private.
func IsSpecialUseIPv4(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	if ip4[0] == 100 && ip4[1]&0xC0 == 64 {
		return true // 100.64.0.0/10 carrier-grade NAT
	}
	if ip4[0] == 192 && ip4[1] == 0 && ip4[2] == 0 {
		return true // 192.0.0.0/24 IETF protocol assignments
	}
	if ip4[0] == 192 && ip4[1] == 0 && ip4[2] == 2 {
		return true // 192.0.2.0/24 TEST-NET-1
	}
	if ip4[0] == 198 && ip4[1] == 51 && ip4[2] == 100 {
		return true // 198.51.100.0/24 TEST-NET-2
	}
	if ip4[0] == 203 && ip4[1] == 0 && ip4[2] == 113 {
		return true // 203.0.113.0/24 TEST-NET-3
	}
	if ip4[0] >= 224 {
		return true // multicast and reserved classes
	}
	return false
}

// IsPublicRoutableIPv4 reports whether ip is a publicly routable IPv4 address
// that remote peers can reach directly. This is the single canonical IPv4
// reachability classifier for the codebase: RFC 1918 private ranges, loopback,
// link-local, CGNAT (100.64.0.0/10), and special-use/TEST-NET ranges all
// return false.
//
// Non-IPv4 input (including IPv6) returns false; use IsPubliclyRoutableHost for
// address-family-agnostic host classification.
func IsPublicRoutableIPv4(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	if !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return false
	}
	return !IsSpecialUseIPv4(ip4)
}

// IsPubliclyRoutableIP reports whether ip is a publicly routable address that
// remote peers can reach directly, for either address family. IPv4 addresses
// use IsPublicRoutableIPv4 semantics (RFC 1918, CGNAT, and special-use ranges
// excluded); IPv6 addresses must be global-unicast and non-private (ULA
// fc00::/7, loopback, link-local, and unspecified excluded).
//
// This is the family-agnostic core used by both IsPubliclyRoutableHost (string
// input) and callers that already hold a net.IP (e.g. the SSU2 public-IP
// short-circuit), so IPv4 and IPv6 reachability are judged identically.
func IsPubliclyRoutableIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if !ip.IsGlobalUnicast() {
		return false
	}
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		return !IsSpecialUseIPv4(ip4)
	}
	return true
}

// IsPubliclyRoutableHost reports whether host is an IP literal that is publicly
// routable and reachable by remote peers. IPv4 literals are classified via
// IsPublicRoutableIPv4 semantics; IPv6 literals must be global-unicast and
// non-private. Non-literal hosts (hostnames) and unspecified/loopback/
// link-local addresses return false.
func IsPubliclyRoutableHost(host string) bool {
	return IsPubliclyRoutableIP(net.ParseIP(host))
}
