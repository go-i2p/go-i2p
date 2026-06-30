package nat

import (
	"net"
	"testing"
)

func TestIsPublicRoutableIPv4(t *testing.T) {
	cases := []struct {
		name string
		ip   string
		want bool
	}{
		// Public, routable IPv4.
		{"public_1.2.3.4", "1.2.3.4", true},
		{"public_8.8.8.8", "8.8.8.8", true},
		{"public_203.0.114.1", "203.0.114.1", true},

		// RFC 1918 private — the original classifier bug treated these as public
		// because net.IP.IsGlobalUnicast() returns true for them.
		{"private_10.0.0.1", "10.0.0.1", false},
		{"private_172.16.5.4", "172.16.5.4", false},
		{"private_192.168.1.1", "192.168.1.1", false},

		// CGNAT 100.64.0.0/10.
		{"cgnat_100.64.0.1", "100.64.0.1", false},
		{"cgnat_100.127.255.255", "100.127.255.255", false},
		{"non_cgnat_100.128.0.1", "100.128.0.1", true},

		// Special-use / TEST-NET ranges.
		{"protocol_192.0.0.1", "192.0.0.1", false},
		{"testnet1_192.0.2.5", "192.0.2.5", false},
		{"testnet2_198.51.100.7", "198.51.100.7", false},
		{"testnet3_203.0.113.9", "203.0.113.9", false},
		{"multicast_224.0.0.1", "224.0.0.1", false},
		{"reserved_240.0.0.1", "240.0.0.1", false},

		// Loopback / link-local / unspecified.
		{"loopback_127.0.0.1", "127.0.0.1", false},
		{"linklocal_169.254.1.1", "169.254.1.1", false},
		{"unspecified_0.0.0.0", "0.0.0.0", false},

		// IPv6 is not IPv4 — always false here.
		{"ipv6_global", "2001:db8::1", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			if ip == nil {
				t.Fatalf("failed to parse %q", tc.ip)
			}
			if got := IsPublicRoutableIPv4(ip); got != tc.want {
				t.Errorf("IsPublicRoutableIPv4(%s) = %v, want %v", tc.ip, got, tc.want)
			}
		})
	}
}

func TestIsPublicRoutableIPv4_NonIPv4Nil(t *testing.T) {
	if IsPublicRoutableIPv4(nil) {
		t.Error("IsPublicRoutableIPv4(nil) = true, want false")
	}
}

func TestIsSpecialUseIPv4(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"100.64.0.1", true},
		{"100.127.0.1", true},
		{"100.128.0.1", false},
		{"192.0.0.1", true},
		{"192.0.2.1", true},
		{"198.51.100.1", true},
		{"203.0.113.1", true},
		{"224.0.0.1", true},
		{"255.255.255.255", true},
		{"1.2.3.4", false},
		{"10.0.0.1", false}, // RFC1918 is NOT special-use per this function
	}
	for _, tc := range cases {
		ip := net.ParseIP(tc.ip)
		if ip == nil {
			t.Fatalf("failed to parse %q", tc.ip)
		}
		if got := IsSpecialUseIPv4(ip); got != tc.want {
			t.Errorf("IsSpecialUseIPv4(%s) = %v, want %v", tc.ip, got, tc.want)
		}
	}
	// IPv6 input returns false.
	if IsSpecialUseIPv4(net.ParseIP("2001:db8::1")) {
		t.Error("IsSpecialUseIPv4(ipv6) = true, want false")
	}
}

func TestIsPubliclyRoutableHost(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		{"1.2.3.4", true},
		{"8.8.8.8", true},
		{"10.0.0.1", false},
		{"192.168.1.1", false},
		{"172.16.0.1", false},
		{"100.64.0.1", false},
		{"192.0.2.1", false},
		{"127.0.0.1", false},
		{"169.254.1.1", false},
		{"0.0.0.0", false},
		{"2001:db8::1", true}, // global-unicast IPv6
		{"fc00::1", false},    // unique-local IPv6 (private)
		{"::1", false},        // IPv6 loopback
		{"not-an-ip", false},  // hostname literal
		{"", false},
	}
	for _, tc := range cases {
		if got := IsPubliclyRoutableHost(tc.host); got != tc.want {
			t.Errorf("IsPubliclyRoutableHost(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

func TestIsPubliclyRoutableIP(t *testing.T) {
	cases := []struct {
		name string
		ip   string
		want bool
	}{
		{"public_ipv4", "1.2.3.4", true},
		{"private_ipv4", "192.168.0.1", false},
		{"cgnat_ipv4", "100.64.0.1", false},
		{"testnet_ipv4", "203.0.113.1", false},
		{"loopback_ipv4", "127.0.0.1", false},
		{"unspecified_ipv4", "0.0.0.0", false},
		{"global_ipv6", "2001:db8::1", true},
		{"ula_ipv6", "fc00::1", false},
		{"loopback_ipv6", "::1", false},
		{"linklocal_ipv6", "fe80::1", false},
		{"unspecified_ipv6", "::", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsPubliclyRoutableIP(net.ParseIP(tc.ip)); got != tc.want {
				t.Errorf("IsPubliclyRoutableIP(%s) = %v, want %v", tc.ip, got, tc.want)
			}
		})
	}
	// nil input must not panic and returns false.
	if IsPubliclyRoutableIP(nil) {
		t.Error("IsPubliclyRoutableIP(nil) = true, want false")
	}
}

// TestIsPubliclyRoutableHost_MatchesIP verifies the string and net.IP entry
// points agree for every IP literal, so callers using either form get the same
// reachability verdict.
func TestIsPubliclyRoutableHost_MatchesIP(t *testing.T) {
	for _, s := range []string{
		"1.2.3.4", "10.0.0.1", "100.64.0.1", "203.0.113.1",
		"127.0.0.1", "0.0.0.0", "2001:db8::1", "fc00::1", "::1", "fe80::1",
	} {
		host := IsPubliclyRoutableHost(s)
		ip := IsPubliclyRoutableIP(net.ParseIP(s))
		if host != ip {
			t.Errorf("disagreement for %q: host=%v ip=%v", s, host, ip)
		}
	}
}
