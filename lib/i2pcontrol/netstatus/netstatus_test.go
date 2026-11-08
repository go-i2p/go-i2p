package netstatus

import "testing"

// TestCodeValues pins the wire values. Every one of these numbers is part of the
// I2PControl protocol and is read by external clients, so a change here is a
// compatibility break and must be deliberate.
func TestCodeValues(t *testing.T) {
	cases := []struct {
		name string
		got  int
		want int
	}{
		{"OK", OK, 0},
		{"Testing", Testing, 1},
		{"Firewalled", Firewalled, 2},
		{"Hidden", Hidden, 3},
		{"WarnFirewalledAndFast", WarnFirewalledAndFast, 4},
		{"WarnFirewalledAndFloodfill", WarnFirewalledAndFloodfill, 5},
		{"WarnFirewalledWithInboundTCP", WarnFirewalledWithInboundTCP, 6},
		{"WarnFirewalledWithUDPDisabled", WarnFirewalledWithUDPDisabled, 7},
		{"ErrorI2CP", ErrorI2CP, 8},
		{"ErrorClockSkew", ErrorClockSkew, 9},
		{"ErrorPrivateTCPAddress", ErrorPrivateTCPAddress, 10},
		{"ErrorSymmetricNAT", ErrorSymmetricNAT, 11},
		{"ErrorUDPPortInUse", ErrorUDPPortInUse, 12},
		{"ErrorNoActivePeers", ErrorNoActivePeers, 13},
		{"ErrorUDPDisabledAndTCPUnset", ErrorUDPDisabledAndTCPUnset, 14},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}
}

// TestNameCoversEveryCode asserts that each defined code has a distinct,
// non-empty name. A gap would mean the table was extended without its entry,
// which the compile-time assertions in netstatus.go cannot detect because the
// array still sizes correctly.
func TestNameCoversEveryCode(t *testing.T) {
	seen := map[string]int{}
	for code := 0; code <= MaxCode; code++ {
		name := Name(code)
		if name == Unknown || name == "" {
			t.Errorf("code %d has no name (got %q)", code, name)
			continue
		}
		if prior, dup := seen[name]; dup {
			t.Errorf("codes %d and %d share the name %q", prior, code, name)
		}
		seen[name] = code
	}
	if len(seen) != MaxCode+1 {
		t.Errorf("named %d codes, want %d", len(seen), MaxCode+1)
	}
}

// TestNameOutOfRange checks the fallback for values the router never sends,
// including the negative and above-MaxCode edges a malformed reply could carry.
func TestNameOutOfRange(t *testing.T) {
	for _, code := range []int{-1, -100, MaxCode + 1, MaxCode + 100, 99} {
		if got := Name(code); got != Unknown {
			t.Errorf("Name(%d) = %q, want %q", code, got, Unknown)
		}
	}
}
