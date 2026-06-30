package ssu2

// nat_shortcircuit_test.go validates the public-IP short-circuit and the
// non-private fallback alignment introduced to stop public-IPv4 routers from
// being misclassified as FIREWALLED / stuck in TESTING.

import (
	"net"
	"testing"

	ssu2noise "github.com/go-i2p/go-noise/ssu2"
	"github.com/stretchr/testify/assert"
)

// TestSeedDirectReachability_PrivateBind verifies that a transport bound to a
// non-public (loopback / RFC1918) address does NOT seed a DIRECT classification
// and does not produce a locally-derived external address. The test listener
// binds to 127.0.0.1, so the public-IP short-circuit must decline.
func TestSeedDirectReachability_PrivateBind(t *testing.T) {
	tr, cleanup := makeTestTransportWithListener(t)
	defer cleanup()

	assert.False(t, tr.seedDirectReachability(),
		"loopback bind must not be classified directly reachable")

	// Cache must remain empty — no NATNone was written.
	_, valid := tr.natStateCache.get()
	assert.False(t, valid, "no NAT classification should be cached for a private bind")

	assert.Equal(t, "", tr.DirectPublicExternalAddr(),
		"private bind must not yield a public external address")
}

// TestDirectPublicExternalAddr_NoListener verifies the nil-listener guard:
// with no listener the transport cannot determine a bind address, so the
// short-circuit accessor returns "".
func TestDirectPublicExternalAddr_NoListener(t *testing.T) {
	tr := &SSU2Transport{
		natStateCache: &natState{},
		logger:        testLogger(),
	}
	assert.Equal(t, "", tr.DirectPublicExternalAddr())
	assert.False(t, tr.seedDirectReachability())
}

// TestFindBestPublicIP_NonPrivateFallback verifies the step-8 alignment with
// ntcp2.findBestExternalIP: a public IPv4 always wins, RFC 1918 private
// addresses are NEVER used as a fallback, and a non-private IPv6 address is an
// acceptable fallback when no public IPv4 exists.
func TestFindBestPublicIP_NonPrivateFallback(t *testing.T) {
	pub := &net.IPNet{IP: net.ParseIP("8.8.8.8")}
	priv := &net.IPNet{IP: net.ParseIP("192.168.1.5")}
	v6 := &net.IPNet{IP: net.ParseIP("2001:db8::1")}

	cases := []struct {
		name  string
		addrs []net.Addr
		want  string
	}{
		{"public_only", []net.Addr{pub}, "8.8.8.8"},
		{"private_then_public", []net.Addr{priv, pub}, "8.8.8.8"},
		{"private_only_no_fallback", []net.Addr{priv}, ""},
		{"private_then_v6_fallback", []net.Addr{priv, v6}, "2001:db8::1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, findBestPublicIP(c.addrs))
		})
	}
}

// TestSeedDirectReachability_NilCache verifies the nil-cache guard does not
// panic and reports not-directly-reachable.
func TestSeedDirectReachability_NilCache(t *testing.T) {
	tr := &SSU2Transport{logger: testLogger()}
	assert.False(t, tr.seedDirectReachability())
}

// TestPublicBoundAddress_PrivateBind verifies publicBoundAddress declines a
// loopback bind. Combined with the classifier tests in lib/nat this fully
// pins the "RFC1918 is not public" behavior across the seeding path.
func TestPublicBoundAddress_PrivateBind(t *testing.T) {
	tr, cleanup := makeTestTransportWithListener(t)
	defer cleanup()

	_, _, ok := tr.publicBoundAddress()
	assert.False(t, ok, "loopback bind must not resolve to a public address")
}

// TestInboundBlockedStatusCode_DirectNotBlocked is a guard around the
// precedence rule: a directly-reachable (NATNone) classification must never be
// reported as inbound-blocked, so the router can report OK for public hosts.
func TestInboundBlockedStatusCode_DirectNotBlocked(t *testing.T) {
	tr := &SSU2Transport{natStateCache: &natState{}, logger: testLogger()}
	tr.natStateCache.set(ssu2noise.NATNone, "8.8.8.8:1234")
	assert.Equal(t, 0, tr.InboundBlockedStatusCode())
	assert.False(t, tr.IsInboundBlocked())
}

// TestResolvePublishedHost_Substitution verifies that a non-publicly-routable
// listener host is replaced with the cached PeerTest/NAT-PMP external address,
// while a publicly routable host is published unchanged. This pins the CGNAT /
// wildcard substitution-gap fix: the gate is "not publicly routable", not just
// RFC1918 private.
func TestResolvePublishedHost_Substitution(t *testing.T) {
	const ext = "203.0.113.7:9999"
	cases := []struct {
		name string
		host string
		want string
	}{
		{"rfc1918_substituted", "192.168.1.10", ext},
		{"cgnat_substituted", "100.64.0.5", ext},   // was missed by the old IsPrivate gate
		{"wildcard_substituted", "0.0.0.0", ext},   // unspecified is not public
		{"loopback_substituted", "127.0.0.1", ext}, // non-public
		{"public_unchanged", "1.2.3.4", "1.2.3.4"}, // genuinely public host kept as-is
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tr := &SSU2Transport{natStateCache: &natState{}, logger: testLogger()}
			tr.natStateCache.set(ssu2noise.NATNone, ext)
			assert.Equal(t, c.want, resolvePublishedHost(c.host, tr))
		})
	}
}

// TestResolvePublishedHost_NoCacheKeepsHost verifies that without a cached
// external address the raw (even non-public) host is returned unchanged, so
// downstream buildSSU2Options can decide on a caps-only address.
func TestResolvePublishedHost_NoCacheKeepsHost(t *testing.T) {
	tr := &SSU2Transport{natStateCache: &natState{}, logger: testLogger()}
	assert.Equal(t, "192.168.1.10", resolvePublishedHost("192.168.1.10", tr))
}

// TestPublicBoundAddress_IPv6Comment documents that publicBoundAddress now
// accepts publicly routable IPv6 via nat.IsPubliclyRoutableIP. The loopback
// listener used by the test harness is non-public, so this remains a negative
// case; the positive IPv6 path is exercised by the lib/nat classifier tests.
func TestPublicBoundAddress_IPv6LoopbackDeclined(t *testing.T) {
	tr, cleanup := makeTestTransportWithListener(t)
	defer cleanup()
	_, _, ok := tr.publicBoundAddress()
	assert.False(t, ok)
}
