// Regression tests for tunnel-hop capability filtering. i2pd advertises
// top-level caps such as "Of" (bandwidth tier 'O' + floodfill 'f') without any
// reachability letter. Requiring the 'R' letter collapsed the entire candidate
// set to zero against an i2pd-only peer set, so go-i2p built no tunnels. These
// tests pin the corrected behavior: caps is an explicit opt-out signal only
// ('H' hidden / 'U' unreachable), and a published host:port is treated as
// reachable by default.

package netdb

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestCapsAllowsTunnelParticipation verifies the caps opt-out logic directly.
func TestCapsAllowsTunnelParticipation(t *testing.T) {
	tests := []struct {
		name string
		caps string
		want bool
	}{
		// The i2pd case that triggered the bug: bandwidth tier + floodfill,
		// no reachability letter. Must now be eligible.
		{name: "i2pd floodfill Of", caps: "Of", want: true},
		{name: "reachable R", caps: "R", want: true},
		{name: "reachable bandwidth RP", caps: "RP", want: true},
		{name: "floodfill with R Rf", caps: "Rf", want: true},
		{name: "low bandwidth K", caps: "K", want: true},
		{name: "high bandwidth P", caps: "P", want: true},
		{name: "no caps", caps: "", want: true},
		// Leading I2P length byte must not break substring matching.
		{name: "length-prefixed Of", caps: "\x02Of", want: true},
		// Explicit opt-outs.
		{name: "hidden H", caps: "H", want: false},
		{name: "reachable but hidden RH", caps: "RH", want: false},
		{name: "unreachable U", caps: "U", want: false},
		{name: "floodfill unreachable Uf", caps: "Uf", want: false},
		// 'U' wins over 'R' when both are advertised (malformed): the router's
		// own "cannot be reached" declaration is authoritative.
		{name: "conflicting RU", caps: "RU", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, capsAllowsTunnelParticipation(tt.caps))
		})
	}
}

// TestSelectPeers_I2PDStyleCapsOfBuildsSelection is the end-to-end regression
// test: a peer set of i2pd-style caps=Of RouterInfos, each with a published
// host:port, must yield a non-empty tunnel-peer selection. Before the fix this
// selection was empty because every peer was skipped with reason
// "caps_lacks_R_or_advertises_H".
func TestSelectPeers_I2PDStyleCapsOfBuildsSelection(t *testing.T) {
	routerDB := newTestRouterNetDB(t)
	db := routerDB.StdNetDB

	const total = 4
	for i := 0; i < total; i++ {
		// i2pd 2.56 floodfill advertises caps=Of (version 0.9.65).
		ri := *createTestRouterInfoWithOptions(t, map[string]string{"caps": "Of"})
		setRouterHostPort(t, &ri, distinctHost(i), "12345")
		h, err := ri.IdentHash()
		assert.NoError(t, err)
		db.riCache.put(h, Entry{RouterInfo: &ri})
	}

	// All four i2pd-style peers must survive filtering.
	available := db.filterAvailablePeers(db.GetAllRouterInfos(), nil)
	assert.Len(t, available, total, "caps=Of peers with a published host:port must be eligible")

	// And a tunnel build must be able to select from them.
	selected, err := selectHashes(routerDB, 3)
	assert.NoError(t, err)
	assert.NotEmpty(t, selected, "tunnel peer selection must be non-empty against an i2pd-only peer set")
	assert.Len(t, selected, 3)
}

// TestSelectPeers_UnreachableAndHiddenStillExcluded confirms the fix did not
// loosen the filter past its original RCA: 'U' (unreachable) and 'H' (hidden)
// peers are still dropped even when they advertise a host:port.
func TestSelectPeers_UnreachableAndHiddenStillExcluded(t *testing.T) {
	routerDB := newTestRouterNetDB(t)
	db := routerDB.StdNetDB

	// One eligible i2pd-style peer.
	ok := *createTestRouterInfoWithOptions(t, map[string]string{"caps": "Of"})
	setRouterHostPort(t, &ok, distinctHost(0), "12345")
	okHash, err := ok.IdentHash()
	assert.NoError(t, err)
	db.riCache.put(okHash, Entry{RouterInfo: &ok})

	// One unreachable peer (caps=Uf) and one hidden peer (caps=H), both with a
	// published host:port so only the caps filter can exclude them.
	unreachable := *createTestRouterInfoWithOptions(t, map[string]string{"caps": "Uf"})
	setRouterHostPort(t, &unreachable, distinctHost(1), "12345")
	uHash, err := unreachable.IdentHash()
	assert.NoError(t, err)
	db.riCache.put(uHash, Entry{RouterInfo: &unreachable})

	hidden := *createTestRouterInfoWithOptions(t, map[string]string{"caps": "H"})
	setRouterHostPort(t, &hidden, distinctHost(2), "12345")
	hHash, err := hidden.IdentHash()
	assert.NoError(t, err)
	db.riCache.put(hHash, Entry{RouterInfo: &hidden})

	available := db.filterAvailablePeers(db.GetAllRouterInfos(), nil)
	assert.Len(t, available, 1, "only the caps=Of peer should remain eligible")

	availableHash, err := available[0].IdentHash()
	assert.NoError(t, err)
	assert.Equal(t, okHash, availableHash)
}
