// Issue #55 requirement 1: gateway and hop selection must be reachability-aware
// with an explicit tier order -- established session, then a session already
// connecting, then dial-on-demand.
//
// Selection that ignores transport state cannot converge: the reporter had 124
// established NTCP2 sessions and 63 "available" peers, yet every client tunnel
// build landed on a peer there was no session for. These tests pin the tier
// ordering, including that a connecting peer is preferred over an unknown one.

package netdb

import (
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// seedPeers installs `total` reachable peers with distinct hosts and returns
// their hashes in insertion order.
func seedPeers(t *testing.T, db *StdNetDB, total int) []common.Hash {
	t.Helper()
	hashes := make([]common.Hash, 0, total)
	for i := 0; i < total; i++ {
		ri := *createTestRouterInfoWithOptions(t, map[string]string{"caps": "R"})
		setRouterHostPort(t, &ri, distinctHost(i), "12345")
		h, err := ri.IdentHash()
		require.NoError(t, err)
		db.riCache.put(h, Entry{RouterInfo: &ri})
		hashes = append(hashes, h)
	}
	return hashes
}

// TestIssue55_SelectionPrefersConnectingOverDialOnDemand is the tier-2 test that
// did not exist before: with NO established session but one peer already being
// dialled, selection must pick the peer we are dialling rather than gambling on
// an unknown one.
//
// Pre-fix this fails: there was no connecting provider, so tier 2 was empty and
// selection fell straight through to random dial-on-demand.
func TestIssue55_SelectionPrefersConnectingOverDialOnDemand(t *testing.T) {
	routerDB := newTestRouterNetDB(t)
	db := routerDB.StdNetDB

	hashes := seedPeers(t, db, 6)

	// Nothing established, one peer connecting.
	db.SetConnectedPeerProvider(func() map[common.Hash]struct{} { return nil })
	connecting := map[common.Hash]struct{}{hashes[3]: {}}
	db.SetConnectingPeerProvider(func() map[common.Hash]struct{} { return connecting })

	selected, err := selectHashes(routerDB, 1)
	require.NoError(t, err)
	require.Len(t, selected, 1)
	assert.Equal(t, hashes[3], selected[0],
		"with no established session, the peer already being dialled must be preferred "+
			"over an unknown candidate")
}

// TestIssue55_EstablishedBeatsConnecting pins the tier order itself: an
// established session outranks an in-flight dial.
func TestIssue55_EstablishedBeatsConnecting(t *testing.T) {
	routerDB := newTestRouterNetDB(t)
	db := routerDB.StdNetDB

	hashes := seedPeers(t, db, 6)

	established := map[common.Hash]struct{}{hashes[0]: {}}
	connecting := map[common.Hash]struct{}{hashes[1]: {}}
	db.SetConnectedPeerProvider(func() map[common.Hash]struct{} { return established })
	db.SetConnectingPeerProvider(func() map[common.Hash]struct{} { return connecting })

	selected, err := selectHashes(routerDB, 1)
	require.NoError(t, err)
	require.Len(t, selected, 1)
	assert.Equal(t, hashes[0], selected[0],
		"tier 1 (established) must win over tier 2 (connecting)")
}

// TestIssue55_TiersFillRequestInOrder checks that a multi-hop request is filled
// tier by tier without duplicates: established first, then connecting, then
// dial-on-demand. An N-hop tunnel needs N distinct candidates, so a tier that
// cannot fill the request must not be the whole answer.
func TestIssue55_TiersFillRequestInOrder(t *testing.T) {
	routerDB := newTestRouterNetDB(t)
	db := routerDB.StdNetDB

	hashes := seedPeers(t, db, 9)

	established := map[common.Hash]struct{}{hashes[0]: {}}
	connecting := map[common.Hash]struct{}{hashes[1]: {}}
	db.SetConnectedPeerProvider(func() map[common.Hash]struct{} { return established })
	db.SetConnectingPeerProvider(func() map[common.Hash]struct{} { return connecting })

	selected, err := selectHashes(routerDB, 3)
	require.NoError(t, err)
	require.Len(t, selected, 3, "the request must be filled across tiers")

	seen := make(map[common.Hash]int, len(selected))
	for _, h := range selected {
		seen[h]++
	}
	for h, n := range seen {
		assert.Equal(t, 1, n, "peer %x selected more than once; tiers must not overlap", h[:4])
	}

	assert.Equal(t, 1, seen[hashes[0]], "the established peer must be included")
	assert.Equal(t, 1, seen[hashes[1]], "the connecting peer must be included")
}

// TestIssue55_NoProvidersDegradeToUnbiased checks cold start: with neither
// provider wired, every candidate stays eligible and nothing panics.
func TestIssue55_NoProvidersDegradeToUnbiased(t *testing.T) {
	routerDB := newTestRouterNetDB(t)
	db := routerDB.StdNetDB

	seedPeers(t, db, 5)
	assert.False(t, db.HasConnectedPeerProvider())
	assert.False(t, db.HasConnectingPeerProvider())

	selected, err := selectHashes(routerDB, 2)
	require.NoError(t, err)
	assert.Len(t, selected, 2, "cold start must still fill the request")
}

// TestIssue55_ConnectingProviderAccessor asserts the wiring guard exists so a
// dropped SetConnectingPeerProvider call fails a test instead of degrading
// silently -- the same failure mode that made #55 hard to catch.
func TestIssue55_ConnectingProviderAccessor(t *testing.T) {
	routerDB := newTestRouterNetDB(t)
	db := routerDB.StdNetDB

	db.SetConnectingPeerProvider(func() map[common.Hash]struct{} { return nil })
	assert.True(t, db.HasConnectingPeerProvider(),
		"the accessor must report a wired connecting provider")

	db.SetConnectingPeerProvider(nil)
	assert.False(t, db.HasConnectingPeerProvider(),
		"passing nil must clear the tier")
}

// TestIssue55_PartitionByHashesExcludesUnknownHashes pins that a peer whose
// identity hash cannot be computed is not placed in a reachability tier: the
// tiers are ordered by *known* reachability, and an unknown hash is unknown.
func TestIssue55_PartitionByHashesExcludesUnknownHashes(t *testing.T) {
	ri := *createTestRouterInfoWithOptions(t, map[string]string{"caps": "R"})
	hash, err := ri.IdentHash()
	require.NoError(t, err)

	include := map[common.Hash]struct{}{hash: {}}
	got := partitionByHashes([]router_info.RouterInfo{ri}, include, nil)
	assert.Len(t, got, 1, "a peer in the include set must be selected")

	got = partitionByHashes([]router_info.RouterInfo{ri}, include, include)
	assert.Empty(t, got, "a peer in the exclude set must be dropped")
}
