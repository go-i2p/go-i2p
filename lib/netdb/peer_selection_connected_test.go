package netdb

import (
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/stretchr/testify/assert"
)

// TestSelectPeers_PrefersConnectedPeers verifies that when a connected-peer
// provider is wired, SelectPeers biases selection toward peers that already
// have an established transport session. This is the core fix for tunnel
// builds never converging ("no transports available" retry loop).
func TestSelectPeers_PrefersConnectedPeers(t *testing.T) {
	routerDB := newTestRouterNetDB(t)
	db := routerDB.StdNetDB

	// Create several reachable peers.
	const total = 6
	hashes := make([]common.Hash, 0, total)
	for i := 0; i < total; i++ {
		ri := *createTestRouterInfoWithOptions(t, map[string]string{"caps": "R"})
		// Give each a distinct host so diversity filtering does not collapse them.
		setRouterHostPort(t, &ri, distinctHost(i), "12345")
		h, err := ri.IdentHash()
		assert.NoError(t, err)
		db.riCache.put(h, Entry{RouterInfo: &ri})
		hashes = append(hashes, h)
	}

	// Mark the first two peers as "connected".
	connected := map[common.Hash]struct{}{
		hashes[0]: {},
		hashes[1]: {},
	}
	db.SetConnectedPeerProvider(func() map[common.Hash]struct{} {
		return connected
	})

	// Request exactly the number of connected peers; all selected peers should
	// be drawn from the connected set.
	selected, err := selectHashes(routerDB, 2)
	assert.NoError(t, err)
	assert.Len(t, selected, 2)
	for _, h := range selected {
		_, ok := connected[h]
		assert.True(t, ok, "selected peer should be a connected peer when connected peers satisfy the request")
	}
}

// TestSelectPeers_FallsBackWhenNotEnoughConnected verifies that the connected
// bias is soft: when there are not enough connected peers to satisfy the
// request, the remainder is filled from the other reachable peers.
func TestSelectPeers_FallsBackWhenNotEnoughConnected(t *testing.T) {
	routerDB := newTestRouterNetDB(t)
	db := routerDB.StdNetDB

	const total = 6
	hashes := make([]common.Hash, 0, total)
	for i := 0; i < total; i++ {
		ri := *createTestRouterInfoWithOptions(t, map[string]string{"caps": "R"})
		setRouterHostPort(t, &ri, distinctHost(i), "12345")
		h, err := ri.IdentHash()
		assert.NoError(t, err)
		db.riCache.put(h, Entry{RouterInfo: &ri})
		hashes = append(hashes, h)
	}

	connected := map[common.Hash]struct{}{hashes[0]: {}}
	db.SetConnectedPeerProvider(func() map[common.Hash]struct{} {
		return connected
	})

	selected, err := selectHashes(routerDB, 3)
	assert.NoError(t, err)
	assert.Len(t, selected, 3)

	// The single connected peer must be included; the rest come from others.
	seenConnected := false
	for _, h := range selected {
		if _, ok := connected[h]; ok {
			seenConnected = true
		}
	}
	assert.True(t, seenConnected, "connected peer should be preferred and included in the selection")
}

// TestSelectPeers_NoProviderIsUnbiased verifies that with no provider wired the
// behavior degrades to the previous random-diverse selection (no panic, full
// candidate pool eligible).
func TestSelectPeers_NoProviderIsUnbiased(t *testing.T) {
	routerDB := newTestRouterNetDB(t)
	db := routerDB.StdNetDB

	for i := 0; i < 4; i++ {
		ri := *createTestRouterInfoWithOptions(t, map[string]string{"caps": "R"})
		setRouterHostPort(t, &ri, distinctHost(i), "12345")
		h, err := ri.IdentHash()
		assert.NoError(t, err)
		db.riCache.put(h, Entry{RouterInfo: &ri})
	}

	selected, err := selectHashes(routerDB, 2)
	assert.NoError(t, err)
	assert.Len(t, selected, 2)
}

// TestPartitionByConnected verifies the pure partition helper directly.
func TestPartitionByConnected(t *testing.T) {
	riA := *createTestRouterInfoWithOptions(t, map[string]string{"caps": "R"})
	riB := *createTestRouterInfoWithOptions(t, map[string]string{"caps": "R"})
	setRouterHostPort(t, &riA, distinctHost(0), "12345")
	setRouterHostPort(t, &riB, distinctHost(1), "12345")

	hashA, err := riA.IdentHash()
	assert.NoError(t, err)

	connected := map[common.Hash]struct{}{hashA: {}}
	connectedPeers, otherPeers := partitionByConnected([]router_info.RouterInfo{riA, riB}, connected)

	assert.Len(t, connectedPeers, 1)
	assert.Len(t, otherPeers, 1)
	h, _ := connectedPeers[0].IdentHash()
	assert.Equal(t, hashA, h)
}

// distinctHost returns a distinct RFC 5737 test IPv4 address per index so that
// peer diversity filtering does not collapse the candidate set.
func distinctHost(i int) string {
	return "198.51.100." + itoa(10+i)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := []byte{}
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

// selectHashes runs SelectPeers and returns the identity hashes of the result.
func selectHashes(routerDB *RouterNetDB, count int) ([]common.Hash, error) {
	peers, err := routerDB.SelectPeers(count, nil)
	if err != nil {
		return nil, err
	}
	out := make([]common.Hash, 0, len(peers))
	for _, ri := range peers {
		h, herr := ri.IdentHash()
		if herr != nil {
			return nil, herr
		}
		out = append(out, h)
	}
	return out, nil
}
