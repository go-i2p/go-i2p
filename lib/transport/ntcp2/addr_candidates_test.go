package ntcp2

import (
	"testing"
	"time"

	"github.com/go-i2p/common/router_address"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/testutil"
	noise "github.com/go-i2p/go-noise/ntcp2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeRouterInfoWithNTCP2Addresses(t *testing.T, addresses ...map[string]string) router_info.RouterInfo {
	t.Helper()
	require.GreaterOrEqual(t, len(addresses), 1)

	addrCfg := &testutil.RouterAddressConfig{
		Cost:       3,
		Expiration: time.Now().Add(24 * time.Hour),
		Transport:  "NTCP2",
		Options:    addresses[0],
	}

	ri := testutil.CreateSignedTestRouterInfo(t, nil, addrCfg)
	for _, options := range addresses[1:] {
		addr, err := router_address.NewRouterAddress(3, time.Now().Add(24*time.Hour), "NTCP2", options)
		require.NoError(t, err)
		require.NoError(t, ri.AddAddress(addr))
	}

	return *ri
}

func TestExtractNTCP2DialCandidates_MultipleIPv4AndDedup(t *testing.T) {
	ri := makeRouterInfoWithNTCP2Addresses(t,
		map[string]string{"host": "198.51.100.10", "port": "12345"},
		map[string]string{"host": "198.51.100.10", "port": "12345"}, // duplicate
		map[string]string{"host": "203.0.113.20", "port": "22345"},
	)

	candidates, err := ExtractNTCP2DialCandidates(ri)
	require.NoError(t, err)
	require.Len(t, candidates, 2, "duplicate addresses should be removed")

	assert.Equal(t, "198.51.100.10:12345", candidates[0].(*noise.Addr).UnderlyingAddr().String())
	assert.Equal(t, "203.0.113.20:22345", candidates[1].(*noise.Addr).UnderlyingAddr().String())
}

func TestExtractNTCP2Addr_ReturnsFirstPreferredCandidate(t *testing.T) {
	ri := makeRouterInfoWithNTCP2Addresses(t,
		map[string]string{"host": "198.51.100.10", "port": "12345"},
		map[string]string{"host": "203.0.113.20", "port": "22345"},
	)

	candidate, err := ExtractNTCP2Addr(ri)
	require.NoError(t, err)
	require.NotNil(t, candidate)

	wrapped, ok := candidate.(*noise.Addr)
	require.True(t, ok)
	assert.Equal(t, "198.51.100.10:12345", wrapped.UnderlyingAddr().String())
}
