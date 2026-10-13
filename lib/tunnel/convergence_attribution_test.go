// Convergence regression tests for tunnel build failure attribution.
//
// These lock in the behaviour that keeps client tunnel pools reaching a ready
// state (issue #55). When a build fails at the gateway — before any hop-to-hop
// forwarding happened — only the gateway is at fault. Penalising the untouched
// middle and end hops burns healthy peers into cooldown, and the pool stops
// converging. The tests below pin that distinction in both directions.

package tunnel

import (
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/samber/oops"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// gatewayFailureError builds the exact error shape the transport layer produces
// when the muxer cannot dial the first hop: the sentinel from
// lib/transport is wrapped twice on the way up through the session provider and
// the build sender.
func gatewayFailureError() error {
	sentinel := oops.Errorf("no transports available")
	getSession := oops.Wrapf(sentinel, "failed to get session for gateway %x", []byte{0xaa, 0xbb})
	return oops.Wrapf(getSession, "failed to send build request")
}

// TestAttribution_GatewayFailurePenalizesOnlyFirstHop is the core #55 guard: a
// gateway-only failure must cool down hop 0 and leave hops 1..n available for
// reuse. If this regresses, every failed build burns three peers instead of one
// and the pool exhausts the reachable peer set.
func TestAttribution_GatewayFailurePenalizesOnlyFirstHop(t *testing.T) {
	pool := NewTunnelPool(&MockPeerSelector{})
	defer pool.Stop()

	gateway := makePeerHash(0xAA)
	middle := makePeerHash(0xBB)
	end := makePeerHash(0xCC)

	result := &BuildTunnelResult{
		TunnelID:   0,
		PeerHashes: []common.Hash{gateway, middle, end},
	}

	marked := pool.extractAndMarkFailedPeersForError(result, gatewayFailureError())

	assert.True(t, pool.IsPeerFailed(gateway), "gateway must be penalised: it could not be dialed")
	assert.False(t, pool.IsPeerFailed(middle), "middle hop must stay available: it was never contacted")
	assert.False(t, pool.IsPeerFailed(end), "end hop must stay available: it was never contacted")

	// The full hop list is still returned so the caller can exclude it from the
	// immediate retry, even though only the gateway is in cooldown.
	assert.Len(t, marked, 3, "all selected hops returned for retry-time exclusion")
}

// TestAttribution_UnattributableFailurePenalizesAllHops is the other half of the
// guard. A build reply timeout means the record reached the hops and something
// went wrong downstream, so all hops are suspect and must be cooled down.
// Regressing this would let the pool re-pick a peer that actively failed us.
func TestAttribution_UnattributableFailurePenalizesAllHops(t *testing.T) {
	pool := NewTunnelPool(&MockPeerSelector{})
	defer pool.Stop()

	gateway := makePeerHash(0xDD)
	middle := makePeerHash(0xEE)
	end := makePeerHash(0xFF)

	result := &BuildTunnelResult{
		TunnelID:   0,
		PeerHashes: []common.Hash{gateway, middle, end},
	}

	// Reply timeout: no single hop can be blamed.
	err := oops.Errorf("build reply timeout after 30s")
	pool.extractAndMarkFailedPeersForError(result, err)

	assert.True(t, pool.IsPeerFailed(gateway))
	assert.True(t, pool.IsPeerFailed(middle))
	assert.True(t, pool.IsPeerFailed(end))
}

// TestConvergence_PoolReachesReadyDespiteUnreachableGateway proves the property
// issue #55 reported as broken: given a mix of dialable and undialable peers,
// the pool must converge to a ready tunnel rather than retry forever. The
// gateway-only attribution is what makes this work — the first build burns only
// the bad gateway, so the retry still has healthy hops to pick.
func TestConvergence_PoolReachesReadyDespiteUnreachableGateway(t *testing.T) {
	pool := NewTunnelPoolWithConfig(&MockPeerSelector{}, PoolConfig{
		MinTunnels:       1,
		MaxTunnels:       2,
		HopCount:         3,
		BuildRetryDelay:  10 * time.Millisecond,
		MaxBuildRetries:  4,
		TunnelLifetime:   5 * time.Minute,
		RebuildThreshold: time.Minute,
	})
	defer pool.Stop()

	badGateway := makePeerHash(0x11)
	good1 := makePeerHash(0x22)
	good2 := makePeerHash(0x33)

	callCount := 0
	builder := &callbackBuilder{
		callback: func(req BuildTunnelRequest) (*BuildTunnelResult, error) {
			callCount++
			if callCount == 1 {
				// First attempt picks an undialable gateway. Only that hop is at fault.
				return &BuildTunnelResult{
					TunnelID:   0,
					PeerHashes: []common.Hash{badGateway, good1, good2},
				}, gatewayFailureError()
			}
			// Retry succeeds with the remaining healthy peers.
			return &BuildTunnelResult{
				TunnelID:   TunnelID(4242),
				PeerHashes: []common.Hash{good1, good2},
			}, nil
		},
	}
	pool.SetTunnelBuilder(builder)

	req := newBuildTunnelRequest(3, false)
	tunnelID, err := pool.executeBuildWithRetry(&req)

	require.NoError(t, err, "pool must converge to a successful build")
	assert.Equal(t, TunnelID(4242), tunnelID)
	assert.Equal(t, 2, callCount, "one failed build then one success")

	assert.True(t, pool.IsPeerFailed(badGateway), "the undialable gateway is penalised")
	assert.False(t, pool.IsPeerFailed(good1), "healthy hops survive the gateway failure")
	assert.False(t, pool.IsPeerFailed(good2), "healthy hops survive the gateway failure")
}

// TestConvergence_ExhaustsRetriesWhenAllGatewaysUnreachable is the negative
// control: when every candidate gateway is undialable, the build must fail after
// the bounded retry count rather than spinning forever.
func TestConvergence_ExhaustsRetriesWhenAllGatewaysUnreachable(t *testing.T) {
	pool := NewTunnelPoolWithConfig(&MockPeerSelector{}, PoolConfig{
		MinTunnels:      1,
		MaxTunnels:      2,
		HopCount:        3,
		BuildRetryDelay: 5 * time.Millisecond,
		MaxBuildRetries: 3,
	})
	defer pool.Stop()

	hops := []common.Hash{makePeerHash(0xA1), makePeerHash(0xA2), makePeerHash(0xA3)}

	callCount := 0
	builder := &callbackBuilder{
		callback: func(req BuildTunnelRequest) (*BuildTunnelResult, error) {
			callCount++
			return &BuildTunnelResult{TunnelID: 0, PeerHashes: hops}, gatewayFailureError()
		},
	}
	pool.SetTunnelBuilder(builder)

	req := newBuildTunnelRequest(3, false)
	_, err := pool.executeBuildWithRetry(&req)

	assert.Error(t, err, "build must ultimately fail when no gateway is dialable")
	assert.Greater(t, callCount, 1, "pool must retry before giving up")
	assert.LessOrEqual(t, callCount, 4, "retries must stay bounded")

	// Every attempt failed at the same gateway, so only that hop accumulates a
	// penalty. The middle and end hops were never contacted and must stay out of
	// cooldown — burning them is precisely the non-convergence bug from #55.
	assert.True(t, pool.IsPeerFailed(hops[0]), "the undialable gateway is penalised")
	assert.False(t, pool.IsPeerFailed(hops[1]), "uncontacted middle hop stays available")
	assert.False(t, pool.IsPeerFailed(hops[2]), "uncontacted end hop stays available")
}
