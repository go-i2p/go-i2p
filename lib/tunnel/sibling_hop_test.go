// Tests for I2P-010: sibling tunnels in one pool must not share hops. The
// pool now excludes the hops of every committed tunnel (ready or in-flight)
// from each new build, with a soft fallback that relaxes the exclusion only
// when it would starve selection.

package tunnel

import (
	"sync"
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// siblingRecordingBuilder is a mock builder that mimics the real TunnelManager:
// on a successful build it registers the tunnel in the pool with its hops
// populated (as AddTunnel does), so the next sibling build sees those hops as
// active. It records the ExcludePeers of every request so tests can assert the
// pool is excluding sibling hops.
type siblingRecordingBuilder struct {
	mu        sync.Mutex
	pool      *Pool
	hopSeed   byte
	requests  []BuildTunnelRequest
	builtHops [][]common.Hash
	// failWith, when set, makes every build return this error instead of
	// succeeding (used to drive the non-starvation failure path).
	failWith error
	// starveIfExcludes, when set, makes a build fail with ErrInsufficientPeers
	// exactly when its ExcludePeers contains every hash in this list. This
	// models the real starvation condition: selection runs out of candidates
	// precisely when the active sibling hops are excluded, so the pool's relaxed
	// retry (which drops those hops) succeeds.
	starveIfExcludes []common.Hash
	calls            int
}

// starves reports whether req excludes all of starveIfExcludes, i.e. whether
// this request represents the strict (sibling-hops-excluded) attempt.
func (b *siblingRecordingBuilder) starves(req BuildTunnelRequest) bool {
	if len(b.starveIfExcludes) == 0 {
		return false
	}
	set := make(map[common.Hash]struct{}, len(req.ExcludePeers))
	for _, h := range req.ExcludePeers {
		set[h] = struct{}{}
	}
	for _, h := range b.starveIfExcludes {
		if _, ok := set[h]; !ok {
			return false
		}
	}
	return true
}

func (b *siblingRecordingBuilder) BuildTunnel(req BuildTunnelRequest) (*BuildTunnelResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.requests = append(b.requests, req)
	b.calls++

	if b.failWith != nil {
		return &BuildTunnelResult{TunnelID: 0}, b.failWith
	}
	if b.starves(req) {
		return &BuildTunnelResult{TunnelID: 0}, ErrInsufficientPeers
	}

	hops := []common.Hash{makePeerHash(b.hopSeed), makePeerHash(b.hopSeed + 1)}
	b.hopSeed += 2

	id := TunnelID(6000 + len(b.builtHops))
	// Simulate the real builder registering the in-flight tunnel with hops.
	b.pool.AddTunnel(&TunnelState{
		ID:        id,
		Hops:      hops,
		State:     TunnelBuilding,
		CreatedAt: time.Now(),
	})
	b.builtHops = append(b.builtHops, hops)

	return &BuildTunnelResult{TunnelID: id, PeerHashes: hops}, nil
}

func (b *siblingRecordingBuilder) snapshot() ([]BuildTunnelRequest, [][]common.Hash) {
	b.mu.Lock()
	defer b.mu.Unlock()
	reqs := make([]BuildTunnelRequest, len(b.requests))
	copy(reqs, b.requests)
	hops := make([][]common.Hash, len(b.builtHops))
	copy(hops, b.builtHops)
	return reqs, hops
}

// assertExcluded asserts every hash in want appears in the exclusion list.
func assertExcluded(t *testing.T, exclusion, want []common.Hash) {
	t.Helper()
	set := make(map[common.Hash]struct{}, len(exclusion))
	for _, h := range exclusion {
		set[h] = struct{}{}
	}
	for _, h := range want {
		_, ok := set[h]
		assert.True(t, ok, "expected hop %x to be excluded", h[0])
	}
}

// TestBuildSiblingTunnel_ExcludesActiveHops is the core I2P-010 check: each new
// sibling build must exclude the hops of tunnels already committed to the pool.
func TestBuildSiblingTunnel_ExcludesActiveHops(t *testing.T) {
	pool := NewTunnelPool(&MockPeerSelector{})
	defer pool.Stop()

	b := &siblingRecordingBuilder{pool: pool, hopSeed: 0x10}
	pool.SetTunnelBuilder(b)

	require.True(t, pool.attemptBuildTunnels(3), "all three sibling builds should succeed")

	reqs, hops := b.snapshot()
	require.Len(t, reqs, 3)
	require.Len(t, hops, 3)

	// The first build starts from an empty pool, so it excludes no sibling hops.
	// The second must exclude tunnel 0's hops; the third must exclude tunnels 0
	// and 1's hops.
	assertExcluded(t, reqs[1].ExcludePeers, hops[0])
	assertExcluded(t, reqs[2].ExcludePeers, hops[0])
	assertExcluded(t, reqs[2].ExcludePeers, hops[1])

	// And the exclusion must not leak a tunnel's own hops into its own request:
	// tunnel 0's request predates its registration, so it excludes neither of
	// its own hops.
	assert.NotContains(t, reqs[0].ExcludePeers, hops[0][0])
}

// TestBuildSiblingTunnel_StarvationFallsBack verifies the soft fallback: when
// excluding active hops starves selection (ErrInsufficientPeers), the pool
// retries with only the failed-peer exclusion so the build still succeeds,
// rather than failing outright.
func TestBuildSiblingTunnel_StarvationFallsBack(t *testing.T) {
	pool := NewTunnelPool(&MockPeerSelector{})
	defer pool.Stop()

	// Seed one committed tunnel so activeTunnelHops is non-empty and the strict
	// attempt is meaningful.
	seedHops := []common.Hash{makePeerHash(0x71), makePeerHash(0x72)}
	pool.AddTunnel(&TunnelState{
		ID:        TunnelID(9000),
		Hops:      seedHops,
		State:     TunnelReady,
		CreatedAt: time.Now(),
	})

	// The builder starves (ErrInsufficientPeers) exactly when the seed tunnel's
	// hops are excluded — i.e. on the strict attempt — and succeeds once the
	// pool relaxes and drops them.
	b := &siblingRecordingBuilder{
		pool:             pool,
		hopSeed:          0x20,
		starveIfExcludes: seedHops,
	}
	pool.SetTunnelBuilder(b)

	require.True(t, pool.attemptBuildTunnels(1), "build should succeed via relaxed fallback")

	reqs, _ := b.snapshot()
	// The strict attempt(s) carry the seed hops; the final relaxed attempt must
	// not. Find the successful (last) request and confirm it dropped them.
	require.NotEmpty(t, reqs)
	requireExcluded := reqs[0]
	assertExcluded(t, requireExcluded.ExcludePeers, seedHops) // strict attempt excluded them
	last := reqs[len(reqs)-1]
	for _, h := range seedHops {
		assert.NotContains(t, last.ExcludePeers, h, "relaxed retry must drop the sibling-hop exclusion")
	}
}

// TestBuildSiblingTunnel_NonStarvationErrorNotRelaxed verifies the fallback is
// narrow: a failure that is NOT starvation (e.g. gateway unreachable) is not
// papered over by relaxing the exclusion.
func TestBuildSiblingTunnel_NonStarvationErrorNotRelaxed(t *testing.T) {
	pool := NewTunnelPool(&MockPeerSelector{})
	defer pool.Stop()

	pool.AddTunnel(&TunnelState{
		ID:        TunnelID(9001),
		Hops:      []common.Hash{makePeerHash(0x81)},
		State:     TunnelReady,
		CreatedAt: time.Now(),
	})

	b := &siblingRecordingBuilder{
		pool:     pool,
		hopSeed:  0x30,
		failWith: ErrGatewayUnreachable, // a real failure, not starvation
	}
	pool.SetTunnelBuilder(b)

	require.False(t, pool.attemptBuildTunnels(1), "a gateway-unreachable failure should not be relaxed away")

	reqs, _ := b.snapshot()
	// Every attempt keeps the sibling-hop exclusion (no relaxed retry issued).
	require.NotEmpty(t, reqs)
	for _, r := range reqs {
		assertExcluded(t, r.ExcludePeers, []common.Hash{makePeerHash(0x81)})
	}
}

// TestActiveTunnelHops_SkipsZeroAndDedups verifies the hop-collection helper
// ignores zero hashes and returns each distinct hop once.
func TestActiveTunnelHops_SkipsZeroAndDedups(t *testing.T) {
	pool := NewTunnelPool(&MockPeerSelector{})
	defer pool.Stop()

	shared := makePeerHash(0x55)
	pool.AddTunnel(&TunnelState{
		ID:        TunnelID(9100),
		Hops:      []common.Hash{shared, {}, makePeerHash(0x56)},
		State:     TunnelReady,
		CreatedAt: time.Now(),
	})
	pool.AddTunnel(&TunnelState{
		ID:        TunnelID(9101),
		Hops:      []common.Hash{shared, makePeerHash(0x57)},
		State:     TunnelBuilding,
		CreatedAt: time.Now(),
	})

	hops := pool.activeTunnelHops()

	// Expect exactly the three distinct non-zero hashes: shared, 0x56, 0x57.
	require.Len(t, hops, 3)
	set := make(map[common.Hash]int)
	for _, h := range hops {
		set[h]++
	}
	assert.Equal(t, 1, set[shared], "shared hop must appear once")
	assert.Equal(t, 1, set[makePeerHash(0x56)])
	assert.Equal(t, 1, set[makePeerHash(0x57)])
	assert.NotContains(t, set, common.Hash{}, "zero hash must be skipped")
}

// TestMergeExclusions_DedupsAndDropsZero verifies the exclusion-merge helper.
func TestMergeExclusions_DedupsAndDropsZero(t *testing.T) {
	a := []common.Hash{makePeerHash(0x01), {}, makePeerHash(0x02)}
	b := []common.Hash{makePeerHash(0x02), makePeerHash(0x03), {}}

	merged := mergeExclusions(a, b)

	set := make(map[common.Hash]int)
	for _, h := range merged {
		set[h]++
	}
	assert.Equal(t, 1, set[makePeerHash(0x01)])
	assert.Equal(t, 1, set[makePeerHash(0x02)], "duplicate must be collapsed")
	assert.Equal(t, 1, set[makePeerHash(0x03)])
	assert.NotContains(t, set, common.Hash{})
}
