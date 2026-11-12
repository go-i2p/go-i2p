// Acceptance harness for issue #55: a client tunnel pool driven against a peer
// set where a fixed fraction of candidates cannot be dialled.
//
// Undialable peers are the normal case on I2P -- the reporter saw `no route to
// host` and SSU2 handshake timeouts as a matter of course -- so the fraction
// below is the knob that models reality, not the retry count. The retry count
// is what was hiding the bug: with enough blind retries a pool eventually
// stumbles onto a dialable set, which is why the failure looked intermittent
// instead of structural.

package tunnel

import (
	"fmt"
	"sync"
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fractionBuilder models a peer set in which a fixed fraction of peers are
// undialable. A build whose gateway is undialable fails with
// ErrGatewayUnreachable -- the same sentinel the router attaches at the
// transport boundary in production -- and a build whose gateway is dialable
// succeeds.
//
// Selection is driven by the pool's exclusion set, so the builder consults
// req.ExcludePeers to model "we keep picking new peers as old ones are burned".
type fractionBuilder struct {
	mu             sync.Mutex
	peers          []common.Hash
	undialable     map[common.Hash]bool
	attempts       int
	gatewayTries   map[common.Hash]int
	hopCount       int
	successTunnels int
}

func newFractionBuilder(total int, undialableFraction float64, hopCount int) *fractionBuilder {
	b := &fractionBuilder{
		undialable:   make(map[common.Hash]bool),
		gatewayTries: make(map[common.Hash]int),
		hopCount:     hopCount,
	}
	undialableCount := int(float64(total) * undialableFraction)
	if undialableCount > total {
		undialableCount = total
	}

	// Spread the undialable peers evenly through the set instead of clustering
	// them at the front. If they were clustered, convergence would depend on how
	// many retries the loop is allowed -- the very thing this harness must not
	// depend on, since the retry count is what hid the original bug.
	step := 1
	if undialableCount > 0 {
		step = total / undialableCount
	}
	if step < 1 {
		step = 1
	}
	for i := 0; i < total; i++ {
		h := makePeerHash(byte(i + 1))
		b.peers = append(b.peers, h)
		if undialableCount > 0 && i%step == 0 && len(b.undialable) < undialableCount {
			b.undialable[h] = true
		}
	}
	return b
}

func (b *fractionBuilder) BuildTunnel(req BuildTunnelRequest) (*BuildTunnelResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.attempts++

	excluded := make(map[common.Hash]bool, len(req.ExcludePeers))
	for _, h := range req.ExcludePeers {
		excluded[h] = true
	}

	// Pick the first not-yet-excluded peer as the gateway, the way selection
	// would after cooldowns have burned the previous picks.
	var gateway common.Hash
	found := false
	for _, h := range b.peers {
		if !excluded[h] {
			gateway, found = h, true
			break
		}
	}
	if !found {
		return &BuildTunnelResult{PeerHashes: nil},
			fmt.Errorf("selection exhausted every candidate: %w", ErrNoDialableCandidates)
	}
	b.gatewayTries[gateway]++

	path := []common.Hash{gateway}
	for i := 1; i < b.hopCount; i++ {
		path = append(path, makePeerHash(byte(0x80+i)))
	}

	if b.undialable[gateway] {
		return &BuildTunnelResult{TunnelID: 0, PeerHashes: path},
			fmt.Errorf("failed to get session for gateway: %w", ErrGatewayUnreachable)
	}

	b.successTunnels++
	return &BuildTunnelResult{
		TunnelID:   TunnelID(9000 + b.successTunnels),
		PeerHashes: path,
	}, nil
}

func (b *fractionBuilder) snapshot() (attempts int, tries map[common.Hash]int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	tries = make(map[common.Hash]int, len(b.gatewayTries))
	for h, n := range b.gatewayTries {
		tries[h] = n
	}
	return b.attempts, tries
}

// TestIssue55_Acceptance_PoolConvergesWithUndialablePeers is the acceptance
// evidence issue #55 asked for: with a fixed fraction of netDb peers
// undialable, the pool must reach a ready tunnel rather than spinning until
// the 120 s session monitor gives up.
//
// The fraction is tuned, not the retry count. At 50 % undialable -- far worse
// than the reporter's mix -- convergence must still be fast, because a
// gateway-unreachable failure now penalizes only the gateway and cools it down
// briefly, so the retry immediately has healthy hops left.
func TestIssue55_Acceptance_PoolConvergesWithUndialablePeers(t *testing.T) {
	const undialableFraction = 0.50
	const totalPeers = 12

	pool := NewTunnelPoolWithConfig(&MockPeerSelector{}, PoolConfig{
		MinTunnels:       1,
		MaxTunnels:       2,
		HopCount:         3,
		BuildRetryDelay:  time.Millisecond,
		MaxBuildRetries:  6,
		TunnelLifetime:   5 * time.Minute,
		RebuildThreshold: time.Minute,
	})
	defer pool.Stop()

	builder := newFractionBuilder(totalPeers, undialableFraction, 3)
	pool.SetTunnelBuilder(builder)

	start := time.Now()
	req := newBuildTunnelRequest(3, false)
	tunnelID, err := pool.executeBuildWithRetry(&req)
	elapsed := time.Since(start)

	require.NoError(t, err,
		"pool must converge with %.0f%% of peers undialable", undialableFraction*100)
	assert.NotEqual(t, TunnelID(0), tunnelID, "a real tunnel must come back")

	attempts, tries := builder.snapshot()
	stats := pool.GetBuildStats()

	t.Logf("ACCEPTANCE undialable_fraction=%.2f total_peers=%d attempts=%d "+
		"distinct_gateways_tried=%d builds_attempted=%d builds_no_dialable=%d "+
		"builds_refused=%d peers_penalized_unreachable=%d peers_penalized_refused=%d "+
		"peers_in_cooldown=%d elapsed=%s",
		undialableFraction, totalPeers, attempts, len(tries),
		stats.BuildsAttempted, stats.BuildsNoDialableCandidate, stats.BuildsRefused,
		stats.PeersPenalizedGatewayUnreachable, stats.PeersPenalizedRefused,
		len(pool.GetFailedPeers()), elapsed)

	// Convergence must not depend on burning the whole peer set.
	assert.Less(t, len(tries), totalPeers,
		"convergence must not require trying every peer; the retry loop was the "+
			"thing hiding the bug, so a full sweep means attribution is broken again")

	// The counters must attribute the failure, which is the whole point of #55:
	// a user should read these numbers instead of 290 MB of debug log.
	assert.Greater(t, stats.BuildsNoDialableCandidate, uint64(0),
		"at least one attempt must be attributed to an undialable gateway")
	assert.Zero(t, stats.BuildsRefused, "nothing in this harness refuses a build")

	// Only gateways we could not dial are in cooldown, and never the uncontacted
	// middle/end hops.
	for _, h := range []common.Hash{makePeerHash(0x81), makePeerHash(0x82)} {
		assert.False(t, pool.IsPeerFailed(h),
			"uncontacted hop %x must not be penalised", h[:4])
	}
}

// TestIssue55_Acceptance_AllGatewaysUnreachableFastsFail is the negative
// control at 100 %: when nothing is dialable the pool must stop after the
// bounded retry count and report ErrNoDialableCandidates, rather than waiting
// out a 120 s monitor with no reason.
func TestIssue55_Acceptance_AllGatewaysUnreachableFastsFail(t *testing.T) {
	pool := NewTunnelPoolWithConfig(&MockPeerSelector{}, PoolConfig{
		MinTunnels:      1,
		MaxTunnels:      2,
		HopCount:        3,
		BuildRetryDelay: time.Millisecond,
		MaxBuildRetries: 3,
	})
	defer pool.Stop()

	builder := newFractionBuilder(4, 1.0, 3)
	pool.SetTunnelBuilder(builder)

	start := time.Now()
	req := newBuildTunnelRequest(3, false)
	_, err := pool.executeBuildWithRetry(&req)
	elapsed := time.Since(start)

	require.Error(t, err, "with every peer undialable the build must fail")
	assert.ErrorIs(t, err, ErrNoDialableCandidates,
		"the terminal error must name the failure mode, got %v", err)
	assert.Less(t, elapsed, 5*time.Second,
		"failure must be fast and bounded, not a 120 s wait")

	stats := pool.GetBuildStats()
	t.Logf("NEGATIVE CONTROL all-undialable attempts=%d builds_no_dialable=%d "+
		"peers_penalized_unreachable=%d elapsed=%s err=%v",
		stats.BuildsAttempted, stats.BuildsNoDialableCandidate,
		stats.PeersPenalizedGatewayUnreachable, elapsed, err)
}
