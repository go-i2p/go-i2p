// Tests for the bootstrap peer floor being suppressible in testnet mode.
//
// go-i2p historically gated startup on emergencyReseedFloor: with fewer than 40
// RouterInfos in the NetDB the router retried reseeding until its attempt budget
// ran out and then exited before I2PControl started. On a small test network that
// count is unreachable, so the router reported failure on a perfectly healthy
// testnet. These tests pin that router.testnet removes the floor from every path
// that expresses it.
package router

import (
	"context"
	"testing"

	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/go-i2p/lib/netdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newFloorTestRouter builds a minimal Router with a real (empty) StdNetDB and the
// given testnet flag, low-peer threshold and emergency reseed floor.
//
// BootstrapType "file" with no path is deliberate: it makes any reseed attempt fail
// instantly and offline, so a test that expects no reseed cannot accidentally pass
// by reaching the network, and a test that expects one can tell by whether the
// attempt was recorded (performReseedWithContext calls markReseedAttempt before it
// selects the bootstrapper).
func newFloorTestRouter(t *testing.T, testnet bool, lowPeerThreshold int) *Router {
	t.Helper()
	return newFloorTestRouterWithFloor(t, testnet, lowPeerThreshold, 0)
}

// newFloorTestRouterWithFloor is newFloorTestRouter with an explicit
// bootstrap.emergency_reseed_floor (0 means unset, i.e. use the default).
func newFloorTestRouterWithFloor(t *testing.T, testnet bool, lowPeerThreshold, emergencyReseedFloor int) *Router {
	t.Helper()
	return &Router{
		cfg: &config.RouterConfig{
			Testnet: testnet,
			Bootstrap: &config.BootstrapConfig{
				LowPeerThreshold:     lowPeerThreshold,
				EmergencyReseedFloor: emergencyReseedFloor,
				BootstrapType:        "file",
			},
		},
		netdb: netdb.NewStdNetDB(t.TempDir()),
	}
}

// TestEmergencyReseedThresholdTestnetIsZero verifies a testnet router expresses no
// floor, even when a production low-peer threshold is configured.
func TestEmergencyReseedThresholdTestnetIsZero(t *testing.T) {
	r := newFloorTestRouter(t, true, 10)

	assert.Equal(t, noPeerFloor, r.emergencyReseedThreshold(),
		"testnet mode must not express a bootstrap peer floor")
	assert.True(t, r.isTestnet())
}

// TestEmergencyReseedThresholdProductionUnchanged verifies the floor still applies
// by default: the documented production behaviour (the hardcoded floor, raised by
// bootstrap.low_peer_threshold) must not drift.
func TestEmergencyReseedThresholdProductionUnchanged(t *testing.T) {
	tests := []struct {
		name             string
		lowPeerThreshold int
		want             int
	}{
		{"hardcoded floor when unset", 0, emergencyReseedFloor},
		{"hardcoded floor at the default", 10, emergencyReseedFloor},
		{"operator-raised threshold wins", 60, 60},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newFloorTestRouter(t, false, tt.lowPeerThreshold)
			assert.Equal(t, tt.want, r.emergencyReseedThreshold())
		})
	}
}

// TestEmergencyReseedThresholdConfigurableFloor verifies bootstrap.emergency_reseed_floor
// replaces the hardcoded floor, which is what lets a small private network (a
// testnet that does not set router.testnet) start without 40 RouterInfos.
func TestEmergencyReseedThresholdConfigurableFloor(t *testing.T) {
	tests := []struct {
		name                 string
		lowPeerThreshold     int
		emergencyReseedFloor int
		want                 int
	}{
		{"lowered floor wins over default", 10, 1, 1},
		{"lowered floor not raised by low_peer_threshold", 10, 1, 1},
		{"raised floor wins over default", 10, 100, 100},
		{"zero floor means default", 10, 0, emergencyReseedFloor},
		{"unset floor keeps low_peer_threshold raise", 60, 0, 60},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newFloorTestRouterWithFloor(t, false, tt.lowPeerThreshold, tt.emergencyReseedFloor)
			assert.Equal(t, tt.want, r.emergencyReseedThreshold())
		})
	}
}

// TestEmergencyReseedThresholdTestnetIgnoresConfiguredFloor verifies router.testnet
// still wins over an explicitly configured floor: a testnet expresses no floor at
// all, so the configured value cannot reintroduce the startup gate.
func TestEmergencyReseedThresholdTestnetIgnoresConfiguredFloor(t *testing.T) {
	r := newFloorTestRouterWithFloor(t, true, 10, 40)
	assert.Equal(t, noPeerFloor, r.emergencyReseedThreshold())
}

// TestEnsureNetDBReadyTestnetNeverBlocks verifies startup succeeds with an empty
// NetDB in testnet mode. This is the regression: a production router returns an
// error here after exhausting its reseed attempts, which stops the router before
// I2PControl is started.
func TestEnsureNetDBReadyTestnetNeverBlocks(t *testing.T) {
	r := newFloorTestRouter(t, true, 10)
	require.Equal(t, 0, r.netdb.Size(), "the testnet regression starts from an empty NetDB")

	assert.NoError(t, r.ensureNetDBReady(),
		"testnet startup must not fail on a low RouterInfo count")

	// The configured bootstrap source is still consulted once, best-effort.
	assert.False(t, r.lastReseedAttempt.IsZero(),
		"an empty testnet NetDB should still be seeded best-effort")
}

// TestEnsureNetDBReadyProductionStillGatesStartup verifies the production path is
// untouched: with the router stopping (cancelled context) the startup gate still
// returns an error rather than letting the router continue under the floor. The
// cancelled context keeps this instant; running the full retry budget takes minutes.
func TestEnsureNetDBReadyProductionStillGatesStartup(t *testing.T) {
	r := newFloorTestRouter(t, false, 10)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r.ctx = ctx

	err := r.ensureNetDBReady()

	require.Error(t, err, "production startup must still gate on the peer floor")
	assert.ErrorIs(t, err, context.Canceled,
		"the error must come from the retry loop, proving startup entered it")
}

// TestEnsureNetDBReadyTestnetSkipsSeedWhenPopulated verifies a testnet router with
// any peers at all does not reseed on startup, so a restart does not pay for a
// bootstrap fetch it does not need.
func TestEnsureNetDBReadyTestnetSkipsSeedWhenPopulated(t *testing.T) {
	r := newFloorTestRouter(t, true, 10)
	fillNetDB(t, r.netdb, 3)

	require.NoError(t, r.ensureNetDBReady())

	assert.True(t, r.lastReseedAttempt.IsZero(),
		"a seeded testnet must not reseed at startup; the floor is not what keeps it running")
}

// TestMaintainNetDBPeerFloorTestnetDoesNotReseed verifies the watchdog never
// escalates to an emergency reseed in testnet mode. Reseeding would pull
// production RouterInfos into the test network.
func TestMaintainNetDBPeerFloorTestnetDoesNotReseed(t *testing.T) {
	r := newFloorTestRouter(t, true, 10)

	r.maintainNetDBPeerFloor()

	assert.True(t, r.lastReseedAttempt.IsZero(),
		"testnet watchdog must not attempt a reseed; markReseedAttempt records every attempt")
}

// TestMaintainNetDBPeerFloorProductionReseeds verifies the watchdog still
// escalates when a floor is expressed, so this change is scoped to testnet mode.
func TestMaintainNetDBPeerFloorProductionReseeds(t *testing.T) {
	r := newFloorTestRouter(t, false, 10)

	r.maintainNetDBPeerFloor()

	assert.False(t, r.lastReseedAttempt.IsZero(),
		"a production router below the floor must still attempt an emergency reseed")
}

// TestReseedWithoutFloorSurvivesFailures verifies the best-effort seed never
// blocks or surfaces an error when the bootstrap source fails or the router is
// already stopping.
func TestReseedWithoutFloorSurvivesFailures(t *testing.T) {
	r := newFloorTestRouter(t, true, 10)
	require.NoError(t, r.ensureNetDBReady(), "seeding failure must not surface as a startup error")
	assert.Equal(t, 0, r.netdb.Size(), "a failing seed simply adds no peers")

	stopped := newFloorTestRouter(t, true, 10)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	stopped.ctx = ctx
	stopped.reseedWithoutFloor()
	assert.Equal(t, 0, stopped.netdb.Size(), "a cancelled seed attempt simply adds no peers")
}

// countingBootstrap records that a fetch was attempted and returns no peers.
type countingBootstrap struct {
	attempts int
}

func (c *countingBootstrap) GetPeers(ctx context.Context, n int) ([]router_info.RouterInfo, error) {
	c.attempts++
	return nil, nil
}

// TestExecuteReseedWithoutFloorStillFetches verifies a reseed requested while no
// floor is expressed actually reaches the bootstrap source even with a populated
// NetDB. StdNetDB skips a fetch once its size exceeds the requested minimum, so
// passing the floor (0) through would turn every testnet reseed — including an
// operator-requested one from I2PControl — into a silent no-op.
func TestExecuteReseedWithoutFloorStillFetches(t *testing.T) {
	r := newFloorTestRouter(t, true, 10)
	fillNetDB(t, r.netdb, 3)

	b := &countingBootstrap{}
	require.NoError(t, r.executeReseedWithContext(context.Background(), b))

	assert.Equal(t, 1, b.attempts,
		"a reseed with no floor must still fetch; the floor is not a fetch target")
}

// TestExecuteReseedProductionSkipsWhenAboveFloor verifies the production fetch
// target is still passed through, so a router already above the floor does not
// pay for a redundant fetch.
func TestExecuteReseedProductionSkipsWhenAboveFloor(t *testing.T) {
	r := newFloorTestRouter(t, false, 10)
	fillNetDB(t, r.netdb, emergencyReseedFloor+1)

	b := &countingBootstrap{}
	require.NoError(t, r.executeReseedWithContext(context.Background(), b))

	assert.Zero(t, b.attempts,
		"a production router above the floor must still skip the fetch")
}
