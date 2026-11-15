// Transport enable-gate guards.
//
// transport.ntcp2_enabled and transport.ssu2_enabled must reach the transport
// construction point in initializeTransports. Before this, NTCP2Enabled was
// loaded and validated in lib/config but never read by lib/router: the router
// always built NTCP2 regardless, so an operator who set ntcp2_enabled=false
// believed they had disabled a transport they had not. These tests pin that the
// flag now controls which transports exist, and that a router with neither
// transport enabled fails fast instead of starting headless.

package router

import (
	"testing"

	"github.com/go-i2p/go-i2p/lib/config"
	ntcp "github.com/go-i2p/go-i2p/lib/transport/ntcp2"
	ssu2 "github.com/go-i2p/go-i2p/lib/transport/ssu2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// muxerTransportTypes returns the concrete transport types installed on the
// router's muxer after construction.
func muxerTransportTypes(t *testing.T, r *Router) (hasNTCP2, hasSSU2 bool) {
	t.Helper()
	muxer := r.transports.Load()
	require.NotNil(t, muxer, "transports muxer must be installed by CreateRouter")
	for _, tr := range muxer.GetTransports() {
		switch tr.(type) {
		case *ntcp.NTCP2Transport:
			hasNTCP2 = true
		case *ssu2.SSU2Transport:
			hasSSU2 = true
		}
	}
	return hasNTCP2, hasSSU2
}

// TestCreateRouter_NTCP2Disabled verifies transport.ntcp2_enabled=false removes
// the NTCP2 transport from the muxer (SSU2 still present).
func TestCreateRouter_NTCP2Disabled(t *testing.T) {
	cfg := createTestRouterConfig(t.TempDir())
	cfg.Transport = &config.TransportDefaults{
		NTCP2Enabled: false,
		SSU2Enabled:  true,
	}

	r, err := CreateRouter(cfg)
	require.NoError(t, err, "CreateRouter should succeed with NTCP2 disabled and SSU2 enabled")
	t.Cleanup(func() { r.Stop() })

	hasNTCP2, hasSSU2 := muxerTransportTypes(t, r)
	assert.False(t, hasNTCP2, "NTCP2 transport must be absent when transport.ntcp2_enabled=false")
	assert.True(t, hasSSU2, "SSU2 transport must be present when transport.ssu2_enabled=true")
}

// TestCreateRouter_BothTransportsDisabled verifies the fail-fast guard: with
// neither transport enabled the router cannot reach the network, so
// CreateRouter must return an error rather than start a headless router.
func TestCreateRouter_BothTransportsDisabled(t *testing.T) {
	cfg := createTestRouterConfig(t.TempDir())
	cfg.Transport = &config.TransportDefaults{
		NTCP2Enabled: false,
		SSU2Enabled:  false,
	}

	_, err := CreateRouter(cfg)
	require.Error(t, err, "CreateRouter must fail when no transport is enabled")
	assert.Contains(t, err.Error(), "no transports enabled",
		"error should explain that at least one transport must be enabled")
}

// TestCreateRouter_NilTransportKeepsNTCP2Default pins the historical default: a
// nil Transport config (as used by createTestRouterConfig and many callers)
// keeps NTCP2 enabled and SSU2 disabled, so this change does not alter the
// default startup posture.
func TestCreateRouter_NilTransportKeepsNTCP2Default(t *testing.T) {
	cfg := createTestRouterConfig(t.TempDir())
	require.Nil(t, cfg.Transport, "test config should have a nil Transport to exercise the default")

	r, err := CreateRouter(cfg)
	require.NoError(t, err, "CreateRouter should succeed with a nil Transport config")
	t.Cleanup(func() { r.Stop() })

	hasNTCP2, hasSSU2 := muxerTransportTypes(t, r)
	assert.True(t, hasNTCP2, "nil Transport config must keep NTCP2 enabled (historical default)")
	assert.False(t, hasSSU2, "nil Transport config must keep SSU2 disabled (historical default)")
}
