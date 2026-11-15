// Gate test for the UPnP/NAT-PMP port mapper.
//
// The mapper used to start unconditionally on any non-loopback bind, so a
// public bind always asked the gateway to open a port. router.upnp_enabled is
// now threaded into ssu2.Config.DisablePortMapping and initNATManagers must
// honor it. These tests pin both branches of that gate.

package ssu2

import (
	"context"
	"testing"

	"github.com/go-i2p/go-i2p/lib/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeTestTransportWithAddr builds a transport whose config advertises a
// non-loopback ListenerAddress (so validateAndExtractPort returns valid) while
// the real listener stays loopback. The port mapper's retry loop waits its
// initial backoff before any network work, so a started mapper is inert for the
// duration of the test; we still Stop it to be tidy.
func makeTestTransportWithAddr(t *testing.T, listenerAddr string, disablePortMapping bool) (*SSU2Transport, func()) {
	t.Helper()
	l, listenerCleanup := makeTestListener(t)
	ctx, cancel := context.WithCancel(context.Background())
	cfg := &Config{
		ListenerAddress:    listenerAddr,
		MaxSessions:        4,
		DisablePortMapping: disablePortMapping,
	}
	tr := &SSU2Transport{
		listener:        l,
		logger:          log.WithField("test", "nat-portmap"),
		ctx:             ctx,
		cancel:          cancel,
		handler:         NewDefaultHandler(),
		sessionRegistry: transport.NewSessionRegistry(log.WithField("test", "nat-portmap-registry")),
	}
	tr.config.Store(cfg)
	require.NoError(t, initNATManagers(tr))

	cleanup := func() {
		if tr.portMapperManager != nil {
			_ = tr.portMapperManager.Stop()
		}
		cancel()
		listenerCleanup()
	}
	return tr, cleanup
}

// TestInitNATManagers_PortMappingEnabled verifies the mapper starts on a
// non-loopback bind when port mapping is not disabled (the default posture).
func TestInitNATManagers_PortMappingEnabled(t *testing.T) {
	tr, cleanup := makeTestTransportWithAddr(t, "10.0.0.1:9002", false)
	defer cleanup()

	assert.NotNil(t, tr.portMapperManager,
		"port mapper must start on a non-loopback bind when DisablePortMapping=false")
}

// TestInitNATManagers_PortMappingDisabled verifies the gate: with
// DisablePortMapping=true (router.upnp_enabled=false) the mapper must not start,
// so a public bind no longer unconditionally requests a gateway port mapping.
func TestInitNATManagers_PortMappingDisabled(t *testing.T) {
	tr, cleanup := makeTestTransportWithAddr(t, "10.0.0.1:9002", true)
	defer cleanup()

	assert.Nil(t, tr.portMapperManager,
		"port mapper must NOT start when DisablePortMapping=true (router.upnp_enabled=false)")
}
