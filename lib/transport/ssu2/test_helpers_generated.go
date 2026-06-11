package ssu2

// test_helpers_generated.go provides shared test helper functions
// for SSU2Transport tests after refactoring to use SessionRegistry.

import (
	"context"
	"testing"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/transport"
)

// makeMinimalTransport creates an SSU2Transport with only the fields required
// for non-network methods (Name, Addr, GetSessionCount, etc.).
func makeMinimalTransport() *SSU2Transport {
	ctx, cancel := context.WithCancel(context.Background())
	cfg := &Config{ListenerAddress: "127.0.0.1:0", MaxSessions: 4}
	tr := &SSU2Transport{
		handler:         NewDefaultHandler(),
		natStateCache:   &natState{},
		ctx:             ctx,
		cancel:          cancel,
		logger:          log.WithField("test", "transport_unit"),
		sessionRegistry: transport.NewSessionRegistry(log.WithField("test", "registry")),
	}
	tr.config.Store(cfg)
	return tr
}

// newTestPeerHashSSU2 creates a test peer hash from a string seed.
func newTestPeerHashSSU2(seed string) data.Hash {
	var h data.Hash
	copy(h[:], []byte(seed))
	return h
}

// makeMinimalTransportForRaceTests creates an SSU2Transport for testing
// session map logic without requiring a real listener or NAT managers.
func makeMinimalTransportForRaceTests(t *testing.T, maxSessions int) *SSU2Transport {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	cfg := &Config{ListenerAddress: "127.0.0.1:0", MaxSessions: maxSessions}
	tr := &SSU2Transport{
		handler:       NewDefaultHandler(),
		natStateCache: &natState{},
		ctx:           ctx,
		cancel:        cancel,
		logger:        log.WithField("test", "critical_race"),
	}
	tr.config.Store(cfg)
	return tr
}
