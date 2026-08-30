package ssu2

// test_helpers_generated.go provides shared test helper functions
// for SSU2Transport tests after refactoring to use SessionRegistry.

import (
	"context"

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
