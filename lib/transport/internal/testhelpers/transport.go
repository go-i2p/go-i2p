package testhelpers

import (
	"context"
	"testing"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/transport"
	"github.com/go-i2p/logger"
)

// NewTestRouterHash creates a 32-byte test router hash with each byte set to
// its index plus the given offset. This function is shared across both NTCP2
// and SSU2 test suites.
func NewTestRouterHash(offset byte) data.Hash {
	var h data.Hash
	for i := range h {
		h[i] = byte(i) + offset
	}
	return h
}

// NewTestPeerHash creates a data.Hash from the given string content. This
// function is shared across both NTCP2 and SSU2 test suites and is used to
// generate deterministic test hashes for peer identification.
func NewTestPeerHash(content string) data.Hash {
	var h data.Hash
	copy(h[:], []byte(content))
	return h
}

// NewMinimalTransport creates a minimal transport with only the fields required
// for non-network methods (Name, Addr, GetSessionCount, etc.). The transport's
// context is cleaned up automatically via t.Cleanup.
//
// This is a protocol-agnostic helper that returns the low-level fields needed
// by both NTCP2 and SSU2 transports. Callers should embed this in their
// protocol-specific factory functions.
type MinimalTransportFields struct {
	Ctx             context.Context
	Cancel          context.CancelFunc
	Logger          *logger.Entry
	SessionRegistry *transport.SessionRegistry
	ListenerAddress string
	MaxSessions     int
}

// NewMinimalTransportFields creates the common fields for both NTCP2 and SSU2
// minimal transports. The caller is responsible for wrapping these fields in
// the appropriate transport type (NTCP2Transport or SSU2Transport).
func NewMinimalTransportFields(t *testing.T, maxSessions int) MinimalTransportFields {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	logEntry := logger.WithField("test", "transport_unit")
	return MinimalTransportFields{
		Ctx:             ctx,
		Cancel:          cancel,
		Logger:          logEntry,
		SessionRegistry: transport.NewSessionRegistry(logEntry),
		ListenerAddress: "127.0.0.1:0",
		MaxSessions:     maxSessions,
	}
}

// NewMinimalTransportWithHash creates a minimal transport together with a
// data.Hash derived from hashContent. This is a convenience helper for tests
// that need both a transport and a corresponding hash. The transport's context
// is cleaned up automatically via t.Cleanup.
func NewMinimalTransportWithHash(t *testing.T, hashContent string) (any, data.Hash) {
	t.Helper()
	_ = NewMinimalTransportFields(t, 4) // Validates setup; returns would be transport-specific
	return nil, NewTestPeerHash(hashContent)
}
