package i2np

import (
	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/go-i2p/go-i2p/lib/tunnel/buildrecord"
)

// TunnelBuildCoordinator is the narrow interface needed by I2NPMessageDispatcher.
// It covers dependency injection, build emission, and reply processing — the
// operations that belong to the message-routing layer.
type TunnelBuildCoordinator interface {
	// Configuration — dependency injection points
	SetOurRouterHash(hash common.Hash)
	SetGarlicKeyRegistrar(r GarlicKeyRegistrar)
	SetSessionProvider(provider SessionProvider)
	SetPeerSelector(selector tunnel.PeerSelector)

	// Lifecycle
	Stop()

	// Build operations — structurally satisfies tunnel.BuilderInterface
	BuildTunnel(req tunnel.BuildTunnelRequest) (*tunnel.BuildTunnelResult, error)
	BuildTunnelFromRequest(req tunnel.BuildTunnelRequest) (buildrecord.TunnelID, []common.Hash, error)
	BuildTunnelWithBuilder(builder TunnelBuilder) error

	// Reply processing — structurally satisfies TunnelBuildReplyProcessor
	ProcessTunnelBuildReply(handler TunnelReplyHandler, messageID int) error
	ProcessTunnelReply(handler TunnelReplyHandler, messageID int) error
}

// TunnelStatsReader is the narrow interface needed by I2PControl and router status reporters.
// It covers pool access and build-metrics reads — the operations that belong to the
// observability layer. Any substitute only needs to implement these 10 methods.
type TunnelStatsReader interface {
	// Pool access
	GetPool() *tunnel.Pool
	GetInboundPool() *tunnel.Pool
	GetOutboundPool() *tunnel.Pool

	// Build metrics
	GetBuildSuccessCount(windowMs int64) float64
	GetBuildRejectCount(windowMs int64) float64
	GetBuildExpireCount(windowMs int64) float64
	GetBuildAvgTimeMs(windowMs int64) float64
	GetClientBuildSuccessCount(windowMs int64) float64
	GetClientBuildRejectCount(windowMs int64) float64
	GetClientBuildExpireCount(windowMs int64) float64
}

// TunnelOrchestrator defines the full interface for the tunnel build coordinator.
// It composes TunnelBuildCoordinator and TunnelStatsReader into a single seam for
// callers that need the complete surface (e.g. router wiring). Consumers that only
// need a subset should depend on TunnelBuildCoordinator or TunnelStatsReader directly.
//
// TunnelOrchestrator structurally satisfies:
//   - tunnel.BuilderInterface    (BuildTunnel — used by i2cp.Server.SetTunnelBuilder)
//   - TunnelBuildReplyProcessor  (ProcessTunnelBuildReply — used by MessageProcessor)
type TunnelOrchestrator interface {
	TunnelBuildCoordinator
	TunnelStatsReader
	// SetInboundHandler wires the InboundHandlerRegistrar so that newly-active
	// inbound tunnels are registered as control-plane endpoints (C-1 fix).
	SetInboundHandler(h InboundHandlerRegistrar)
}

// Compile-time assertion: *TunnelManager must fully implement TunnelOrchestrator.
var _ TunnelOrchestrator = (*TunnelManager)(nil)
